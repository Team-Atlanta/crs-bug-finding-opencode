"""
opencode agent for autonomous vulnerability discovery.

Implements the agent interface (setup / run) using the opencode CLI
in headless `opencode run` mode. opencode reads AGENTS.md and the
custom `bug-hunter` agent definition, then autonomously: analyzes
source -> identifies vulnerabilities -> crafts inputs -> verifies
crashes -> writes POVs to pov_dir/.

Open-source models are routed through the OSS-CRS LiteLLM proxy
(an OpenAI-compatible endpoint). opencode reaches the proxy via a
custom provider declared in opencode.json (using @ai-sdk/openai-compatible).
"""

import json
import logging
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

logger = logging.getLogger("agent.opencode")

_raw_model = os.environ.get("OPENCODE_MODEL", "claude-sonnet-4-5").strip()
# opencode uses "<provider>/<model>" — strip any pre-existing provider prefix
# the operator may have supplied (we always re-prefix with our litellm provider).
_OPENCODE_MODEL_NAME = (
    _raw_model.removeprefix("openai/")
    .removeprefix("anthropic/")
    .removeprefix("google/")
    .removeprefix("gemini/")
    .removeprefix("litellm/")
)
OPENCODE_MODEL = f"litellm/{_OPENCODE_MODEL_NAME}"

# 0 = no timeout (run until budget is exhausted)
try:
    AGENT_TIMEOUT = int(os.environ.get("AGENT_TIMEOUT", "0"))
except ValueError:
    AGENT_TIMEOUT = 0
if AGENT_TIMEOUT < 0:
    AGENT_TIMEOUT = 0

_TEMPLATE_PATH = Path(__file__).with_name("AGENTS.md")
_SECTIONS_DIR = _TEMPLATE_PATH.with_name("sections")
_SKILLS_DIR = _TEMPLATE_PATH.with_name("skills")


def _load_section(section_name: str) -> str:
    section_path = _SECTIONS_DIR / section_name
    return section_path.read_text()


def _load_prompt_templates() -> dict[str, str]:
    return {
        "agents_md": _TEMPLATE_PATH.read_text(),
        "workflow_find": _load_section("workflow_find.md"),
        "diff_present": _load_section("diff_present.md"),
        "diff_absent": _load_section("diff_absent.md"),
        "seeds_present": _load_section("seeds_present.md"),
        "pre_submit": _load_section("pre_submit.md"),
    }


def _md_inline(value: str) -> str:
    """Return a markdown-safe inline code span."""
    ticks = 1
    while "`" * ticks in value:
        ticks += 1
    fence = "`" * ticks
    return f"{fence}{value}{fence}"


def _list_input_files(input_dir: Path, *, non_empty_only: bool = False) -> list[Path]:
    if not input_dir.exists():
        return []
    files = sorted(
        f for f in input_dir.rglob("*") if f.is_file() and not f.name.startswith(".")
    )
    if not non_empty_only:
        return files
    return [f for f in files if f.read_text(errors="replace").strip()]


def _install_skills(source_dir: Path, harness: str) -> None:
    """Copy skills from package data into source_dir/.agents/skills/."""
    target_skills = source_dir / ".agents" / "skills"
    if not _SKILLS_DIR.exists():
        logger.warning("Skills directory not found: %s", _SKILLS_DIR)
        return

    for skill_dir in _SKILLS_DIR.iterdir():
        if not skill_dir.is_dir():
            continue
        destination = target_skills / skill_dir.name
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(skill_dir, destination)
        skill_md = destination / "SKILL.md"
        if skill_md.exists():
            content = skill_md.read_text()
            content = content.replace("{harness}", harness)
            content = content.replace("{source_dir}", str(source_dir))
            skill_md.write_text(content)
        logger.info("Installed skill: %s", skill_dir.name)


def _write_opencode_config(config_dir: Path, llm_api_url: str) -> Path:
    """Write opencode.json with a custom litellm provider pointing at the OSS-CRS proxy.

    opencode supports OpenAI-compatible providers via @ai-sdk/openai-compatible.
    The provider's options.baseURL / apiKey use opencode's {env:VAR} interpolation,
    which we satisfy by exporting OPENAI_BASE_URL / OPENAI_API_KEY.
    """
    config_dir.mkdir(parents=True, exist_ok=True)
    base_url = llm_api_url.rstrip("/")
    if not base_url.endswith("/v1"):
        base_url = f"{base_url}/v1"

    cfg = {
        "$schema": "https://opencode.ai/config.json",
        "provider": {
            "litellm": {
                "npm": "@ai-sdk/openai-compatible",
                "name": "OSS-CRS LiteLLM",
                "options": {
                    "baseURL": base_url,
                    "apiKey": "{env:OPENAI_API_KEY}",
                },
                "models": {
                    _OPENCODE_MODEL_NAME: {
                        "name": _OPENCODE_MODEL_NAME,
                        "limit": {"context": 200000, "output": 32000},
                    }
                },
            }
        },
        "model": OPENCODE_MODEL,
        "small_model": OPENCODE_MODEL,
        "disabled_providers": [
            "opencode",
            "anthropic",
            "openai",
            "github-copilot",
            "openrouter",
            "google",
        ],
        "share": "disabled",
        "autoupdate": False,
        "permission": {
            "edit": "allow",
            "bash": "allow",
            "webfetch": "deny",
            "websearch": "deny",
        },
    }

    config_path = config_dir / "opencode.json"
    config_path.write_text(json.dumps(cfg, indent=2) + "\n")
    config_path.chmod(0o600)
    return config_path


def _write_bug_hunter_agent(agents_dir: Path) -> Path:
    """Write the primary `bug-hunter` agent definition opencode will run with --agent."""
    agents_dir.mkdir(parents=True, exist_ok=True)
    body = (
        "---\n"
        "description: Autonomous security researcher hunting for crashing inputs (POVs)\n"
        "mode: primary\n"
        f"model: {OPENCODE_MODEL}\n"
        "temperature: 0.2\n"
        "permission:\n"
        "  edit: allow\n"
        "  bash: allow\n"
        "  webfetch: deny\n"
        "  websearch: deny\n"
        "---\n\n"
        "You are an expert security researcher. Read AGENTS.md (in the working\n"
        "directory) for full task context, environment paths, the harness, and the\n"
        "submission protocol. Use read/grep/glob/bash tools to investigate the\n"
        "target codebase. Verify every candidate POV with `libCRS run-pov` before\n"
        "saving it to the POV directory. Keep going until killed.\n"
    )
    agent_path = agents_dir / "bug-hunter.md"
    agent_path.write_text(body)
    return agent_path


def setup(source_dir: Path, config: dict) -> None:
    """One-time agent configuration."""
    try:
        version_result = subprocess.run(
            ["opencode", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        logger.info(
            "opencode version: %s",
            version_result.stdout.strip() or version_result.stderr.strip(),
        )
    except OSError as error:
        logger.warning("Failed to get opencode version: %s", error)

    llm_api_url = config.get("llm_api_url", "")
    llm_api_key = config.get("llm_api_key", "")
    opencode_home = Path(config.get("opencode_home", Path.home() / ".config" / "opencode"))
    opencode_home.mkdir(parents=True, exist_ok=True)

    # Hermetic / non-interactive mode
    os.environ["IS_SANDBOX"] = "1"
    os.environ["OPENCODE_DISABLE_AUTOUPDATE"] = "1"
    os.environ["OPENCODE_DISABLE_LSP_DOWNLOAD"] = "1"
    os.environ["OPENCODE_DISABLE_MODELS_FETCH"] = "1"
    os.environ["OPENCODE_DISABLE_DEFAULT_PLUGINS"] = "1"
    os.environ["OPENCODE_DISABLE_PROJECT_CONFIG"] = "1"
    os.environ["OPENCODE_DISABLE_CLAUDE_CODE_PROMPT"] = "1"

    if llm_api_url and llm_api_key:
        # @ai-sdk/openai-compatible reads baseURL/apiKey from provider options;
        # we wire them in via opencode's {env:VAR} interpolation.
        base_url = llm_api_url.rstrip("/")
        if not base_url.endswith("/v1"):
            base_url = f"{base_url}/v1"
        os.environ["OPENAI_BASE_URL"] = base_url
        os.environ["OPENAI_API_KEY"] = llm_api_key
        logger.info("opencode configured with LiteLLM proxy: %s", base_url)
        logger.info("OPENCODE_MODEL: %s", OPENCODE_MODEL)
    else:
        logger.warning("No LLM API URL/key set — opencode will not be able to call any model")

    config_path = _write_opencode_config(opencode_home, llm_api_url or "http://localhost:4000")
    logger.info("Wrote opencode config to %s", config_path)

    agent_path = _write_bug_hunter_agent(opencode_home / "agents")
    logger.info("Wrote bug-hunter agent to %s", agent_path)

    # Set OPENCODE_CONFIG so opencode reads our injected config explicitly.
    os.environ["OPENCODE_CONFIG"] = str(config_path)

    # Keep the AGENTS.md / .agents/ files out of the target repo's git diff.
    global_gitignore = Path.home() / ".gitignore"
    existing = ""
    if global_gitignore.exists():
        existing = global_gitignore.read_text(errors="replace")
    lines = [line.rstrip("\n") for line in existing.splitlines()]
    for entry in ("AGENTS.md", ".agents/", ".opencode/"):
        if entry not in lines:
            lines.append(entry)
    global_gitignore.write_text("\n".join(lines).rstrip("\n") + "\n")
    try:
        git_config = subprocess.run(
            ["git", "config", "--global", "core.excludesFile", str(global_gitignore)],
            capture_output=True,
        )
        if git_config.returncode != 0:
            logger.warning(
                "Failed to set global git excludesFile: %s",
                git_config.stderr.decode(errors="replace")
                if isinstance(git_config.stderr, bytes)
                else git_config.stderr,
            )
    except OSError as error:
        logger.warning("Failed to run git config for excludesFile: %s", error)

    logger.info("Agent setup complete")


def run(
    source_dir: Path,
    build_dir: Path,
    pov_dir: Path,
    diff_dir: Path,
    seed_dir: Path,
    bug_candidate_dir: Path,
    harness: str,
    work_dir: Path,
    *,
    language: str = "c",
    sanitizer: str = "address",
) -> bool:
    """Launch opencode in headless `run` mode for autonomous vulnerability discovery."""
    work_dir.mkdir(parents=True, exist_ok=True)
    try:
        templates = _load_prompt_templates()
    except OSError as error:
        logger.error("Failed to load prompt template(s): %s", error)
        return False

    _install_skills(source_dir, harness)

    diffs = _list_input_files(diff_dir, non_empty_only=True)
    seeds = _list_input_files(seed_dir)
    bug_candidates = _list_input_files(bug_candidate_dir)

    if diffs:
        diff_list = "\n".join(f"- {_md_inline(str(path))}" for path in diffs)
        diff_section = templates["diff_present"].format(diff_list=diff_list)
    else:
        diff_section = templates["diff_absent"]

    if seeds:
        seed_list = "\n".join(f"- {_md_inline(str(path))}" for path in seeds)
        seed_section = templates["seeds_present"].format(seed_list=seed_list)
    else:
        seed_section = ""

    if bug_candidates:
        bug_candidate_list = "\n".join(
            f"- {_md_inline(str(path))}" for path in bug_candidates
        )
        bug_candidate_section = (
            "## Bug-Candidate Reports\n\n"
            "Static analysis reports are available:\n\n"
            f"{bug_candidate_list}\n\n"
            "Use these to prioritize which code paths to target.\n"
        )
    else:
        bug_candidate_section = ""

    agents_md = templates["agents_md"].format(
        language=language,
        sanitizer=sanitizer,
        source_dir=source_dir,
        build_dir=build_dir,
        work_dir=work_dir,
        harness=harness,
        pov_dir=pov_dir,
        workflow_section=templates["workflow_find"],
        diff_section=diff_section,
        seed_section=seed_section,
        bug_candidate_section=bug_candidate_section,
        pre_submit_section=templates["pre_submit"],
    )
    (source_dir / "AGENTS.md").write_text(agents_md)

    target = os.environ.get("OSS_CRS_TARGET", source_dir.name)
    prompt_lines = [
        f"Find vulnerabilities in project {_md_inline(target)} through harness {_md_inline(harness)}.",
        f"Write crashing inputs (POVs) to {_md_inline(str(pov_dir))}.",
        "",
        "Available evidence:",
        f"- Diff files: {len(diffs)}",
        f"- Seed files: {len(seeds)}",
        f"- Bug-candidate files: {len(bug_candidates)}",
    ]
    if diffs:
        diff_files = " ".join(_md_inline(str(path)) for path in diffs)
        prompt_lines.append(f"- Diff files: {diff_files}")
    if seeds:
        seed_files = " ".join(_md_inline(str(path)) for path in seeds)
        prompt_lines.append(f"- Seed files: {seed_files}")
    if bug_candidates:
        bug_files = " ".join(_md_inline(str(path)) for path in bug_candidates)
        prompt_lines.append(f"- Bug-candidate report files: {bug_files}")
    prompt_lines.extend(
        [
            "",
            "Read AGENTS.md (in the working directory) for the full workflow,"
            " environment, and submission instructions.",
            "Keep going until killed and find as many distinct vulnerabilities as possible.",
        ]
    )
    prompt = "\n".join(prompt_lines)

    stdout_log = work_dir / "opencode_stdout.log"
    stderr_log = work_dir / "opencode_stderr.log"
    cmd = [
        "opencode",
        "run",
        "--dir",
        str(source_dir),
        "--agent",
        "bug-hunter",
        "--model",
        OPENCODE_MODEL,
        "--format",
        "json",
        "--dangerously-skip-permissions",
        "--print-logs",
        prompt,
    ]

    (work_dir / "agent_prompt.txt").write_text(prompt)
    (work_dir / "agent_agents_md.md").write_text(agents_md)
    (work_dir / "agent_cmd.txt").write_text(" ".join(cmd) + "\n")
    logger.info("Agent inputs saved to %s", work_dir)

    try:
        with open(stdout_log, "w") as stdout_file, open(stderr_log, "w") as stderr_file:
            proc = subprocess.Popen(
                cmd,
                stdout=stdout_file,
                stderr=stderr_file,
                text=True,
                cwd=source_dir,
                start_new_session=True,
            )
            try:
                proc.wait(timeout=AGENT_TIMEOUT or None)
                logger.info("opencode exit code: %d", proc.returncode)
            except subprocess.TimeoutExpired:
                logger.warning(
                    "opencode timed out (%ds), killing process tree", AGENT_TIMEOUT
                )
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    time.sleep(2)
                    if proc.poll() is None:
                        os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
                logger.info("opencode exit code after timeout handling: %d", proc.returncode)
    except Exception as error:
        logger.error("Error running opencode: %s", error)
        return False

    # Tidy up large cache artifacts that would bloat the log dir.
    for cache_root in (
        Path.home() / ".cache" / "opencode",
        Path.home() / ".local" / "share" / "opencode" / "log",
    ):
        if cache_root.is_dir():
            try:
                if cache_root.name == "log":
                    # Keep recent logs if small; just chmod for read access.
                    pass
                else:
                    shutil.rmtree(cache_root, ignore_errors=True)
                    logger.info("Cleaned up opencode cache dir %s", cache_root)
            except OSError:
                pass

    subprocess.run(
        ["chmod", "-R", "og+rX", str(Path.home() / ".config" / "opencode")],
        capture_output=True,
    )

    if proc.returncode != 0:
        logger.warning("opencode failed (rc=%d), see %s", proc.returncode, stderr_log)

    pov_files = list(pov_dir.glob("*")) if pov_dir.exists() else []
    pov_files = [path for path in pov_files if path.is_file() and not path.name.startswith(".")]
    if pov_files:
        logger.info(
            "Agent produced %d POV(s): %s", len(pov_files), [path.name for path in pov_files]
        )
        return True

    logger.info("Agent did not produce any POVs")
    return False
