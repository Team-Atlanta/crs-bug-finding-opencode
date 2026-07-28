"""
crs-bug-finding-opencode finder module.

Thin launcher that delegates vulnerability discovery to a swappable AI agent.
The agent (selected via CRS_AGENT env var) handles: source analysis, input
crafting, crash verification, and POV submission (writing files to pov_dir/).

POVs are auto-submitted by libCRS via register_submit_dir.

To add a new agent, create a module in agents/ implementing setup() and run().
"""

import importlib
import inspect
import logging
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

from libCRS.base import DataType
from libCRS.cli.main import init_crs_utils

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("finder")

TARGET = os.environ.get("OSS_CRS_TARGET", "")
HARNESS = os.environ.get("OSS_CRS_TARGET_HARNESS", "")
LANGUAGE = os.environ.get("FUZZING_LANGUAGE", "c")
SANITIZER = os.environ.get("SANITIZER", "address")
LLM_API_URL = os.environ.get("OSS_CRS_LLM_API_URL", "")
LLM_API_KEY = open(os.environ["OSS_CRS_LLM_API_KEY_FILE"]).read().strip() if os.environ.get("OSS_CRS_LLM_API_KEY_FILE") else os.environ.get("OSS_CRS_LLM_API_KEY", "")

CRS_AGENT = os.environ.get("CRS_AGENT", "opencode")

WORK_DIR = Path("/work")
SRC_DIR = Path("/src")
POV_DIR = WORK_DIR / "povs"
DIFF_DIR = WORK_DIR / "diffs"
BUG_CANDIDATE_DIR = WORK_DIR / "bug-candidates"
SEED_DIR = WORK_DIR / "seeds"

crs = None


def setup_source() -> Path | None:
    """Download build-output /src and prepare it as the working directory."""
    safe_dir_proc = subprocess.run(
        ["git", "config", "--system", "--add", "safe.directory", "*"],
        capture_output=True,
    )
    if safe_dir_proc.returncode != 0:
        fallback_proc = subprocess.run(
            ["git", "config", "--global", "--add", "safe.directory", "*"],
            capture_output=True,
        )
        if fallback_proc.returncode != 0:
            logger.warning(
                "Failed to configure git safe.directory in both --system and --global scopes"
            )

    try:
        crs.download_build_output("src", SRC_DIR)
    except Exception as e:
        logger.error("Failed to download /src build output via libCRS: %s", e)
        return None

    project_dir = SRC_DIR.resolve()

    if not (project_dir / ".git").exists():
        logger.info("No .git found in %s, initializing git repo", project_dir)
        subprocess.run(["git", "init"], cwd=project_dir, capture_output=True, timeout=60)
        subprocess.run(["git", "add", "-A"], cwd=project_dir, capture_output=True, timeout=60)
        commit_proc = subprocess.run(
            [
                "git",
                "-c",
                "user.name=crs-bug-finding-opencode",
                "-c",
                "user.email=crs-bug-finding-opencode@local",
                "commit",
                "-m",
                "initial source",
            ],
            cwd=project_dir, capture_output=True, timeout=60,
        )
        if commit_proc.returncode != 0:
            stderr = (
                commit_proc.stderr.decode(errors="replace")
                if isinstance(commit_proc.stderr, bytes)
                else str(commit_proc.stderr)
            )
            logger.error("Failed to create initial commit: %s", stderr.strip())
            return None

    return project_dir


def load_agent(agent_name: str):
    """Dynamically load an agent module from the agents package."""
    module_name = f"agents.{agent_name}"
    try:
        return importlib.import_module(module_name)
    except ImportError as e:
        logger.error("Failed to load agent '%s': %s", agent_name, e)
        sys.exit(1)


def run_agent(source_dir: Path, build_dir: Path, agent) -> bool:
    """Run the agent for vulnerability discovery."""
    agent_work_dir = WORK_DIR / "agent"

    run_sig = inspect.signature(agent.run)
    run_kwargs = {
        "source_dir": source_dir,
        "build_dir": build_dir,
        "pov_dir": POV_DIR,
        "diff_dir": DIFF_DIR,
        "seed_dir": SEED_DIR,
        "bug_candidate_dir": BUG_CANDIDATE_DIR,
        "harness": HARNESS,
        "work_dir": agent_work_dir,
    }
    optional_kwargs = {
        "language": LANGUAGE,
        "sanitizer": SANITIZER,
    }
    for key, value in optional_kwargs.items():
        if key in run_sig.parameters:
            run_kwargs[key] = value

    return bool(agent.run(**run_kwargs))


def main():
    logger.info(
        "Starting finder: target=%s harness=%s agent=%s",
        TARGET, HARNESS, CRS_AGENT,
    )

    global crs
    crs = init_crs_utils()

    # Fetch inputs
    try:
        diff_files_fetched = crs.fetch(DataType.DIFF, DIFF_DIR)
        if diff_files_fetched:
            logger.info("Fetched %d diff file(s) into %s", len(diff_files_fetched), DIFF_DIR)
    except Exception as e:
        logger.warning("Diff fetch failed: %s — delta mode diffs unavailable", e)

    # try:
    #     seed_files_fetched = crs.fetch(DataType.SEED, SEED_DIR)
    #     if seed_files_fetched:
    #         logger.info("Fetched %d seed file(s) into %s", len(seed_files_fetched), SEED_DIR)
    # except Exception as e:
    #     logger.warning("Seed fetch failed: %s — seeds unavailable", e)

    try:
        bug_files_fetched = crs.fetch(DataType.BUG_CANDIDATE, BUG_CANDIDATE_DIR)
        if bug_files_fetched:
            logger.info(
                "Fetched %d bug-candidate file(s) into %s",
                len(bug_files_fetched),
                BUG_CANDIDATE_DIR,
            )
    except Exception as e:
        logger.warning("Bug-candidate fetch failed: %s — static findings unavailable", e)

    # Register POV submission directory — libCRS daemon auto-submits new files.
    POV_DIR.mkdir(parents=True, exist_ok=True)
    submit_thread = threading.Thread(
        target=crs.register_submit_dir,
        args=(DataType.POV, POV_DIR),
        daemon=True,
    )
    submit_thread.start()
    logger.info("POV submit watcher started for %s", POV_DIR)

    # Register log directory for persistence (creates symlink to host-mounted LOG_DIR)
    log_dir = WORK_DIR / "logs"
    if log_dir.exists() or log_dir.is_symlink():
        if log_dir.is_symlink():
            log_dir.unlink()
        else:
            shutil.rmtree(log_dir)
    try:
        crs.register_log_dir(log_dir)
        logger.info("Registered log dir: %s", log_dir)
    except Exception as e:
        logger.warning("Failed to register log dir: %s", e)
        log_dir.mkdir(parents=True, exist_ok=True)

    # Register opencode home as a log directory for post-run analysis.
    # Anything pre-existing is just baseline/migration state from the image
    # build; we don't need to preserve it.
    opencode_home = Path.home() / ".config" / "opencode"
    opencode_home.parent.mkdir(parents=True, exist_ok=True)
    if opencode_home.exists() or opencode_home.is_symlink():
        if opencode_home.is_symlink() or opencode_home.is_file():
            opencode_home.unlink()
        else:
            shutil.rmtree(opencode_home, ignore_errors=True)
    try:
        crs.register_log_dir(opencode_home)
        logger.info("opencode home registered as log dir at %s", opencode_home)
    except Exception as e:
        logger.warning("Failed to register opencode-home log dir: %s", e)
        opencode_home.mkdir(parents=True, exist_ok=True)

    # Setup source
    source_dir = setup_source()
    if source_dir is None:
        logger.error("Failed to set up source directory")
        sys.exit(1)
    logger.info("Source directory: %s", source_dir)

    # Download build outputs (harness binaries)
    build_dir = WORK_DIR / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    try:
        crs.download_build_output("build", build_dir)
        logger.info("Downloaded build outputs to %s", build_dir)
    except Exception as e:
        logger.error("Failed to download build outputs: %s", e)
        sys.exit(1)

    # Register agent work directory as a log dir so agent logs are persisted
    # in real-time (survives SIGTERM on timeout).
    agent_work_dir = WORK_DIR / "agent"
    try:
        crs.register_log_dir(agent_work_dir)
        logger.info("Agent work dir registered as log dir at %s", agent_work_dir)
    except Exception as e:
        logger.warning("Failed to register agent work log dir: %s", e)
        agent_work_dir.mkdir(parents=True, exist_ok=True)

    # Load and run agent
    agent = load_agent(CRS_AGENT)
    agent.setup(source_dir, {
        "llm_api_url": LLM_API_URL,
        "llm_api_key": LLM_API_KEY,
        "opencode_home": str(opencode_home),
    })

    iteration = 0
    while True:
        iteration += 1
        logger.info("Starting agent iteration %d", iteration)
        if run_agent(source_dir, build_dir, agent):
            logger.info("Agent iteration %d completed successfully", iteration)
        else:
            logger.warning("Agent iteration %d did not report success", iteration)
        logger.info("Restarting agent...")


if __name__ == "__main__":
    main()
