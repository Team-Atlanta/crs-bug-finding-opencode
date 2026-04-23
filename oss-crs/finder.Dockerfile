# =============================================================================
# crs-bug-finding-opencode Finder Module
# =============================================================================
# RUN phase: Analyzes source code and crafts POV inputs using opencode.
#
# Uses pre-built ASAN harness from the build phase — no builder sidecar needed.
# =============================================================================

# These ARGs are required by the oss-crs framework template
ARG target_base_image
ARG crs_version

FROM opencode-bug-finding-base

# Install libCRS (CLI + Python package)
COPY --from=libcrs . /libCRS
RUN pip3 install /libCRS \
    && python3 -c "from libCRS.base import DataType; print('libCRS OK')"

# Install crs-bug-finding-opencode package (finder + agents)
COPY pyproject.toml /opt/crs-bug-finding-opencode/pyproject.toml
COPY finder.py /opt/crs-bug-finding-opencode/finder.py
COPY agents/ /opt/crs-bug-finding-opencode/agents/
RUN pip3 install /opt/crs-bug-finding-opencode

CMD ["run_finder"]
