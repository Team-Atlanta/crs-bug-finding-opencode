# =============================================================================
# crs-bug-finding-opencode Docker Bake Configuration
# =============================================================================
#
# Builds the CRS base image with opencode CLI and Python dependencies.
#
# Usage:
#   docker buildx bake prepare
#   docker buildx bake --push prepare   # Push to registry
# =============================================================================

variable "REGISTRY" {
  default = "ghcr.io/team-atlanta"
}

variable "VERSION" {
  default = "latest"
}

variable "OPENCODE_CLI_VERSION" {
  default = "1.4.11"
}

function "tags" {
  params = [name]
  result = [
    "${REGISTRY}/${name}:${VERSION}",
    "${REGISTRY}/${name}:latest",
    "${name}:latest"
  ]
}

# -----------------------------------------------------------------------------
# Groups
# -----------------------------------------------------------------------------

group "default" {
  targets = ["prepare"]
}

group "prepare" {
  targets = ["opencode-bug-finding-base"]
}

# -----------------------------------------------------------------------------
# Base Image
# -----------------------------------------------------------------------------

target "opencode-bug-finding-base" {
  context    = "."
  dockerfile = "oss-crs/base.Dockerfile"
  tags       = tags("opencode-bug-finding-base")
  args = {
    OPENCODE_CLI_VERSION = OPENCODE_CLI_VERSION
  }
}
