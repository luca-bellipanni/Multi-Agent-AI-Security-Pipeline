#!/bin/bash
set -euo pipefail

# GitHub Actions passes -e HOME=/github/home (root-owned) to Docker.
# Override to appuser's home so git config --global can write.
export HOME=/home/appuser

# Mark workspace as safe for git operations (only if git is installed)
if command -v git &> /dev/null && [ -n "${GITHUB_WORKSPACE:-}" ]; then
    git config --global --add safe.directory "${GITHUB_WORKSPACE}"
fi

cd /app
exec python -m src.main
