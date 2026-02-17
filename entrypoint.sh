#!/bin/bash
set -euo pipefail

# Mark workspace as safe for git operations (only if git is installed)
if command -v git &> /dev/null && [ -n "${GITHUB_WORKSPACE:-}" ]; then
    git config --global --add safe.directory "${GITHUB_WORKSPACE}"
fi

cd /app
exec python -m src.main
