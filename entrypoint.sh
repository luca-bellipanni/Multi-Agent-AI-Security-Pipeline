#!/bin/bash
set -euo pipefail

# Mark workspace as safe for git operations inside the container
if [ -n "${GITHUB_WORKSPACE:-}" ]; then
    git config --global --add safe.directory "${GITHUB_WORKSPACE}"
fi

exec python /app/src/main.py
