#!/usr/bin/env bash
#
# check.sh — run the same lint + test checks CI runs.
#
# Usage:
#   scripts/check.sh
#
# What it does:
#   - uv run ruff check .          (lint)
#   - uv run ruff format --check . (format check, no files modified)
#   - uv run pytest -v             (tests)
#
# Run this on demand before pushing/opening a PR, or let scripts/release.sh
# call it for you. Requires scripts/dev-setup.sh to have been run first.

set -euo pipefail

if ! command -v uv >/dev/null 2>&1; then
    echo "Error: uv is not installed. Run scripts/dev-setup.sh first."
    exit 1
fi

echo "Running lint..."
uv run ruff check .

echo
echo "Running format check..."
uv run ruff format --check .

echo
echo "Running tests..."
uv run pytest -v