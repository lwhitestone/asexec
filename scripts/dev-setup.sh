#!/usr/bin/env bash
#
# dev-setup.sh — one-time local dev environment setup.
#
# Usage:
#   scripts/dev-setup.sh
#
# What it does:
#   - Installs uv if it isn't already on PATH (via the official installer)
#   - Runs `uv sync --all-extras --dev` to create the venv and install deps
#
# Run this once per clone (or after pulling dependency changes). It does
# NOT run lint or tests — use scripts/check.sh for that.

set -euo pipefail

if ! command -v uv >/dev/null 2>&1; then
    echo "uv not found — installing it now..."
    curl -LsSf https://astral.sh/uv/install.sh | sh

    # The installer places uv in ~/.local/bin (or ~/.cargo/bin on older
    # versions); that dir may not be on PATH yet in this shell.
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

    if ! command -v uv >/dev/null 2>&1; then
        echo "Error: uv installed but not found on PATH."
        echo "Open a new terminal (or 'source ~/.bashrc') and re-run this script."
        exit 1
    fi

    echo "uv installed: $(uv --version)"
fi

echo "Syncing dependencies (including dev + extras)..."
uv sync --all-extras --dev

echo
echo "Dev environment ready. Common commands:"
echo "  scripts/check.sh           # lint + tests"
echo "  uv run pytest              # run tests"
echo "  uv run ruff check .        # lint"
echo "  uv run ruff format .       # format"
echo "  uv run asexec --help       # run the CLI"
echo "  scripts/release.sh X.Y.Z   # cut a release"