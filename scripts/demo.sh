#!/usr/bin/env bash
# One-command demo path. Fails fast unless running on Nebius Token Factory.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/bin:$PATH"
uv run redline preflight
uv run redline audit fixtures/poisoned-repo
