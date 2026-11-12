#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHONPATH=src python3 -m unittest discover -s tests -t . -q
PYTHONPATH=src python3 -m claude_hook_guard doctor --format json
PYTHONPATH=src python3 -m claude_hook_guard simulate --builtin-suite --format json
PYTHONPATH=src python3 -m claude_hook_guard lint examples/settings.valid.json --format json
echo "claude-hook-guard check.sh ok"
