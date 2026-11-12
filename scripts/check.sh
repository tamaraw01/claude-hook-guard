#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="${ROOT_DIR}/src"

python3 -m claude_hook_guard doctor --format json
python3 -m claude_hook_guard lint "${ROOT_DIR}/examples/settings.good.json" --format json
python3 -m claude_hook_guard simulate --input "${ROOT_DIR}/examples/payloads.jsonl" --format json
python3 -m unittest discover -s "${ROOT_DIR}/tests" -t "${ROOT_DIR}" -q
echo "check.sh: OK"
