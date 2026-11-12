# claude-hook-guard

Deterministic Python 3.10+ CLI that validates Claude Code hook configuration files (`.claude/settings.json`, `.claude/settings.local.json`, `hooks/hooks.json`) and simulates `PreToolUse` JSONL payloads locally without invoking Claude Code.

Distribution note: `claude-hook-guard` is a Python standard-library tool distributed via GitHub release ZIP and `python3 -m claude_hook_guard` (not published on npm or PyPI, and not affiliated with the unrelated `misty7kr/claude-hook-guard` npm package).

## Quick start

```bash
# 1. Run built-in health check
PYTHONPATH=src python3 -m claude_hook_guard doctor

# 2. Lint your Claude Code settings
PYTHONPATH=src python3 -m claude_hook_guard lint .claude/settings.json

# 3. Simulate PreToolUse JSONL payloads
PYTHONPATH=src python3 -m claude_hook_guard simulate --input examples/payloads.jsonl

# 4. Run full self-check and unit tests
bash scripts/check.sh
```

Or install into an isolated environment from the extracted folder:

```bash
pipx install .
claude-hook-guard doctor --format json
```

## What it checks

### Linter rules (`lint`)
- `CHG001` (error): `command` field is an array instead of a string (rejected by Claude Code 2.1.x schema).
- `CHG002` (error): unknown hook event name.
- `CHG003` (warn): unknown matcher group or handler keys (`$schema`, `id`, `description`) that cause startup warnings.
- `CHG004` (error): missing required fields (`hooks`, `type`, `command`, `prompt`).
- `CHG005` (warn): `PreToolUse` or `PostToolUse` placed in `.claude/settings.local.json`.
- `CHG006` (warn): `Stop` hook present without verifying `stop_hook_active` and `-p` print-mode behavior.
- `CHG007` (warn): multiple `PreToolUse` matchers targeting the same tool (risk of `updatedInput` conflicts).

### Simulator (`simulate`)
- Splits compound shell commands on `&&`, `||`, `;`, `|`, and newlines so leading `cd` commands do not mask trailing `rm -rf` or force-push operations.
- Flags `.env`, `.dev.vars`, `.npmrc`, `.netrc`, SSH key, and AWS credential access across `Read`, `Grep`, `Glob`, and `Bash`.
- With `--settings <file> --exec`, executes matching `PreToolUse` command hooks on stdin and flags exit code 2 blocks or multi-hook `updatedInput` conflicts.
