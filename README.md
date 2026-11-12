# claude-hook-guard

Deterministic Python 3.10+ CLI that lints Claude Code hook settings (`.claude/settings.json`, `.claude/settings.local.json`, `hooks/hooks.json`) and simulates `PreToolUse` JSONL payloads offline. Zero external runtime dependencies.

Note: This Python package is unrelated to the third-party `claude-hook-guard` package on npm. Do not install via `npx`.

## Packaged Releases

- Packaged ZIP release (`$0+` MIT): [Download claude-hook-guard on Gumroad](https://aditama1.gumroad.com/l/claude-hook-guard)
- Tested hook scripts & CI workflows: [Claude Code Guardrails Kit ($39 / $79 / $149)](https://aditama1.gumroad.com/l/claude-hook-guard-kit) (use code `HOOKS20` for 20% off Pro `$79` or Team `$149`)

| Tier | Price | What Is Included |
|---|---:|---|
| **[claude-hook-guard](https://aditama1.gumroad.com/l/claude-hook-guard)** | **$0+** | This MIT CLI (`lint`, `simulate`, `doctor`) as a packaged ZIP |
| **[Solo Guardrails](https://aditama1.gumroad.com/l/claude-hook-guard-kit)** | **$39** | `PreToolUse` destructive-shell guard, `.env` and credential file-boundary guard, GitHub Actions + `pre-commit` recipes, starter `settings.json` config pack (22 files) |
| **[Guardrails Pro (Recommended)](https://aditama1.gumroad.com/l/claude-hook-guard-kit)** | **$79** | Everything in Solo + compound bash splitter, `PostToolUse` secret redactor, hardened `Stop` gate pack, JSONL replay suite, `updatedInput` conflict checker (28 files, `$63.20` with `HOOKS20`) |
| **[Team & CI Governance](https://aditama1.gumroad.com/l/claude-hook-guard-kit)** | **$149** | Everything in Pro + 5-seat commercial license, multi-repo org policy pack, org CI matrix workflow (34 files, `$119.20` with `HOOKS20`) |

Every paid tier has a 14-day refund policy.

## Quick start

Run directly from the unpacked archive or repo without installing anything:

```bash
PYTHONPATH=src python3 -m claude_hook_guard doctor
PYTHONPATH=src python3 -m claude_hook_guard simulate --builtin-suite
PYTHONPATH=src python3 -m claude_hook_guard lint examples/settings.valid.json
```

Or install into a virtual environment:

```bash
python3 -m pip install -e .
claude-hook-guard doctor --format json
```

Run the self-check and unit tests in one command:

```bash
bash scripts/check.sh
```

## Subcommands

### `lint <path...> [--strict] [--format text|json]`

Validates one or more settings JSON files (or directories of `.json` files) against the Claude Code hooks reference:

- `CHG001`: invalid hook handler schema (for example `command` as an array instead of a string, missing `url` on `http`, missing `tool` on `mcp_tool`, or invalid `shell` value).
- `CHG002`: unknown hook event name or unknown handler `type`.
- `CHG003`: broad or risky `PreToolUse` matcher without a targeted guard.
- `CHG004`: `Stop` hook present without a `stop_hook_active` loop guard.
- `CHG005`: multiple `PreToolUse` command hooks that risk `updatedInput` conflicts.
- `CHG008`: `matcher` set on an event that does not support matchers (`UserPromptSubmit`, `Stop`, etc.).
- `CHG009`: `if` condition set on a non-tool event.

Exit codes: `0` when valid, `1` when any error is found (or warning with `--strict`).

### `simulate (--builtin-suite | --suite <jsonl>) [--settings <json>] [--exec-hooks] [--format text|json]`

Replays `PreToolUse` JSONL payloads through the segment splitter (`&&`, `||`, `;`, `|`, `&`, and unquoted newlines) and checks for destructive shell commands (`rm -rf` outside safe paths) and `.env` / credential reads.

Pass `--settings` with `--exec-hooks` to execute matching `command` hooks locally (supporting both shell string and `args` exec form, with timeout reporting). Non-command handlers (`http`, `prompt`, `agent`, `mcp_tool`) are skipped and reported in `reasons`.

### `doctor [--format text|json]`

Verifies Python version, imports, and the 3-case built-in regression suite.
