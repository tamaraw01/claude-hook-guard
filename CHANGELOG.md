# Changelog

## 1.0.0

- Added `claude_hook_guard.cli` and `python -m claude_hook_guard` with `lint`, `simulate`, and `doctor` subcommands and `--format json`.
- Updated linter to cover all 33 Claude Code hook events, 5 handler types (`command`, `http`, `prompt`, `agent`, `mcp_tool`), `CHG008` (matcher on no-matcher event), and `CHG009` (`if` on non-tool event).
- Updated simulator matcher evaluation to match the Claude Code spec (exact list vs unanchored regex), added `args` exec-form and timeout reporting for `--exec-hooks`, and fixed newline splitting in `split_shell_segments` while keeping `2>&1` redirects intact.
