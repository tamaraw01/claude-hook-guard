# Compatibility Matrix

## Claude Code Hooks Specification

- Authoritative source: `https://code.claude.com/docs/en/hooks.md` (verified 2026-11-12)
- Supported lifecycle events: 33 (`ConfigChange`, `CwdChanged`, `DirectoryAdded`, `Elicitation`, `ElicitationResult`, `FileChanged`, `InstructionsLoaded`, `Notification`, `PermissionDenied`, `PermissionRequest`, `PostCompact`, `PostToolUse`, `PostToolUseFailure`, `PreCompact`, `PreToolUse`, `SessionEnd`, `SessionStart`, `Setup`, `Stop`, `StopFailure`, `SubagentStart`, `SubagentStop`, `TaskCompleted`, `TaskCreated`, `TeammateIdle`, `ToolResult`, `UserPromptSubmit`, `WorktreeCreate`, `WorktreeRemove`, plus `PreToolUse`/`PostToolUse` matcher variants and tool events listed in `VALID_EVENTS` in `src/claude_hook_guard/linter.py`).
- Supported handler types: 5 (`command`, `http`, `prompt`, `agent`, `mcp_tool`).
- Matcher rules: `*`, empty, or omitted matches all; `[A-Za-z0-9_ ,|-]+` is evaluated as an exact pipe-delimited list; any other pattern is evaluated as an unanchored regex.

## Runtime Environment

| Component | Supported | Notes |
|---|---|---|
| Python | 3.10, 3.11, 3.12, 3.13 | Stdlib only; zero third-party runtime dependencies |
| OS | Linux, macOS, Windows (WSL / Git Bash) | `check.sh` requires Bash; CLI runs under any Python 3.10+ |
| Packaging | Source checkout, `pip install -e .`, release ZIP | Tested in clean `HOME` with `PYTHONNOUSERSITE=1` |
