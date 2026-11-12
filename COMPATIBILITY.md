# Compatibility matrix

| Component | Supported versions | Notes |
|---|---|---|
| Python | 3.10, 3.11, 3.12, 3.13 | Standard library only; zero third-party packages |
| OS | Linux, macOS, Windows (WSL or native Python) | Uses `pathlib` and `shlex` |
| Claude Code | 2.1.x hook schema | Validates `PreToolUse`, `PostToolUse`, `Stop`, `SubagentStop`, `Notification`, `UserPromptSubmit`, `SessionStart`, `SessionEnd`, `PreCompact` |
| Distribution | GitHub release ZIP, `python3 -m claude_hook_guard`, `pipx install` from source | Not published on npm or PyPI |
