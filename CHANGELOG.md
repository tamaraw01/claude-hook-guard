# Changelog

## 1.0.0 (2026-11-12)

- Initial MIT release of `claude-hook-guard`.
- Added `lint` command for `.claude/settings.json`, `.claude/settings.local.json`, and `hooks/hooks.json` (`CHG001` through `CHG007`).
- Added `simulate` command for local `PreToolUse` JSONL replay, compound shell splitting (`&&`, `||`, `;`, `|`), destructive command checks, `.env` / credential access checks, and optional `--exec` hook runner with `updatedInput` conflict detection.
- Added `doctor` command and `scripts/check.sh` 1-command verification script.
