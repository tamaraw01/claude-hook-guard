"""Validate .claude/settings.json, settings.local.json, and hooks/hooks.json."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

VALID_EVENTS = frozenset(
    {
        "PreToolUse",
        "PostToolUse",
        "Notification",
        "Stop",
        "SubagentStop",
        "UserPromptSubmit",
        "SessionStart",
        "SessionEnd",
        "PreCompact",
    }
)
ALLOWED_MATCHER_KEYS = frozenset({"matcher", "hooks"})
ALLOWED_HANDLER_KEYS = frozenset({"type", "command", "prompt", "timeout", "async"})
ALLOWED_HANDLER_TYPES = frozenset({"command", "prompt"})


@dataclass(frozen=True)
class LintFinding:
    code: str
    severity: str  # "error" or "warn"
    source: str
    path: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def lint_settings_dict(data: dict[str, Any], source: str = "settings.json") -> list[LintFinding]:
    findings: list[LintFinding] = []
    if not isinstance(data, dict):
        return [LintFinding("CHG000", "error", source, "$", "Root JSON value must be an object.")]

    hooks = data.get("hooks")
    if hooks is None:
        return findings
    if not isinstance(hooks, dict):
        return [LintFinding("CHG004", "error", source, "$.hooks", "'hooks' must be an object.")]

    is_local = Path(source).name == "settings.local.json"
    pretool_matchers: dict[str, int] = {}

    for event_name, groups in hooks.items():
        event_path = f"$.hooks.{event_name}"
        if event_name not in VALID_EVENTS:
            findings.append(
                LintFinding(
                    "CHG002",
                    "error",
                    source,
                    event_path,
                    f"Unknown hook event '{event_name}'. Valid events: {', '.join(sorted(VALID_EVENTS))}.",
                )
            )

        if is_local and event_name in ("PreToolUse", "PostToolUse"):
            findings.append(
                LintFinding(
                    "CHG005",
                    "warn",
                    source,
                    event_path,
                    f"{event_name} in settings.local.json can silently fail to execute; move to .claude/settings.json.",
                )
            )

        if event_name == "Stop":
            findings.append(
                LintFinding(
                    "CHG006",
                    "warn",
                    source,
                    event_path,
                    "Stop hook configured: verify script handles stop_hook_active and -p print mode without silencing stdout.",
                )
            )

        if not isinstance(groups, list):
            findings.append(LintFinding("CHG004", "error", source, event_path, "Event value must be a list of matcher groups."))
            continue

        for idx, group in enumerate(groups):
            gpath = f"{event_path}[{idx}]"
            if not isinstance(group, dict):
                findings.append(LintFinding("CHG004", "error", source, gpath, "Matcher group must be an object."))
                continue

            unknown_group_keys = sorted(set(group.keys()) - ALLOWED_MATCHER_KEYS)
            if unknown_group_keys:
                findings.append(
                    LintFinding(
                        "CHG003",
                        "warn",
                        source,
                        gpath,
                        f"Unknown matcher group key(s) {', '.join(unknown_group_keys)} trigger Claude Code 2.1.x startup warnings.",
                    )
                )

            if event_name == "PreToolUse":
                matcher_key = str(group.get("matcher", "*"))
                pretool_matchers[matcher_key] = pretool_matchers.get(matcher_key, 0) + 1

            handlers = group.get("hooks")
            if not isinstance(handlers, list) or not handlers:
                findings.append(
                    LintFinding("CHG004", "error", source, f"{gpath}.hooks", "Matcher group requires a non-empty 'hooks' array.")
                )
                continue

            for hidx, handler in enumerate(handlers):
                hpath = f"{gpath}.hooks[{hidx}]"
                if not isinstance(handler, dict):
                    findings.append(LintFinding("CHG004", "error", source, hpath, "Hook handler must be an object."))
                    continue

                unknown_hkeys = sorted(set(handler.keys()) - ALLOWED_HANDLER_KEYS)
                if unknown_hkeys:
                    findings.append(
                        LintFinding(
                            "CHG003",
                            "warn",
                            source,
                            hpath,
                            f"Unknown handler key(s): {', '.join(unknown_hkeys)}.",
                        )
                    )

                htype = handler.get("type")
                if htype not in ALLOWED_HANDLER_TYPES:
                    findings.append(
                        LintFinding("CHG004", "error", source, f"{hpath}.type", f"Handler 'type' must be 'command' or 'prompt', got {htype!r}.")
                    )
                    continue

                if htype == "command":
                    cmd = handler.get("command")
                    if isinstance(cmd, list):
                        findings.append(
                            LintFinding(
                                "CHG001",
                                "error",
                                source,
                                f"{hpath}.command",
                                "Hook 'command' must be a string, not an array (rejected by Claude Code 2.1.x schema).",
                            )
                        )
                    elif not isinstance(cmd, str) or not cmd.strip():
                        findings.append(
                            LintFinding("CHG004", "error", source, f"{hpath}.command", "Command hook requires a non-empty string 'command'.")
                        )
                elif htype == "prompt":
                    prompt = handler.get("prompt")
                    if not isinstance(prompt, str) or not prompt.strip():
                        findings.append(
                            LintFinding("CHG004", "error", source, f"{hpath}.prompt", "Prompt hook requires a non-empty string 'prompt'.")
                        )

    for matcher_key, count in sorted(pretool_matchers.items()):
        if count > 1:
            findings.append(
                LintFinding(
                    "CHG007",
                    "warn",
                    source,
                    "$.hooks.PreToolUse",
                    f"Multiple ({count}) PreToolUse matcher groups target '{matcher_key}'; updatedInput can conflict across hooks.",
                )
            )

    return findings


def lint_settings_file(path: str | Path) -> list[LintFinding]:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [LintFinding("CHG000", "error", str(p), "$", f"Failed to read JSON: {exc}")]
    return lint_settings_dict(data, source=str(p))
