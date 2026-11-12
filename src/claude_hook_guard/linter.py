"""Validate .claude/settings.json, settings.local.json, and hooks/hooks.json."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# Source: https://code.claude.com/docs/en/hooks.md, read 2026-11-12. See COMPATIBILITY.md.
VALID_EVENTS = frozenset(
    {
        "ConfigChange", "CwdChanged", "DirectoryAdded", "Elicitation", "ElicitationResult",
        "FileChanged", "InstructionsLoaded", "MessageDisplay", "Notification", "PermissionDenied",
        "PermissionRequest", "PostCompact", "PostModelSwitch", "PostToolBatch", "PostToolUse",
        "PostToolUseFailure", "PreCompact", "PreModelSwitch", "PreToolUse", "SessionEnd",
        "SessionStart", "Setup", "Stop", "StopFailure", "SubagentStart", "SubagentStop",
        "TaskCompleted", "TaskCreated", "TeammateIdle", "UserPromptExpansion", "UserPromptSubmit",
        "WorktreeCreate", "WorktreeRemove",
    }
)
# Claude Code ignores a matcher on these events, so a matcher there is a silent no-op.
NO_MATCHER_EVENTS = frozenset(
    {
        "UserPromptSubmit", "PostToolBatch", "Stop", "TeammateIdle", "TaskCreated", "TaskCompleted",
        "WorktreeCreate", "WorktreeRemove", "MessageDisplay", "CwdChanged",
    }
)
# A handler with `if` on any other event never runs.
IF_EVENTS = frozenset({"PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest", "PermissionDenied"})
ALLOWED_MATCHER_KEYS = frozenset({"matcher", "hooks"})
COMMON_HANDLER_KEYS = frozenset({"type", "if", "timeout", "statusMessage", "once"})
HANDLER_FIELDS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    # type: (required string fields, all type-specific fields)
    "command": (frozenset({"command"}), frozenset({"command", "args", "async", "asyncRewake", "shell", "onFailure"})),
    "http": (frozenset({"url"}), frozenset({"url", "headers", "allowedEnvVars", "onFailure"})),
    "mcp_tool": (frozenset({"server", "tool"}), frozenset({"server", "tool", "input"})),
    "prompt": (frozenset({"prompt"}), frozenset({"prompt", "model"})),
    "agent": (frozenset({"prompt"}), frozenset({"prompt", "model"})),
}
ALLOWED_HANDLER_TYPES = frozenset(HANDLER_FIELDS)


@dataclass(frozen=True)
class LintFinding:
    code: str
    severity: str  # "error" or "warn"
    source: str
    path: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _lint_handler(handler: dict[str, Any], event_name: str, source: str, hpath: str) -> list[LintFinding]:
    out: list[LintFinding] = []
    htype = handler.get("type")
    if htype not in HANDLER_FIELDS:
        allowed = ", ".join(sorted(ALLOWED_HANDLER_TYPES))
        return [LintFinding("CHG004", "error", source, f"{hpath}.type", f"Handler 'type' must be one of {allowed}; got {htype!r}.")]
    required, specific = HANDLER_FIELDS[htype]

    unknown = sorted(set(handler) - COMMON_HANDLER_KEYS - specific)
    if unknown:
        out.append(LintFinding("CHG003", "warn", source, hpath, f"Unknown key(s) for a {htype} handler: {', '.join(unknown)}."))

    for key in sorted(required):
        value = handler.get(key)
        if htype == "command" and isinstance(value, list):
            out.append(
                LintFinding(
                    "CHG001",
                    "error",
                    source,
                    f"{hpath}.command",
                    "Hook 'command' must be a string. Put the program in 'command' and its arguments in 'args'.",
                )
            )
        elif not isinstance(value, str) or not value.strip():
            out.append(LintFinding("CHG004", "error", source, f"{hpath}.{key}", f"{htype} handler requires a non-empty string '{key}'."))

    args = handler.get("args")
    if args is not None and not (isinstance(args, list) and all(isinstance(a, str) for a in args)):
        out.append(LintFinding("CHG004", "error", source, f"{hpath}.args", "'args' must be an array of strings."))
    if "shell" in handler and handler["shell"] not in ("bash", "powershell"):
        out.append(LintFinding("CHG004", "error", source, f"{hpath}.shell", "'shell' accepts \"bash\" or \"powershell\"."))
    if "onFailure" in handler and handler["onFailure"] not in ("continue", "block"):
        out.append(LintFinding("CHG004", "error", source, f"{hpath}.onFailure", "'onFailure' accepts \"continue\" or \"block\"."))
    timeout = handler.get("timeout")
    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0):
        out.append(LintFinding("CHG004", "error", source, f"{hpath}.timeout", "'timeout' must be a positive number of seconds."))

    if "if" in handler and event_name not in IF_EVENTS:
        out.append(
            LintFinding(
                "CHG009",
                "error",
                source,
                f"{hpath}.if",
                f"'if' is only evaluated on tool events; on {event_name} this handler never runs.",
            )
        )
    return out


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

            if event_name in NO_MATCHER_EVENTS and group.get("matcher") not in (None, "", "*"):
                findings.append(
                    LintFinding(
                        "CHG008",
                        "warn",
                        source,
                        f"{gpath}.matcher",
                        f"{event_name} has no matcher support; Claude Code ignores this matcher and fires on every occurrence.",
                    )
                )

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
                findings.extend(_lint_handler(handler, event_name, source, hpath))

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
