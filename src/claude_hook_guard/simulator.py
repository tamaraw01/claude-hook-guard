"""Simulate PreToolUse JSONL payloads and detect compound-shell/exfil hazards."""

from __future__ import annotations

import json
import re
import shlex
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any

DESTRUCTIVE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("rm -rf / recursive delete", re.compile(r"\brm\s+(?:-[A-Za-z]*r[A-Za-z]*f|-[A-Za-z]*f[A-Za-z]*r|--recursive\s+--force|--force\s+--recursive)\b")),
    ("git push --force", re.compile(r"\bgit\s+push\b[^\n]*(?:--force\b|-f\b)")),
    ("git reset --hard", re.compile(r"\bgit\s+reset\s+--hard\b")),
    ("mkfs filesystem format", re.compile(r"\bmkfs(?:\.[a-z0-9]+)?\b")),
    ("dd raw disk write", re.compile(r"\bdd\s+[^\n]*\bof=/dev/")),
    ("chmod 777 recursive", re.compile(r"\bchmod\s+-R\s+777\b")),
)

SECRET_PATH_RE = re.compile(
    r"(?:^|[/'\"\s=])(?:\.env(?:\.[A-Za-z0-9_.-]+)?|\.dev\.vars|\.npmrc|\.netrc|id_rsa|id_ed25519|\.aws/credentials)(?:$|[/'\"\s:])"
)
ENV_DUMP_RE = re.compile(r"\b(?:printenv|env)\b(?:\s|$)")

BUILTIN_PAYLOADS: list[dict[str, Any]] = [
    {"tool_name": "Bash", "tool_input": {"command": "cd /tmp && rm -rf /var/tmp/demo"}},
    {"tool_name": "Read", "tool_input": {"file_path": ".env.production"}},
    {"tool_name": "Bash", "tool_input": {"command": "git status && pytest -q"}},
]


@dataclass
class SimulationResult:
    index: int
    tool_name: str
    decision: str  # "allow" or "block"
    reasons: list[str] = field(default_factory=list)
    segments: list[str] = field(default_factory=list)
    hook_runs: list[dict[str, Any]] = field(default_factory=list)
    updated_input_conflict: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def split_shell_segments(command: str) -> list[str]:
    """Split a shell command on &&, ||, ;, |, and newlines while respecting quotes."""
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return [seg.strip() for seg in re.split(r"(?:&&|\|\||[;\n|])", command) if seg.strip()]

    segments: list[str] = []
    current: list[str] = []
    for tok in tokens:
        if tok in ("&&", "||", ";", "|", "&", "\n"):
            if current:
                segments.append(" ".join(current))
                current = []
        else:
            current.append(tok)
    if current:
        segments.append(" ".join(current))
    return segments


def analyze_payload(payload: dict[str, Any], index: int = 0) -> SimulationResult:
    tool_name = str(payload.get("tool_name") or payload.get("tool") or "unknown")
    tool_input = payload.get("tool_input") or payload.get("input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {}

    reasons: list[str] = []
    segments: list[str] = []

    if tool_name == "Bash":
        cmd = str(tool_input.get("command", ""))
        segments = split_shell_segments(cmd)
        for seg in segments:
            for label, pat in DESTRUCTIVE_PATTERNS:
                if pat.search(seg):
                    reasons.append(f"Destructive command ({label}) in segment: {seg}")
            if SECRET_PATH_RE.search(seg):
                reasons.append(f"Secret file reference in Bash segment: {seg}")
            if ENV_DUMP_RE.search(seg):
                reasons.append(f"Environment variable dump in Bash segment: {seg}")
    elif tool_name in ("Read", "Edit", "Write", "MultiEdit", "Grep", "Glob"):
        candidate_fields = [
            str(tool_input.get("file_path", "")),
            str(tool_input.get("path", "")),
            str(tool_input.get("pattern", "")),
        ]
        joined = " ".join(x for x in candidate_fields if x)
        if SECRET_PATH_RE.search(joined):
            reasons.append(f"Secret file access via {tool_name}: {joined.strip()}")

    decision = "block" if reasons else "allow"
    return SimulationResult(index=index, tool_name=tool_name, decision=decision, reasons=reasons, segments=segments)


def _matcher_applies(matcher: str | None, tool_name: str) -> bool:
    if not matcher or matcher == "*":
        return True
    try:
        return re.fullmatch(matcher, tool_name) is not None
    except re.error:
        return matcher == tool_name


def _exec_matching_hooks(payload: dict[str, Any], settings: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    runs: list[dict[str, Any]] = []
    updated_inputs: list[Any] = []
    tool_name = str(payload.get("tool_name") or payload.get("tool") or "")
    groups = settings.get("hooks", {}).get("PreToolUse", [])
    raw_stdin = json.dumps(payload)

    for group in groups:
        if not isinstance(group, dict):
            continue
        if not _matcher_applies(group.get("matcher"), tool_name):
            continue
        for handler in group.get("hooks", []):
            if not isinstance(handler, dict) or handler.get("type") != "command":
                continue
            cmd = handler.get("command")
            if not isinstance(cmd, str) or not cmd.strip():
                continue
            timeout = int(handler.get("timeout", 10))
            proc = subprocess.run(
                cmd,
                shell=True,
                input=raw_stdin,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            parsed_out: dict[str, Any] | None = None
            if proc.stdout.strip():
                try:
                    parsed_out = json.loads(proc.stdout.strip().splitlines()[-1])
                except json.JSONDecodeError:
                    parsed_out = None
            if isinstance(parsed_out, dict):
                hso = parsed_out.get("hookSpecificOutput")
                if isinstance(hso, dict) and "updatedInput" in hso:
                    updated_inputs.append(hso["updatedInput"])
            runs.append(
                {
                    "command": cmd,
                    "returncode": proc.returncode,
                    "stdout": proc.stdout.strip(),
                    "stderr": proc.stderr.strip(),
                }
            )
    return runs, len(updated_inputs) > 1


def replay_jsonl_lines(
    lines: list[str],
    settings: dict[str, Any] | None = None,
    exec_hooks: bool = False,
) -> list[SimulationResult]:
    results: list[SimulationResult] = []
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        payload = json.loads(stripped)
        res = analyze_payload(payload, index=idx)
        if exec_hooks and settings is not None:
            runs, conflict = _exec_matching_hooks(payload, settings)
            res.hook_runs = runs
            res.updated_input_conflict = conflict
            if any(r["returncode"] == 2 for r in runs):
                res.decision = "block"
                res.reasons.append("Hook script exited with code 2 (block).")
            if conflict:
                res.reasons.append("Multiple PreToolUse hooks returned updatedInput (conflict risk #15897).")
        results.append(res)
    return results
