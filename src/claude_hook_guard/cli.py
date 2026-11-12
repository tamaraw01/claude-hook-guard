"""CLI entrypoint for claude-hook-guard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from claude_hook_guard import __version__
from claude_hook_guard.linter import LintFinding, lint_settings_dict, lint_settings_file
from claude_hook_guard.simulator import BUILTIN_PAYLOADS, analyze_payload, replay_jsonl_lines


def _cmd_lint(args: argparse.Namespace) -> int:
    findings: list[LintFinding] = []
    for target in args.paths:
        findings.extend(lint_settings_file(target))

    errors = sum(1 for f in findings if f.severity == "error")
    warns = sum(1 for f in findings if f.severity == "warn")
    ok = errors == 0 and (warns == 0 if args.strict else True)

    if args.format == "json":
        print(
            json.dumps(
                {
                    "ok": ok,
                    "errors": errors,
                    "warnings": warns,
                    "findings": [f.to_dict() for f in findings],
                },
                indent=2,
            )
        )
    else:
        for f in findings:
            print(f"[{f.severity.upper()}] {f.code} {f.source} ({f.path}): {f.message}")
        print(f"Summary: {errors} error(s), {warns} warning(s)")

    return 0 if ok else 1


def _cmd_simulate(args: argparse.Namespace) -> int:
    if args.builtin_suite:
        lines = [json.dumps(p) for p in BUILTIN_PAYLOADS]
    elif args.input:
        lines = Path(args.input).read_text(encoding="utf-8").splitlines()
    else:
        lines = sys.stdin.read().splitlines()

    settings: dict[str, Any] | None = None
    if args.settings:
        settings = json.loads(Path(args.settings).read_text(encoding="utf-8"))

    results = replay_jsonl_lines(lines, settings=settings, exec_hooks=bool(args.exec_hooks))
    blocked = sum(1 for r in results if r.decision == "block")
    allowed = len(results) - blocked

    if args.format == "json":
        print(
            json.dumps(
                {
                    "summary": {"total": len(results), "blocked": blocked, "allowed": allowed},
                    "results": [r.to_dict() for r in results],
                },
                indent=2,
            )
        )
    else:
        for r in results:
            reason_str = "; ".join(r.reasons) if r.reasons else "no hazards detected"
            print(f"#{r.index} [{r.decision.upper()}] {r.tool_name}: {reason_str}")
        print(f"Summary: {len(results)} payload(s), {blocked} blocked, {allowed} allowed")

    return 1 if (args.fail_on_block and blocked > 0) else 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    py_ok = sys.version_info >= (3, 10)
    bad_sample = {
        "hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": ["python3", "g.py"]}]}
            ]
        }
    }
    lint_hits = lint_settings_dict(bad_sample, source="doctor-sample.json")
    sim_hit = analyze_payload({"tool_name": "Bash", "tool_input": {"command": "cd /tmp && rm -rf /"}})
    ok = py_ok and any(f.code == "CHG001" for f in lint_hits) and sim_hit.decision == "block"

    payload = {
        "ok": ok,
        "version": __version__,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "checks": {
            "python_3_10_plus": py_ok,
            "linter_self_test": any(f.code == "CHG001" for f in lint_hits),
            "simulator_self_test": sim_hit.decision == "block",
        },
    }
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        print(f"claude-hook-guard {__version__} (Python {payload['python']}): {'OK' if ok else 'FAIL'}")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="claude-hook-guard",
        description="Lint Claude Code hook settings and simulate PreToolUse JSONL payloads.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_lint = sub.add_parser("lint", help="Validate .claude/settings.json or hooks/hooks.json")
    p_lint.add_argument("paths", nargs="+", help="Settings or hooks.json file paths")
    p_lint.add_argument("--format", choices=("text", "json"), default="text")
    p_lint.add_argument("--strict", action="store_true", help="Exit 1 on warnings as well as errors")
    p_lint.set_defaults(func=_cmd_lint)

    p_sim = sub.add_parser("simulate", help="Simulate PreToolUse JSONL payloads")
    p_sim.add_argument("--input", help="Path to JSONL file (reads stdin if omitted)")
    p_sim.add_argument("--builtin-suite", action="store_true", help="Run built-in test payloads")
    p_sim.add_argument("--settings", help="Optional settings.json for hook execution")
    p_sim.add_argument("--exec", dest="exec_hooks", action="store_true", help="Execute matching PreToolUse command hooks")
    p_sim.add_argument("--fail-on-block", action="store_true", help="Exit 1 if any payload is blocked")
    p_sim.add_argument("--format", choices=("text", "json"), default="text")
    p_sim.set_defaults(func=_cmd_simulate)

    p_doc = sub.add_parser("doctor", help="Run environment and built-in self-check")
    p_doc.add_argument("--format", choices=("text", "json"), default="text")
    p_doc.set_defaults(func=_cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))
