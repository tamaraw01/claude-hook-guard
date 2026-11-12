"""CLI entrypoint for claude-hook-guard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .linter import LintFinding, lint_settings_file
from .simulator import BUILTIN_PAYLOADS, SimulationResult, replay_jsonl_lines


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="claude-hook-guard",
        description="Lint Claude Code hook settings and simulate PreToolUse payloads.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    lint_p = sub.add_parser("lint", help="Lint Claude Code settings.json or hooks.json files")
    lint_p.add_argument("paths", nargs="+", help="Settings JSON files or directories containing them")
    lint_p.add_argument("--strict", action="store_true", help="Exit 1 on warnings as well as errors")
    lint_p.add_argument("--format", choices=("text", "json"), default="text")

    sim_p = sub.add_parser("simulate", help="Replay PreToolUse JSONL payloads against hook rules")
    src_group = sim_p.add_mutually_exclusive_group(required=True)
    src_group.add_argument("--suite", help="Path to a JSONL file of PreToolUse payloads")
    src_group.add_argument("--builtin-suite", action="store_true", help="Run the 3 built-in regression payloads")
    sim_p.add_argument("--settings", help="Optional settings.json/hooks.json for live hook execution")
    sim_p.add_argument("--exec-hooks", action="store_true", help="Execute matching command hooks in --settings")
    sim_p.add_argument("--format", choices=("text", "json"), default="text")

    doc_p = sub.add_parser("doctor", help="Verify runtime environment and built-in self-checks")
    doc_p.add_argument("--format", choices=("text", "json"), default="text")
    return p


def _expand_settings_paths(raw_paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for raw in raw_paths:
        p = Path(raw)
        if p.is_dir():
            out.extend(sorted(p.rglob("*.json")))
        else:
            out.append(p)
    return out


def _run_lint(paths: list[str], fmt: str, strict: bool) -> int:
    findings: list[LintFinding] = []
    targets = _expand_settings_paths(paths)
    if not targets:
        findings.append(LintFinding("CHG000", "error", "No JSON files found in target path(s).", paths[0]))
    for target in targets:
        findings.extend(lint_settings_file(target))

    errors = sum(1 for f in findings if f.severity == "error")
    warnings = sum(1 for f in findings if f.severity in ("warn", "warning"))
    ok = errors == 0 and (not strict or warnings == 0)

    if fmt == "json":
        print(json.dumps({
            "ok": ok,
            "version": __version__,
            "summary": {"errors": errors, "warnings": warnings},
            "findings": [f.to_dict() for f in findings],
        }, indent=2))
    else:
        for f in findings:
            loc = f"{f.source}: {f.path}: " if f.path else f"{f.source}: "
            print(f"{f.severity.upper()} {f.code} {loc}{f.message}")
        print(f"Summary: {errors} errors, {warnings} warnings")
    return 0 if ok else 1


def _load_settings(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _run_simulate(
    suite_path: str | None,
    builtin_suite: bool,
    settings_path: str | None,
    exec_hooks: bool,
    fmt: str,
) -> int:
    if builtin_suite:
        lines = [json.dumps(p) for p in BUILTIN_PAYLOADS]
    else:
        assert suite_path is not None
        lines = Path(suite_path).read_text(encoding="utf-8").splitlines()

    settings = _load_settings(settings_path)
    results: list[SimulationResult] = replay_jsonl_lines(
        lines,
        settings=settings,
        exec_hooks=exec_hooks,
    )
    blocked = sum(1 for r in results if r.decision == "block")
    allowed = sum(1 for r in results if r.decision == "allow")
    summary = {"total": len(results), "blocked": blocked, "allowed": allowed}

    if fmt == "json":
        print(json.dumps({
            "version": __version__,
            "summary": summary,
            "results": [r.to_dict() for r in results],
        }, indent=2))
    else:
        for r in results:
            reason_str = "; ".join(r.reasons) if r.reasons else "no policy match"
            print(f"[{r.index}] {r.tool_name} -> {r.decision.upper()} ({reason_str})")
        print(f"Summary: {len(results)} total, {blocked} blocked, {allowed} allowed")
    return 0


def _run_doctor(fmt: str) -> int:
    results = replay_jsonl_lines([json.dumps(p) for p in BUILTIN_PAYLOADS])
    ok = len(results) == 3 and sum(1 for r in results if r.decision == "block") == 2
    payload = {
        "ok": ok,
        "version": __version__,
        "python": sys.version.split()[0],
        "builtin_suite_count": len(results),
    }
    if fmt == "json":
        print(json.dumps(payload, indent=2))
    else:
        status = "ok" if ok else "failed"
        print(f"claude-hook-guard {__version__} {status} (python {payload['python']})")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.cmd == "lint":
        return _run_lint(args.paths, args.format, args.strict)
    if args.cmd == "simulate":
        return _run_simulate(args.suite, args.builtin_suite, args.settings, args.exec_hooks, args.format)
    if args.cmd == "doctor":
        return _run_doctor(args.format)
    return 2
