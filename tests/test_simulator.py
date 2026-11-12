import json
import sys
import tempfile
import unittest
from pathlib import Path

from claude_hook_guard.simulator import (
    analyze_payload,
    replay_jsonl_lines,
    split_shell_segments,
)


class SimulatorTests(unittest.TestCase):
    def test_splits_compound_shell_commands_and_catches_trailing_rm(self) -> None:
        segments = split_shell_segments("cd /tmp/work && ls -la; rm -rf /var/tmp/x")
        self.assertEqual(len(segments), 3)
        res = analyze_payload({"tool_name": "Bash", "tool_input": {"command": "cd /tmp && rm -rf /"}})
        self.assertEqual(res.decision, "block")
        self.assertTrue(any("rm -rf" in r for r in res.reasons))

    def test_catches_env_and_dev_vars_reads_across_read_grep_and_bash(self) -> None:
        r1 = analyze_payload({"tool_name": "Read", "tool_input": {"file_path": "/app/.env.production"}})
        r2 = analyze_payload({"tool_name": "Grep", "tool_input": {"path": ".dev.vars", "pattern": "SECRET"}})
        r3 = analyze_payload({"tool_name": "Bash", "tool_input": {"command": "echo ok && cat ~/.aws/credentials"}})
        for r in (r1, r2, r3):
            self.assertEqual(r.decision, "block")

    def test_allows_safe_readonly_commands(self) -> None:
        r = analyze_payload({"tool_name": "Bash", "tool_input": {"command": "git status && pytest -q"}})
        self.assertEqual(r.decision, "allow")

    def test_replay_jsonl_with_exec_hook_and_updated_input_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            hook1 = t / "h1.py"
            hook2 = t / "h2.py"
            hook1.write_text(
                'import json, sys\n'
                'sys.stdin.read()\n'
                'print(json.dumps({"hookSpecificOutput": {"updatedInput": {"command": "echo 1"}}}))\n',
                encoding="utf-8",
            )
            hook2.write_text(
                'import json, sys\n'
                'sys.stdin.read()\n'
                'print(json.dumps({"hookSpecificOutput": {"updatedInput": {"command": "echo 2"}}}))\n',
                encoding="utf-8",
            )
            settings = {
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "Bash", "hooks": [{"type": "command", "command": f"{sys.executable} {hook1}"}]},
                        {"matcher": "Bash", "hooks": [{"type": "command", "command": f"{sys.executable} {hook2}"}]},
                    ]
                }
            }
            lines = [json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo hi"}})]
            results = replay_jsonl_lines(lines, settings=settings, exec_hooks=True)
            self.assertEqual(len(results), 1)
            self.assertTrue(results[0].updated_input_conflict)


if __name__ == "__main__":
    unittest.main()
