import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CLI_SRC = str(Path(__file__).resolve().parents[1] / "src")


class CliTests(unittest.TestCase):
    def _run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "PYTHONPATH": CLI_SRC, "PYTHONNOUSERSITE": "1"}
        return subprocess.run(
            [sys.executable, "-m", "claude_hook_guard", *args],
            env=env,
            capture_output=True,
            text=True,
        )

    def test_lint_command_returns_nonzero_on_invalid_schema_and_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "hooks.json"
            bad.write_text(
                json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": ["echo", "hi"]}]}]}}),
                encoding="utf-8",
            )
            proc = self._run_cli("lint", str(bad), "--format", "json")
            self.assertEqual(proc.returncode, 1)
            report = json.loads(proc.stdout)
            self.assertFalse(report["ok"])
            self.assertEqual(report["findings"][0]["code"], "CHG001")

    def test_simulate_builtin_suite_json(self) -> None:
        proc = self._run_cli("simulate", "--builtin-suite", "--format", "json")
        self.assertEqual(proc.returncode, 0)
        report = json.loads(proc.stdout)
        self.assertEqual(report["summary"]["total"], 3)
        self.assertEqual(report["summary"]["blocked"], 2)
        self.assertEqual(report["summary"]["allowed"], 1)

    def test_doctor_command_reports_ok(self) -> None:
        proc = self._run_cli("doctor", "--format", "json")
        self.assertEqual(proc.returncode, 0)
        report = json.loads(proc.stdout)
        self.assertTrue(report["ok"])


if __name__ == "__main__":
    unittest.main()
