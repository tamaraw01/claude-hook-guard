import json
import tempfile
import unittest
from pathlib import Path

from claude_hook_guard.linter import lint_settings_dict, lint_settings_file


class LinterTests(unittest.TestCase):
    def test_flags_array_command_field_ecc1454(self) -> None:
        cfg = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": ["python3", "guard.py"]}],
                    }
                ]
            }
        }
        findings = lint_settings_dict(cfg, source="hooks/hooks.json")
        codes = [f.code for f in findings]
        self.assertIn("CHG001", codes)

    def test_flags_unknown_event_and_unknown_matcher_keys(self) -> None:
        cfg = {
            "hooks": {
                "InvalidEvent": [
                    {
                        "$schema": "https://example.com/schema.json",
                        "id": "bad-1",
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "echo ok"}],
                    }
                ]
            }
        }
        findings = lint_settings_dict(cfg, source=".claude/settings.json")
        codes = {f.code for f in findings}
        self.assertIn("CHG002", codes)
        self.assertIn("CHG003", codes)

    def test_flags_settings_local_pretooluse_trap(self) -> None:
        cfg = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "python3 guard.py"}],
                    }
                ]
            }
        }
        findings = lint_settings_dict(cfg, source=".claude/settings.local.json")
        codes = {f.code for f in findings}
        self.assertIn("CHG005", codes)

    def test_flags_stop_hook_print_mode_hazard_and_multi_pretooluse(self) -> None:
        cfg = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "python3 a.py"}]},
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "python3 b.py"}]},
                ],
                "Stop": [
                    {"hooks": [{"type": "command", "command": "python3 stop.py"}]}
                ],
            }
        }
        findings = lint_settings_dict(cfg, source=".claude/settings.json")
        codes = {f.code for f in findings}
        self.assertIn("CHG006", codes)
        self.assertIn("CHG007", codes)

    def test_clean_settings_file_passes_without_errors(self) -> None:
        cfg = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "python3 guard.py", "timeout": 10}],
                    }
                ]
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "settings.json"
            p.write_text(json.dumps(cfg), encoding="utf-8")
            findings = lint_settings_file(p)
        errors = [f for f in findings if f.severity == "error"]
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
