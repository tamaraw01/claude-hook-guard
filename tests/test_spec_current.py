"""Checks against the hooks reference at code.claude.com/docs/en/hooks.md."""

import sys
import unittest

from claude_hook_guard.linter import lint_settings_dict
from claude_hook_guard.simulator import SimulationResult, _matcher_applies, analyze_payload, replay_jsonl_lines, split_shell_segments


def _cfg(event: str, handler: dict, **group: object) -> dict:
    return {"hooks": {event: [{**group, "hooks": [handler]}]}}


def _codes(cfg: dict) -> set[str]:
    return {f.code for f in lint_settings_dict(cfg, source=".claude/settings.json")}


class CurrentEventsTests(unittest.TestCase):
    def test_accepts_events_added_after_the_first_nine(self) -> None:
        for event in ("PostToolUseFailure", "PermissionRequest", "SubagentStart", "TaskCompleted", "WorktreeCreate", "FileChanged"):
            with self.subTest(event=event):
                self.assertNotIn("CHG002", _codes(_cfg(event, {"type": "command", "command": "true"})))

    def test_matcher_on_event_without_matcher_support_warns(self) -> None:
        codes = _codes(_cfg("UserPromptSubmit", {"type": "command", "command": "true"}, matcher="Bash"))
        self.assertIn("CHG008", codes)

    def test_matcher_on_tool_event_does_not_warn(self) -> None:
        self.assertNotIn("CHG008", _codes(_cfg("PreToolUse", {"type": "command", "command": "true"}, matcher="Bash")))

    def test_if_field_on_non_tool_event_is_an_error(self) -> None:
        codes = _codes(_cfg("Stop", {"type": "command", "command": "true", "if": "Bash(git *)"}))
        self.assertIn("CHG009", codes)

    def test_if_field_on_pretooluse_is_fine(self) -> None:
        self.assertNotIn("CHG009", _codes(_cfg("PreToolUse", {"type": "command", "command": "true", "if": "Bash(git *)"})))


class HandlerTypeTests(unittest.TestCase):
    def test_accepts_all_five_handler_types_with_required_fields(self) -> None:
        handlers = [
            {"type": "command", "command": "guard.sh", "args": ["--strict"], "shell": "bash", "statusMessage": "Checking"},
            {"type": "http", "url": "http://localhost:8080/hook", "headers": {"Authorization": "Bearer $TOKEN"}, "allowedEnvVars": ["TOKEN"]},
            {"type": "mcp_tool", "server": "my_server", "tool": "security_scan", "input": {"file_path": "${tool_input.file_path}"}},
            {"type": "prompt", "prompt": "Is this safe? $ARGUMENTS", "model": "haiku"},
            {"type": "agent", "prompt": "Verify tests pass. $ARGUMENTS", "timeout": 120},
        ]
        for handler in handlers:
            with self.subTest(type=handler["type"]):
                self.assertEqual(_codes(_cfg("PreToolUse", handler, matcher="Bash")), set())

    def test_http_without_url_is_an_error(self) -> None:
        self.assertIn("CHG004", _codes(_cfg("PreToolUse", {"type": "http"}, matcher="Bash")))

    def test_mcp_tool_without_tool_is_an_error(self) -> None:
        self.assertIn("CHG004", _codes(_cfg("PreToolUse", {"type": "mcp_tool", "server": "s"}, matcher="Bash")))

    def test_agent_without_prompt_is_an_error(self) -> None:
        self.assertIn("CHG004", _codes(_cfg("Stop", {"type": "agent"})))

    def test_args_must_be_list_of_strings(self) -> None:
        self.assertIn("CHG004", _codes(_cfg("PreToolUse", {"type": "command", "command": "x", "args": "--strict"}, matcher="Bash")))

    def test_shell_value_is_checked(self) -> None:
        self.assertIn("CHG004", _codes(_cfg("PreToolUse", {"type": "command", "command": "x", "shell": "zsh"}, matcher="Bash")))

    def test_field_from_other_handler_type_warns(self) -> None:
        self.assertIn("CHG003", _codes(_cfg("PreToolUse", {"type": "prompt", "prompt": "p", "url": "http://x"}, matcher="Bash")))


class MatcherSemanticsTests(unittest.TestCase):
    def test_pipe_list_is_exact(self) -> None:
        self.assertTrue(_matcher_applies("Edit|Write", "Write"))
        self.assertFalse(_matcher_applies("Edit|Write", "NotebookEdit"))

    def test_regex_matcher_is_unanchored(self) -> None:
        self.assertTrue(_matcher_applies("^Notebook", "NotebookEdit"))
        self.assertTrue(_matcher_applies("mcp__memory__.*", "mcp__memory__create_entities"))

    def test_star_and_empty_match_everything(self) -> None:
        self.assertTrue(_matcher_applies("*", "Bash"))
        self.assertTrue(_matcher_applies("", "Bash"))


class NewlineSplitTests(unittest.TestCase):
    def test_newline_starts_a_new_segment(self) -> None:
        self.assertEqual(split_shell_segments("echo a\nrm -rf /x"), ["echo a", "rm -rf /x"])

    def test_quoted_newline_stays_in_one_segment(self) -> None:
        self.assertEqual(split_shell_segments("echo 'a\nb' && ls"), ["echo a\nb", "ls"])

    def test_redirect_ampersand_is_not_a_separator(self) -> None:
        self.assertEqual(split_shell_segments("make 2>&1 && ls"), ["make 2 >& 1", "ls"])

    def test_newline_chained_rm_reported_in_own_segment(self) -> None:
        res = analyze_payload({"tool_name": "Bash", "tool_input": {"command": "echo ok\nrm -rf /var/x"}})
        self.assertEqual(res.decision, "block")
        self.assertTrue(any(r.endswith("segment: rm -rf /var/x") for r in res.reasons))


class ExecHooksTests(unittest.TestCase):
    PAYLOAD = '{"tool_name": "Bash", "tool_input": {"command": "ls"}}'

    def _run(self, handler: dict) -> SimulationResult:
        settings = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [handler]}]}}
        return replay_jsonl_lines([self.PAYLOAD], settings=settings, exec_hooks=True)[0]

    def test_exec_form_args_are_passed_without_shell(self) -> None:
        handler = {"type": "command", "command": sys.executable, "args": ["-c", "import sys; sys.exit(2)"]}
        res = self._run(handler)
        self.assertEqual(res.hook_runs[0]["returncode"], 2)
        self.assertEqual(res.decision, "block")

    def test_timeout_is_reported_not_raised(self) -> None:
        handler = {"type": "command", "command": sys.executable, "args": ["-c", "import time; time.sleep(5)"], "timeout": 0.2}
        res = self._run(handler)
        self.assertEqual(res.hook_runs[0]["returncode"], None)
        self.assertTrue(any("timed out" in r for r in res.reasons))

    def test_non_command_handlers_are_listed_as_skipped(self) -> None:
        res = self._run({"type": "http", "url": "http://127.0.0.1:9/hook"})
        self.assertEqual(res.hook_runs, [])
        self.assertTrue(any("http handler not executed" in r for r in res.reasons))


if __name__ == "__main__":
    unittest.main()
