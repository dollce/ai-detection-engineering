"""Offline contract tests for the Codex CLI reasoning adapter.

No test starts a model, authenticates, downloads a CLI, or contacts a SIEM.
Run from the repository root: python -m unittest discover -s tests/unit -v
"""

import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "autonomous"))
from orchestration import codex_llm  # noqa: E402


class CodexAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = Path(self.temp.name) / "config.yml"
        self.config.write_text(yaml.safe_dump({"agents": {
            "author": {"model": "author-test-model"},
            "tuning": {"model": "tuning-test-model"},
            "intel": {"model": None},
        }}), encoding="utf-8")
        self.enterContext(patch.object(codex_llm, "CONFIG_PATH", self.config))
        self.enterContext(patch.dict(os.environ, {}, clear=True))
        self.which = self.enterContext(patch.object(
            codex_llm.shutil, "which", return_value="/mock/bin/codex"))
        self.calls = []
        self.output = "final answer"
        self.stdout = '{"type":"thread.started","thread_id":"event-only"}\n'
        self.returncode = 0
        self.stderr = ""
        self.login_returncode = 0
        self.failure = None
        self.run = self.enterContext(patch.object(
            codex_llm.subprocess, "run", side_effect=self.fake_run))

    def fake_run(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        if "login" in cmd and "status" in cmd:
            return subprocess.CompletedProcess(cmd, self.login_returncode,
                                               stdout="", stderr="Logged in using ChatGPT")
        self.assertIn("exec", cmd, "Only login status and exec are expected")
        if self.failure is not None:
            raise self.failure
        output_flag = "-o" if "-o" in cmd else "--output-last-message"
        output_path = Path(cmd[cmd.index(output_flag) + 1])
        if self.output is not None:
            output_path.write_text(self.output, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, self.returncode,
                                           stdout=self.stdout, stderr=self.stderr)

    def exec_call(self):
        return next((cmd, kwargs) for cmd, kwargs in reversed(self.calls) if "exec" in cmd)

    def config_overrides(self, cmd):
        result = {}
        for index, arg in enumerate(cmd[:-1]):
            if arg in ("-c", "--config"):
                parsed = tomllib.loads(cmd[index + 1])
                # Flatten nested TOML keys to make the policy assertions readable.
                def flatten(values, prefix=""):
                    for key, value in values.items():
                        name = prefix + key
                        if isinstance(value, dict) and value:
                            flatten(value, name + ".")
                        else:
                            result[name] = value
                flatten(parsed)
        return result

    def test_ci_never_attempts_authentication_or_execution(self):
        for variable in ("CI", "GITHUB_ACTIONS"):
            with self.subTest(variable=variable), patch.dict(os.environ, {variable: "true"}):
                self.assertFalse(codex_llm.is_available())
        self.which.assert_not_called()
        self.run.assert_not_called()

    def test_direct_ask_in_ci_cannot_bypass_deterministic_fallback(self):
        for variable in ("CI", "GITHUB_ACTIONS"):
            with self.subTest(variable=variable), patch.dict(os.environ, {variable: "true"}):
                result = codex_llm.ask("test")
                self.assertFalse(result["success"])
                self.assertTrue(result["error"])
        self.which.assert_not_called()
        self.run.assert_not_called()

    def test_legacy_models_and_invalid_options_fail_before_execution(self):
        for options in ({"model": "opus"}, {"model": "sonnet"}, {"model": "haiku"},
                        {"output_format": "stream-json"}, {"timeout_seconds": 0},
                        {"max_turns": -1}):
            with self.subTest(options=options):
                result = codex_llm.ask("test", **options)
                self.assertFalse(result["success"])
                self.assertTrue(result["error"])
        self.run.assert_not_called()

    def test_no_cli_does_not_try_npx_or_download(self):
        self.which.return_value = None
        self.assertFalse(codex_llm.is_available())
        result = codex_llm.ask("test")
        self.assertFalse(result["success"])
        self.assertTrue(result["error"])
        self.assertTrue(all(call.args == ("codex",) for call in self.which.call_args_list))
        self.run.assert_not_called()

    def test_authentication_checked_with_cli_status(self):
        self.assertTrue(codex_llm.is_available())
        cmd, kwargs = self.calls[-1]
        self.assertEqual(cmd[0], "/mock/bin/codex")
        self.assertIn("login", cmd)
        self.assertIn("status", cmd)
        self.assertGreater(kwargs["timeout"], 0)
        self.login_returncode = 1
        self.assertFalse(codex_llm.is_available())

    def test_authentication_check_errors_are_unavailable(self):
        for error in (OSError("missing"), subprocess.TimeoutExpired("codex", 10)):
            with self.subTest(error=type(error).__name__):
                self.run.side_effect = error
                self.assertFalse(codex_llm.is_available())

    def test_final_message_is_authoritative_and_prompt_uses_stdin(self):
        prompt = "한국어 {json} $(not-a-command) 'quoted'\nC:\\Windows\\Temp"
        result = codex_llm.ask(prompt, system_prompt="Keep the ECS fields.", timeout_seconds=17)
        self.assertTrue(result["success"])
        self.assertEqual(result["response"], "final answer")
        self.assertEqual(set(result), {"success", "response", "model", "error"})
        cmd, kwargs = self.exec_call()
        self.assertEqual(cmd[0], "/mock/bin/codex")
        self.assertIn("exec", cmd)
        self.assertEqual(cmd[-1], "-")
        self.assertNotIn(prompt, cmd)
        self.assertIn(prompt, kwargs["input"])
        self.assertEqual(kwargs["timeout"], 17)
        self.assertFalse(kwargs.get("shell", False))
        overrides = self.config_overrides(cmd)
        self.assertIn("Keep the ECS fields.", overrides["developer_instructions"])
        self.assertNotIn("--max-turns", cmd)
        self.assertNotIn("--output-format", cmd)

    def test_reasoning_is_isolated_ephemeral_and_blocks_execution_and_integrations(self):
        for tools in (None, []):
            with self.subTest(tools=tools):
                self.assertTrue(codex_llm.ask("analyze", allowed_tools=tools)["success"])
                cmd, kwargs = self.exec_call()
                self.assertIn("--ephemeral", cmd)
                self.assertIn("--strict-config", cmd)
                self.assertIn("--ignore-user-config", cmd)
                self.assertIn("--skip-git-repo-check", cmd)
                self.assertEqual(cmd[cmd.index("--sandbox") + 1], "read-only")
                self.assertEqual(cmd[cmd.index("--color") + 1], "never")
                self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", cmd)
                cwd = Path(kwargs["cwd"])
                self.assertFalse(cwd.is_relative_to(REPO_ROOT))
                self.assertFalse(cwd.exists(), "Temporary invocation directory must be cleaned up")
                settings = self.config_overrides(cmd)
                self.assertEqual(settings["approval_policy"], "never")
                self.assertEqual(settings["web_search"], "disabled")
                self.assertEqual(settings["project_doc_max_bytes"], 0)
                self.assertEqual(settings["mcp_servers"], {})
                self.assertIs(settings["features.skip_host_skill_discovery"], True)
                self.assertNotIn("tools.view_image", settings)
                self.assertIs(settings["features.view_image"], False)
                for feature in ("shell_tool", "unified_exec", "apps", "plugins", "multi_agent",
                                "hooks", "memories", "chronicle", "browser_use", "computer_use",
                                "image_generation", "code_mode", "code_mode_host", "goals",
                                "workspace_dependencies", "skill_search"):
                    self.assertIs(settings[f"features.{feature}"], False, feature)

    def test_explicit_model_overrides_environment_and_agent_config(self):
        with patch.dict(os.environ, {"CODEX_MODEL": "environment-test-model"}):
            result = codex_llm.ask("test", model="explicit-test-model")
        self.assertEqual(result["model"], "explicit-test-model")
        cmd, _ = self.exec_call()
        self.assertEqual(cmd[cmd.index("--model") + 1], "explicit-test-model")

    def test_environment_model_overrides_agent_config(self):
        with patch.dict(os.environ, {"CODEX_MODEL": "environment-test-model"}):
            result = codex_llm.ask("test", agent_name="author")
        self.assertEqual(result["model"], "environment-test-model")

    def test_legacy_agent_aliases_use_current_agent_model(self):
        for name, model in (("blue-team", "author-test-model"), ("quality", "tuning-test-model")):
            with self.subTest(agent=name):
                result = codex_llm.ask("test", agent_name=name)
                self.assertEqual(result["model"], model)
                cmd, _ = self.exec_call()
                self.assertEqual(cmd[cmd.index("--model") + 1], model)

    def test_current_agent_config_wins_over_conflicting_legacy_alias(self):
        self.config.write_text(yaml.safe_dump({"agents": {
            "author": {"model": "author-current"},
            "blue-team": {"model": "author-legacy"},
            "tuning": {"model": "tuning-current"},
            "quality": {"model": "tuning-legacy"},
        }}), encoding="utf-8")
        for name, expected in (("blue-team", "author-current"), ("quality", "tuning-current")):
            with self.subTest(agent=name):
                result = codex_llm.ask("test", agent_name=name)
                self.assertTrue(result["success"])
                self.assertEqual(result["model"], expected)
                cmd, _ = self.exec_call()
                self.assertEqual(cmd[cmd.index("--model") + 1], expected)

    def test_null_missing_and_unknown_models_use_cli_default(self):
        for name in ("intel", "unknown"):
            with self.subTest(agent=name):
                self.assertTrue(codex_llm.ask("test", agent_name=name)["success"])
                self.assertNotIn("--model", self.exec_call()[0])
        self.config.unlink()
        self.assertTrue(codex_llm.ask("test")["success"])
        self.assertNotIn("--model", self.exec_call()[0])

    def test_nonzero_exit_remains_failure_even_with_partial_answer(self):
        self.returncode, self.stderr = 9, "provider failed"
        result = codex_llm.ask("test")
        self.assertFalse(result["success"])
        self.assertIn("9", result["error"])
        self.assertEqual(result["response"], "final answer")

    def test_long_cli_banner_does_not_hide_trailing_failure_diagnostic(self):
        self.returncode = 1
        self.stderr = "CLI banner and session metadata " * 40 + "\nProvider rejected request: useful trailing failure"
        result = codex_llm.ask("test")
        self.assertFalse(result["success"])
        self.assertIn("Provider rejected request: useful trailing failure", result["error"])

    def test_stdout_events_cannot_turn_missing_or_empty_final_message_into_success(self):
        for final_message in (None, "", " \n "):
            with self.subTest(final_message=final_message):
                self.output = final_message
                result = codex_llm.ask("test")
                self.assertFalse(result["success"])
                self.assertTrue(result["error"])
                self.assertNotIn("thread.started", result["response"])

    def test_timeout_and_execution_error_fail_closed(self):
        for error in (subprocess.TimeoutExpired("codex", 17), OSError("execution unavailable")):
            with self.subTest(error=type(error).__name__):
                self.failure = error
                result = codex_llm.ask("test", timeout_seconds=17)
                self.assertFalse(result["success"])
                self.assertTrue(result["error"])

    def test_json_content_is_preserved_including_result_field(self):
        for data in ({"result": "ordinary application field"}, [{"id": "T1059"}]):
            with self.subTest(data=data):
                self.output = json.dumps(data)
                result = codex_llm.ask("test", output_format="json")
                self.assertTrue(result["success"])
                self.assertEqual(json.loads(result["response"]), data)
                self.assertNotIn("--output-format", self.exec_call()[0])

    def test_malformed_json_is_not_success(self):
        for text in ("{broken", '{"ok":true}\ntrailing text', '```json\n{"ok":true}\n```'):
            with self.subTest(text=text):
                self.output = text
                result = codex_llm.ask("test", output_format="json")
                self.assertFalse(result["success"])
                self.assertTrue(result["error"])

    def test_unsupported_tools_do_not_execute(self):
        for tools in (["Bash"], ["Edit"], ["Bash(curl:*)", "Read"]):
            with self.subTest(tools=tools):
                result = codex_llm.ask("test", allowed_tools=tools)
                self.assertFalse(result["success"])
                self.assertTrue(result["error"])
        self.assertFalse(any("exec" in cmd for cmd, _ in self.calls))

    def test_native_web_and_legacy_web_alias_only_enable_native_search(self):
        for tools in (["WebSearch"], ["Bash(curl:*)"]):
            with self.subTest(tools=tools):
                result = codex_llm.ask("research", allowed_tools=tools)
                self.assertTrue(result["success"])
                settings = self.config_overrides(self.exec_call()[0])
                self.assertEqual(settings["web_search"], "live")
                self.assertIs(settings["features.shell_tool"], False)
                self.assertIs(settings["features.unified_exec"], False)

    def test_sigma_wrapper_preserves_yaml_contract_and_refinement_context(self):
        self.output = "```yaml\ntitle: Example\ndetection:\n  condition: selection\n```"
        result = codex_llm.ask_for_sigma_rule(
            "T1059.001", "PowerShell", [{"process": {"name": "powershell.exe"}}],
            [{"process": {"name": "cmd.exe"}}], existing_rule_yaml="title: Existing",
            lessons=["Keep process.name as ECS"])
        self.assertTrue(result["success"])
        self.assertEqual(result["sigma_yaml"], "title: Example\ndetection:\n  condition: selection")
        _, kwargs = self.exec_call()
        self.assertIn("title: Existing", kwargs["input"])
        self.assertIn("Keep process.name as ECS", kwargs["input"])
        self.assertIn("powershell.exe", kwargs["input"])

    def test_sigma_wrapper_preserves_error_contract(self):
        self.returncode = 1
        result = codex_llm.ask_for_sigma_rule("T1059", "Execution", [], [])
        self.assertFalse(result["success"])
        self.assertEqual(result["sigma_yaml"], "")
        self.assertTrue(result["error"])

    def test_analysis_wrapper_preserves_context_and_agent_selection(self):
        result = codex_llm.ask_for_analysis("What should change?", "F1 = 0.8", "quality")
        self.assertTrue(result["success"])
        self.assertEqual(result["model"], "tuning-test-model")
        _, kwargs = self.exec_call()
        self.assertIn("F1 = 0.8", kwargs["input"])
        self.assertIn("What should change?", kwargs["input"])

    def test_web_wrapper_uses_native_search_and_timeout(self):
        self.assertTrue(codex_llm.ask_with_web_search("Research", timeout_seconds=31)["success"])
        cmd, kwargs = self.exec_call()
        self.assertEqual(self.config_overrides(cmd)["web_search"], "live")
        self.assertEqual(kwargs["timeout"], 31)

    def test_legacy_import_remains_available_without_claude_execution(self):
        legacy = importlib.import_module("orchestration.claude_llm")
        for name in ("ask", "is_available", "ask_for_sigma_rule", "ask_for_analysis",
                     "ask_with_web_search", "_load_agent_config"):
            self.assertIs(getattr(legacy, name), getattr(codex_llm, name))
        self.assertTrue(legacy.ask("legacy caller")["success"])
        self.assertEqual(self.exec_call()[0][0], "/mock/bin/codex")


if __name__ == "__main__":
    unittest.main()
