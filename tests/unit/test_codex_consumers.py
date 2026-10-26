"""Consumer regressions for CLI migration, with model/network calls disabled."""

from contextlib import redirect_stdout
import importlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "autonomous"))
from orchestration import budget, codex_llm  # noqa: E402
from orchestration.agents import (  # noqa: E402
    author_agent, intel_agent, red_team_agent, security_agent, validation_agent,
)


class ConsumerRegressionTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(redirect_stdout(io.StringIO()))
        self.enterContext(patch("subprocess.run", side_effect=AssertionError("Unexpected subprocess")))
        self.enterContext(patch("urllib.request.urlopen", side_effect=AssertionError("Unexpected network")))
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.available = self.enterContext(patch.object(codex_llm, "is_available", return_value=True))
        self.ask = self.enterContext(patch.object(codex_llm, "ask"))
        self.scenario = {
            "log_sources_used": ["sysmon_1"],
            "events": {
                "attack_sequence": [{"event": {"code": "1"}, "process": {"name": "powershell.exe"}}],
                "benign_similar": [{"event": {"code": "1"}, "process": {"name": "notepad.exe"}}],
            },
            "expected_detection": {"key_fields": ["process.name"]},
        }
        self.request = {"technique_id": "T1059.001", "title": "Suspicious PowerShell",
                        "mitre_tactic": "execution", "scenario_file": "scenario.json"}

    def test_all_seven_consumers_and_legacy_blue_team_import(self):
        for name in ("author", "validation", "red_team", "intel", "quality", "tuning", "security"):
            with self.subTest(agent=name):
                module = importlib.import_module(f"orchestration.agents.{name}_agent")
                self.assertIs(module.codex_llm, codex_llm)
                self.assertTrue(callable(module.run))
        legacy = importlib.import_module("orchestration.agents.blue_team_agent")
        self.assertIs(legacy.validate_detection, validation_agent.validate_detection)
        self.assertIs(legacy.generate_sigma_rule, author_agent.generate_sigma_rule)
        self.ask.assert_not_called()

    def test_red_team_dynamic_json_success_preserves_scenario_metadata(self):
        data = {"attack_events": self.scenario["events"]["attack_sequence"],
                "benign_events": self.scenario["events"]["benign_similar"],
                "key_fields": ["process.name"], "log_sources_used": ["sysmon_1"],
                "notes": "Behavioral process test", "platforms": ["Windows"]}
        self.ask.return_value = {"success": True, "response": "```json\n" + json.dumps(data) + "\n```"}
        attacks, benign, metadata = red_team_agent.generate_scenario_with_codex(
            "T1059.001", self.request)
        self.assertEqual(attacks, data["attack_events"])
        self.assertEqual(benign, data["benign_events"])
        self.assertEqual(metadata["key_fields"], ["process.name"])
        self.assertEqual(metadata["generated_by"], "codex")
        self.assertEqual(self.ask.call_args.kwargs["agent_name"], "red-team")
        self.assertEqual(self.ask.call_args.kwargs["allowed_tools"], [])

    def test_red_team_failure_and_malformed_output_do_not_create_scenarios(self):
        for response in ({"success": False, "error": "CLI unavailable"},
                         {"success": True, "response": "invalid json"},
                         {"success": True, "response": '{"attack_events": []}'}):
            with self.subTest(response=response):
                self.ask.return_value = response
                self.assertIsNone(red_team_agent.generate_scenario_with_codex("T1059.001", self.request))
        self.available.return_value = False
        self.ask.reset_mock()
        self.assertIsNone(red_team_agent.generate_scenario_with_codex("T1059.001", self.request))
        self.ask.assert_not_called()

    def test_hardcoded_scenario_still_runs_without_cli(self):
        self.available.return_value = False
        scenario = red_team_agent.build_scenario("T1055.001", {"title": "Process injection"})
        self.assertTrue(scenario["events"]["attack_sequence"])
        self.assertTrue(scenario["events"]["benign_similar"])
        self.assertTrue(scenario["expected_detection"]["key_fields"])
        self.ask.assert_not_called()

    def test_security_review_preserves_finding_shape(self):
        self.ask.return_value = {"success": True, "response": json.dumps([
            {"file": "detections/execution/test.yml", "severity": "WARN", "description": "Broad condition"}
        ])}
        findings = security_agent.codex_quality_review([
            {"file": "detections/execution/test.yml", "content": "title: Test"}])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "WARN")
        self.assertEqual(findings[0]["finding"], "Broad condition")
        self.assertEqual(findings[0]["category"], "CodexQualityReview")
        self.assertEqual(findings[0]["line"], 0)
        self.assertEqual(self.ask.call_args.kwargs["agent_name"], "security")

    def test_security_review_failure_does_not_break_deterministic_review(self):
        rules = [{"file": "test.yml", "content": "title: Test"}]
        for response in ({"success": False, "error": "CLI failed"},
                         {"success": True, "response": "not json"},
                         {"success": True, "response": "{}"}):
            with self.subTest(response=response):
                self.ask.return_value = response
                self.assertEqual(security_agent.codex_quality_review(rules), [])
        self.available.return_value = False
        self.ask.reset_mock()
        self.assertEqual(security_agent.codex_quality_review(rules), [])
        self.ask.assert_not_called()
        self.assertEqual(security_agent.determine_verdict([
            {"severity": "CRITICAL", "finding": "deterministic finding"}
        ])[0], "BLOCK")

    def test_legacy_consumer_callable_names_remain_callable(self):
        self.available.return_value = False
        self.assertIsNone(red_team_agent.generate_scenario_with_claude("T1059.001", self.request))
        self.assertEqual(security_agent.claude_quality_review([]), [])
        self.ask.assert_not_called()

    def author_and_validate(self, llm_result, available=True):
        self.available.return_value = available
        self.enterContext(patch.object(author_agent, "REPO_ROOT", self.root))
        self.enterContext(patch.object(author_agent, "DETECTIONS_DIR", self.root / "detections"))
        self.enterContext(patch.object(author_agent, "TESTS_DIR", self.root / "tests"))
        self.enterContext(patch.object(validation_agent, "REPO_ROOT", self.root))
        self.enterContext(patch.object(author_agent, "load_scenario", return_value=self.scenario))
        self.enterContext(patch.object(author_agent, "transpile_sigma", return_value=("lucene fixture", "spl fixture")))
        self.enterContext(patch.object(author_agent.learnings, "get_relevant_lessons", return_value=[]))
        sigma = self.enterContext(patch.object(codex_llm, "ask_for_sigma_rule", return_value=llm_result))
        state = MagicMock()
        result = author_agent.author_detection(self.request, state, "offline-test-run")
        self.assertEqual(result["status"], "authored")
        self.assertTrue((self.root / result["sigma_rule"]).is_file())
        self.assertEqual((self.root / result["compiled_lucene"]).read_text(), "lucene fixture")
        self.assertEqual((self.root / result["compiled_spl"]).read_text(), "spl fixture")
        self.assertTrue((self.root / "tests/true_positives/t1059_001_tp.json").is_file())
        self.assertTrue((self.root / "tests/true_negatives/t1059_001_tn.json").is_file())
        state.transition.assert_called_once()
        self.assertEqual(state.transition.call_args.args[:2], ("T1059.001", "AUTHORED"))
        metrics = validation_agent.validate_detection(result["sigma_rule"], self.scenario)
        self.assertEqual({key: metrics[key] for key in ("tp", "fp", "fn", "tn")},
                         {"tp": 1, "fp": 0, "fn": 0, "tn": 1})
        self.assertEqual(metrics["f1_score"], 1.0)
        self.assertEqual(validation_agent.assess_quality(metrics), "auto_deploy")
        return result, sigma

    def test_author_accepts_codex_sigma_and_preserves_artifacts_validation_transition(self):
        rule = "title: Codex fixture\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    process.name: powershell.exe\n  condition: selection\n"
        result, sigma = self.author_and_validate({"success": True, "sigma_yaml": rule})
        self.assertEqual((self.root / result["sigma_rule"]).read_text(), rule)
        sigma.assert_called_once()
        self.assertEqual(sigma.call_args.kwargs["attack_events"], self.scenario["events"]["attack_sequence"])

    def test_author_cli_unavailable_preserves_deterministic_pipeline(self):
        _, sigma = self.author_and_validate({"success": False, "error": "not installed"}, available=False)
        sigma.assert_not_called()

    def test_author_cli_failure_preserves_deterministic_pipeline(self):
        _, sigma = self.author_and_validate({"success": False, "error": "timeout"})
        sigma.assert_called_once()

    def test_author_invalid_sigma_preserves_deterministic_pipeline(self):
        self.author_and_validate({"success": True, "sigma_yaml": "plain model prose"})

    def test_intel_link_selection_and_extraction_keep_python_fetch_path(self):
        index_url = "https://example.test/index"
        report_url = "https://example.test/report"
        index = {"url": index_url, "text": "Index", "links": [{"text": "Threat report", "href": report_url}]}
        page = {"url": report_url, "text": "PowerShell execution observed", "links": []}
        extracted = {"title": "Threat report", "techniques": [{"id": "T1059.001", "name": "PowerShell"}]}
        self.enterContext(patch.object(intel_agent, "INTEL_INDEX_URLS", [index_url]))
        fetch = self.enterContext(patch.object(intel_agent, "_fetch_page", side_effect=[index, page]))
        analysis = self.enterContext(patch.object(codex_llm, "ask_for_analysis", side_effect=[
            {"success": True, "response": json.dumps([{"url": report_url, "title": "Threat report"}])},
            {"success": True, "response": json.dumps(extracted)},
        ]))
        reports = intel_agent.search_web_for_intel(["PowerShell"], set(), max_reports=1)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]["source"], report_url)
        self.assertEqual(reports[0]["techniques"][0]["id"], "T1059.001")
        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(analysis.call_count, 2)
        self.assertTrue(all(call.kwargs["agent_name"] == "intel" for call in analysis.call_args_list))

    def test_validation_extracts_fenced_yaml_and_rejects_plain_prose(self):
        rule = "title: Test\nlogsource: {}\ndetection:\n  selection:\n    process.name: powershell.exe\n  condition: selection"
        self.assertEqual(validation_agent.extract_yaml_from_response("Explanation\n```yaml\n" + rule + "\n```"), rule)
        self.enterContext(patch.object(validation_agent, "REPO_ROOT", self.root))
        (self.root / "invalid.yml").write_text("Model prose instead of a rule", encoding="utf-8")
        metrics = validation_agent.validate_detection("invalid.yml", self.scenario)
        self.assertEqual(metrics["f1_score"], 0)
        self.assertEqual(metrics["fn"], 1)
        self.assertEqual(validation_agent.assess_quality(metrics), "needs_rework")


class BudgetModelRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "config.yml"
        self.enterContext(patch.object(budget, "CONFIG_PATH", self.config))
        self.enterContext(patch.object(budget, "BUDGET_LOG", self.root / "budget-log.jsonl"))
        self.enterContext(patch.dict(os.environ, {}, clear=True))

    def test_missing_config_has_neutral_estimate_and_can_log(self):
        self.assertEqual(budget._get_model_multiplier("author"), 1.0)
        entry = budget.log_run("author", duration_seconds=2, items_processed=1)
        self.assertGreater(entry["estimated_tokens"], 0)
        self.assertEqual(budget.get_daily_usage()["total_tokens"], entry["estimated_tokens"])

    def test_current_agent_config_wins_over_conflicting_legacy_alias(self):
        self.config.write_text(yaml.safe_dump({
            "agents": {
                "author": {"model": "current"}, "blue-team": {"model": "legacy"},
                "tuning": {"model": "current"}, "quality": {"model": "legacy"},
            },
            "budget": {"models": {"current": 2.0, "legacy": 0.5}},
        }), encoding="utf-8")
        self.assertEqual(budget._get_model_multiplier("blue-team"), 2.0)
        self.assertEqual(budget._get_model_multiplier("quality"), 2.0)

    def test_aliases_environment_and_unknown_model_multiplier(self):
        self.config.write_text(yaml.safe_dump({
            "agents": {"author": {"model": "author-test"}, "tuning": {"model": "tuning-test"}},
            "budget": {"default_model_multiplier": 1.25,
                       "models": {"author-test": 2.0, "tuning-test": 0.5, "env-test": 3.0}},
        }), encoding="utf-8")
        self.assertEqual(budget._get_model_multiplier("blue-team"), 2.0)
        self.assertEqual(budget._get_model_multiplier("quality"), 0.5)
        self.assertEqual(budget._get_model_multiplier("unconfigured"), 1.25)
        with patch.dict(os.environ, {"CODEX_MODEL": "env-test"}):
            self.assertEqual(budget._get_model_multiplier("blue-team"), 3.0)
        with patch.dict(os.environ, {"CODEX_MODEL": "unknown-model"}):
            self.assertEqual(budget._get_model_multiplier("quality"), 1.25)


if __name__ == "__main__":
    unittest.main()
