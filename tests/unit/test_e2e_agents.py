"""Offline contracts for live-agent E2E; all reasoning and SIEM I/O is mocked."""
import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("e2e_agents", ROOT / "pipeline/e2e_agents.py")
e2e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e2e)

RULE = """title: Generated shell behavioral smoke
id: 31b12493-e88b-4a55-a182-314d7e36859e
status: experimental
description: Synthetic shell behavior
references: [https://attack.mitre.org/techniques/T1059/003/]
author: Codex
date: '2026-10-26'
logsource:
  category: process_creation
  product: windows
tags: [attack.execution, attack.t1059.003]
detection:
  selection:
    process.name: cmd.exe
    process.command_line|contains: ' & '
  condition: selection
falsepositives: [Administrative command chains]
level: medium
"""


def event(positive):
    return {"event": {"code": "1", "category": "process"},
            "process": {"name": "cmd.exe", "executable": "C:\\Windows\\System32\\cmd.exe",
                        "command_line": "cmd.exe /c whoami & hostname" if positive else "cmd.exe /c ipconfig",
                        "parent": {"name": "sample.exe", "executable": "C:\\Temp\\sample.exe"}},
            "_simulation": {"expected_alert": positive, "technique": "T1059.003",
                            "type": "attack" if positive else "benign_similar",
                            "description": "Chained discovery" if positive else "Routine diagnostics"}}


def scenario():
    return {"attack_events": [event(True), event(True)], "benign_events": [event(False)],
            "key_fields": ["process.name", "process.command_line"], "log_sources_used": ["sysmon_1"]}


def response(text, success=True, error=None):
    return {"success": success, "response": text, "model": "default", "error": error}


class LiveAgentSmokeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        for name in ("autonomous/detection-requests/t1059_003.yml", "detections/execution/t1059_003.yml",
                     "tests/e2e/cases/t1059_003.json", "tests/true_positives/t1059_003_tp.json",
                     "tests/true_negatives/t1059_003_tn.json"):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        self.enterContext(patch.object(e2e, "REPO_ROOT", self.root))
        self.enterContext(patch.object(e2e, "HOLDOUT", self.root / "tests/e2e/cases/t1059_003.json"))
        self.login = self.enterContext(patch.object(e2e.codex_llm, "is_available", return_value=True))
        self.enterContext(patch.object(e2e, "codex_version", return_value="codex-cli 0.163.0"))
        self.ask = self.enterContext(patch.object(e2e.codex_llm, "ask", side_effect=[
            response(json.dumps(scenario())), response(RULE)]))
        self.elastic = self.enterContext(patch.object(e2e, "run_elastic", side_effect=[
            {"status": "PASS"}, {"status": "PASS", "process_exit_code": 0,
                                 "stages": {name: {"status": "PASS"} for name in e2e.ELASTIC_STAGES}}]))
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.args = argparse.Namespace(output_dir=self.root / "artifacts/e2e/unit-test", llm_timeout=None,
                                       es_url="http://127.0.0.1:19200", kibana_url="http://127.0.0.1:15601",
                                       timeout=240, poll_interval=5, allow_remote=False)

    def run_smoke(self):
        return e2e.run(self.args)[0]

    def test_real_reasoning_entry_points_build_generated_and_independent_holdout_cases(self):
        report = self.run_smoke()
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(self.ask.call_count, 2)
        self.assertEqual([c["timeout_seconds"] for c in report["calls"]], [60, 90])
        self.assertTrue(all(c["model_selection"] == "default" and len(c["response_sha256"]) == 64 for c in report["calls"]))
        manifest = json.loads((self.args.output_dir / "llm/case.json").read_text())
        self.assertEqual(len(manifest["cases"]), 8)
        self.assertEqual([c["expected_alert"] for c in manifest["cases"][-5:]], [False, True, True, False, False])
        self.assertTrue(all(c["case_id"].startswith("holdout_") for c in manifest["cases"][-5:]))
        self.assertIn("artifacts/e2e/unit-test/llm/generated_sigma.yml", manifest["sigma_rule"])
        prompts = " ".join(call.kwargs["prompt"] for call in self.ask.call_args_list)
        self.assertNotIn("185.220.101.47", prompts)
        self.assertNotIn("HelpDeskTool", prompts)
        self.assertNotIn("Current rule:", prompts)
        self.assertIs(e2e.codex_llm.ask, self.ask, "Original adapter must be restored")

    def test_scenario_failure_does_not_fallback_or_request_author(self):
        self.ask.side_effect = [response("partial", False, "Codex CLI timed out after 60s")]
        report = self.run_smoke()
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["failure_boundary"], "scenario_generation")
        self.assertEqual(report["calls"][0]["failure_category"], "timeout")
        self.assertEqual(self.ask.call_count, 1)
        self.assertEqual(self.elastic.call_count, 1)

    def test_empty_response_is_failure_even_if_adapter_claims_success(self):
        self.ask.side_effect = [response("  ")]
        report = self.run_smoke()
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(self.ask.call_count, 1)

    def test_invalid_json_is_not_repaired_or_replaced(self):
        self.ask.side_effect = [response("{not json}")]
        self.assertEqual(self.run_smoke()["status"], "FAIL")
        self.assertEqual(self.ask.call_count, 1)

    def test_context_event_in_attack_group_is_rejected(self):
        data = scenario()
        data["attack_events"][0]["process"]["name"] = "update_helper.exe"
        self.ask.side_effect = [response(json.dumps(data))]
        report = self.run_smoke()
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("Context events", report["stages"]["scenario_generation"]["error"])

    def test_missing_or_string_expectation_cannot_pass(self):
        for label in ({}, {"expected_alert": "true"}):
            data = scenario()
            data["attack_events"][0]["_simulation"] = label
            with self.subTest(label=label), self.assertRaises(e2e.AgentE2EFailure):
                e2e.validate_scenario((data["attack_events"], data["benign_events"], {"generated_by": "codex"}))

    def test_deterministic_scenario_and_empty_benign_cases_are_rejected(self):
        data = scenario()
        for result in (None, (data["attack_events"], data["benign_events"], {"generated_by": "fallback"}),
                       (data["attack_events"], [], {"generated_by": "codex"})):
            with self.subTest(result=result), self.assertRaises(e2e.AgentE2EFailure):
                e2e.validate_scenario(result)

    def test_malformed_or_metadata_based_sigma_cannot_pass(self):
        old = self.root / "detections/execution/t1059_003.yml"
        for text in ("{", "- list", "detection: {}", RULE.replace("process.name: cmd.exe", "_simulation.expected_alert: true"),
                     old.read_text()):
            with self.subTest(text=text[:50]), self.assertRaises(e2e.AgentE2EFailure):
                e2e.validate_rule({"success": True, "sigma_yaml": text}, old)

    def test_author_failure_cannot_use_existing_or_deterministic_rule(self):
        self.ask.side_effect = [response(json.dumps(scenario())), response("", False, "failure secret=must-not-be-logged")]
        report = self.run_smoke()
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["failure_boundary"], "sigma_generation")
        self.assertNotIn("must-not-be-logged", (self.args.output_dir / "report.json").read_text())
        self.assertFalse((self.args.output_dir / "llm/generated_sigma.yml").exists())

    def test_elastic_failure_or_cleanup_failure_cannot_be_pass(self):
        self.elastic.side_effect = [{"status": "PASS"}, {"status": "PASS", "process_exit_code": 0,
                                                       "stages": {"cleanup": {"status": "FAIL"}}}]
        report = self.run_smoke()
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["failure_boundary"], "elastic_e2e")

    def test_nonzero_elastic_exit_overrides_pass_report(self):
        self.elastic.side_effect = [{"status": "PASS"}, {"status": "PASS", "process_exit_code": 1,
                                                       "stages": {"cleanup": {"status": "PASS"}}}]
        self.assertEqual(self.run_smoke()["status"], "FAIL")

    def test_missing_elastic_stage_cannot_pass_even_when_overall_and_cleanup_pass(self):
        stages = {name: {"status": "PASS"} for name in e2e.ELASTIC_STAGES}
        del stages["scheduled_alerts"]
        self.elastic.side_effect = [{"status": "PASS"}, {"status": "PASS", "process_exit_code": 0, "stages": stages}]
        self.assertEqual(self.run_smoke()["status"], "FAIL")

    def test_keyboard_interrupt_preserves_failure_and_unrun_stage_evidence(self):
        self.ask.side_effect = KeyboardInterrupt()
        report = self.run_smoke()
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["calls"][0]["status"], "FAIL")
        self.assertEqual(report["stages"]["sigma_generation"]["status"], "NOT_RUN")
        self.assertEqual(report["stages"]["elastic_e2e"]["status"], "NOT_RUN")
        self.assertIs(e2e.codex_llm.ask, self.ask)
        self.assertTrue((self.args.output_dir / "report.json").is_file())

    def test_timeout_override_is_recorded_and_request_budget_is_two(self):
        self.args.llm_timeout = 120
        report = self.run_smoke()
        self.assertEqual([call["timeout_seconds"] for call in report["calls"]], [120, 120])
        self.assertEqual(self.ask.call_count, 2)
        self.assertEqual(report["automatic_retries"], 0)

    def test_preflight_is_read_only_and_does_not_request_reasoning(self):
        e2e.preflight(self.args)
        self.ask.assert_not_called()
        self.assertFalse(self.args.output_dir.exists())

    def test_login_failure_stops_before_reasoning_or_siem(self):
        self.login.return_value = False
        report = self.run_smoke()
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["failure_boundary"], "preflight")
        self.ask.assert_not_called()
        self.elastic.assert_not_called()

    def test_evidence_is_never_overwritten(self):
        self.run_smoke()
        original = (self.args.output_dir / "report.json").read_bytes()
        with self.assertRaises(FileExistsError):
            self.run_smoke()
        self.assertEqual((self.args.output_dir / "report.json").read_bytes(), original)

    def test_existing_repository_file_cannot_be_output_directory(self):
        self.args.output_dir = self.root / "detections/execution"
        with self.assertRaises(e2e.AgentE2EFailure):
            self.run_smoke()
        self.ask.assert_not_called()

    def test_main_failure_exit_agrees_with_report(self):
        self.login.return_value = False
        with contextlib.redirect_stderr(io.StringIO()):
            code = e2e.main(["--output-dir", str(self.args.output_dir)])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads((self.args.output_dir / "report.json").read_text())["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
