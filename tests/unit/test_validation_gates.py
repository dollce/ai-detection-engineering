"""Fail-closed gate contracts. Fixtures and mocked SIEM responses stay offline."""

import contextlib
import io
import json
from pathlib import Path
import shutil
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "autonomous"))
from orchestration import regression, validation_audit
from orchestration.agents import validation_agent
from orchestration.validation_results import ValidationUnavailable, load_events, read_f1, require_no_errors


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


class EvidenceReaderTests(unittest.TestCase):
    def test_all_historical_score_shapes_are_read(self):
        for data in ({"f1": .8}, {"f1_score": .8}, {"metrics": {"f1_score": .8}},
                     {"results": {"f1": .8}}):
            with self.subTest(data=data):
                self.assertEqual(read_f1(data), .8)

    def test_missing_invalid_nonfinite_and_conflicting_scores_cannot_pass(self):
        for data in (None, [], {}, {"metrics": []}, {"f1": None}, {"f1": "1"},
                     {"f1": True}, {"f1": float("nan")}, {"f1": float("inf")},
                     {"f1": -1}, {"f1": 1.1}, {"f1": 1, "metrics": {"f1": .5}}):
            with self.subTest(data=data), self.assertRaises(ValidationUnavailable):
                read_f1(data)

    def test_errors_in_all_result_containers_override_high_score(self):
        for container in (None, "metrics", "results", "validation_details"):
            for error in ({"errors": ["bulk ingest failed"]}, {"errors": "invalid"},
                          {"error": "query failed"}, {"status": "NOT_RUN"}, {"status": "failed"},
                          {"status": "PENDING"}, {"status": "cancelled"}, {"status": None}):
                data = {"f1_score": 1, **error} if container is None else {"f1_score": 1, container: error}
                with self.subTest(container=container, error=error), self.assertRaises(ValidationUnavailable):
                    require_no_errors(data)

    def test_fixture_wrappers_unwrap_events_without_unwrapping_ecs_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.json"
            event = {"process": {"name": "attack.exe"}, "event": {"code": "1"}}
            for data in (event, [event], {"event": event}, {"attack_events": [event]},
                         {"benign_events": [event]}, {"events": [event]}):
                write_json(path, data)
                self.assertEqual(load_events(path), [event])
            for data in ([], {}, [None], [1], ["not an event"], {"description": "attack"}, {"events": []}):
                write_json(path, data)
                with self.subTest(data=data), self.assertRaises(ValidationUnavailable):
                    load_events(path)


class GateFixture(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for name, value in {
            "_PROJECT_ROOT": self.root, "_TP_DIR": self.root / "tests/true_positives",
            "_TN_DIR": self.root / "tests/true_negatives", "_RESULTS_DIR": self.root / "tests/results",
            "_REGRESSION_DIR": self.root / "tests/results/regression",
            "_DETECTIONS_DIR": self.root / "detections",
        }.items():
            self.enterContext(patch.object(regression, name, value))
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.key = "detections/execution/t1000.yml"
        self.rule = self.root / self.key
        self.rule.parent.mkdir(parents=True)
        self.rule.write_text(yaml.safe_dump({
            "title": "Gate fixture", "id": "test-id", "description": "gate contract",
            "logsource": {"category": "process_creation"},
            "detection": {"selection": {"process.name": "attack.exe"}, "condition": "selection"},
        }), encoding="utf-8")
        self.tp = self.root / "tests/true_positives/t1000_tp.json"
        self.tn = self.root / "tests/true_negatives/t1000_tn.json"
        self.attack = {"process": {"name": "attack.exe"}}
        self.benign = {"process": {"name": "benign.exe"}}
        write_json(self.tp, [self.attack])
        write_json(self.tn, [self.benign])
        self.base = self.root / "base"
        (self.base / self.key).parent.mkdir(parents=True)
        shutil.copyfile(self.rule, self.base / self.key)


class RegressionGateTests(GateFixture):
    def check(self, **kwargs):
        return regression.check_regression("T1000", self.key, **kwargs)

    def test_missing_baseline_is_not_run_not_perfect_score(self):
        result = self.check()
        self.assertEqual(result.status, "NOT_RUN")
        self.assertIsNone(result.previous_f1)
        self.assertEqual(result.current_f1, 1)

    def test_trusted_base_produces_pass_and_detects_rule_regression(self):
        self.assertEqual(self.check(baseline_root=self.base).status, "PASS")
        self.rule.write_text(self.rule.read_text().replace("attack.exe", "missing.exe"))
        self.assertEqual(self.check(baseline_root=self.base).status, "FAIL")

    def test_zero_score_fails_even_without_baseline(self):
        write_json(self.tp, [{"process": {"name": "unmatched.exe"}}])
        result = self.check()
        self.assertEqual(result.status, "FAIL")
        self.assertEqual(result.current_f1, 0)

    def test_missing_empty_and_malformed_fixture_block(self):
        original = self.tn.read_text()
        for content in (None, "[]", "{", "{}", '["bad"]'):
            if content is None:
                self.tn.unlink()
            else:
                self.tn.write_text(content)
            with self.subTest(content=content):
                self.assertEqual(self.check(baseline_root=self.base).status, "NOT_RUN")
            self.tn.write_text(original)

    def test_missing_rule_or_unusable_rule_blocks(self):
        for content in ("- not-a-rule", "detection: {}", "{", "detection:\n  condition: selection\n  selection:\n    EventID: 1"):
            self.rule.write_text(content)
            self.assertEqual(self.check(baseline_root=self.base).status, "NOT_RUN")
        self.rule.unlink()
        self.assertEqual(self.check(baseline_root=self.base).status, "NOT_RUN")

    def test_correlations_do_not_receive_single_event_pass(self):
        for kind in ("eql", "threshold"):
            data = yaml.safe_load(self.rule.read_text())
            data["detection_type"] = kind
            self.rule.write_text(yaml.safe_dump(data))
            self.assertEqual(self.check(baseline_root=self.base).status, "NOT_RUN")

    def test_variants_have_separate_results_and_snapshots(self):
        variant = self.root / "detections/execution/t1000_variant.yml"
        shutil.copyfile(self.rule, variant)
        write_json(self.tp.with_name("t1000_variant_tp.json"), [self.attack])
        write_json(self.tn.with_name("t1000_variant_tn.json"), [self.benign])
        key2 = variant.relative_to(self.root).as_posix()
        shutil.copyfile(variant, self.base / key2)
        results = regression.check_changed_files([self.key, key2, self.key], self.base)
        self.assertEqual(len(results), 2)
        self.assertEqual([r.status for r in results], ["PASS", "PASS"])
        regression.save_snapshot(results)
        snapshots = list(regression._REGRESSION_DIR.glob("*_regression.json"))
        self.assertEqual(len(snapshots), 2)
        for r in results:
            self.assertEqual(regression.load_local_baseline(r.technique_id, r.rule_path), 1)

    def test_failed_run_cannot_overwrite_successful_snapshot(self):
        passed = self.check(baseline_root=self.base)
        regression.save_snapshot([passed])
        write_json(self.tp, [self.benign])
        failed = self.check()
        self.assertEqual(failed.status, "FAIL")
        regression.save_snapshot([failed])
        self.assertEqual(regression.load_local_baseline("T1000", self.key), 1)

    def test_corrupt_failed_or_foreign_baseline_is_not_run(self):
        passed = self.check(baseline_root=self.base)
        regression.save_snapshot([passed])
        path = next(regression._REGRESSION_DIR.glob("*_regression.json"))
        original = json.loads(path.read_text())
        for changes in ({"status": "FAIL"}, {"local_f1": float("nan")},
                        {"method": "elasticsearch"}, {"rule_path": "different.yml"}):
            write_json(path, {**original, **changes})
            self.assertEqual(self.check().status, "NOT_RUN")
        path.write_text("{")
        self.assertEqual(self.check().status, "NOT_RUN")

    def test_new_rule_without_trusted_base_is_not_run(self):
        (self.base / self.key).unlink()
        self.assertEqual(self.check(baseline_root=self.base).status, "NOT_RUN")

    def test_fixture_lookup_never_borrows_a_sibling_variant(self):
        self.tn.unlink()
        write_json(self.tn.with_name("t1000_sibling_tn.json"), [self.benign])
        variant = self.rule.with_name("t1000_other.yml")
        with self.assertRaises(ValidationUnavailable):
            regression.find_test_file(variant, self.tn.parent, "tn")
        write_json(self.tn.with_name("t1000_second_tn.json"), [self.benign])
        with self.assertRaises(ValidationUnavailable):
            regression.find_test_file(self.rule, self.tn.parent, "tn")

    def test_cli_empty_input_and_missing_manifest_exit_nonzero_with_not_run_report(self):
        for args in (["--files", ""], ["--files-from", str(self.root / "missing")]):
            output = self.root / "output"
            rc = regression.main([*args, "--output-dir", str(output)])
            self.assertEqual(rc, 1)
            self.assertIn("Overall: NOT_RUN", (output / "regression-report.md").read_text())

    def test_cli_reports_pass_and_failure_without_overwriting_baseline(self):
        manifest = self.root / "changed"
        manifest.write_text(self.key + "\0")
        args = ["--files-from", str(manifest), "--baseline-root", str(self.base),
                "--output-dir", str(self.root / "output")]
        self.assertEqual(regression.main(args), 0)
        self.assertFalse(regression._REGRESSION_DIR.exists())
        write_json(self.tp, [self.benign])
        self.assertEqual(regression.main(args), 1)
        data = json.loads((self.root / "output/regression-report.json").read_text())
        self.assertEqual(data["status"], "FAIL")


class AuditGateTests(GateFixture):
    def setUp(self):
        super().setUp()
        self.request = self.root / "autonomous/detection-requests/t1000.yml"
        self.request.parent.mkdir(parents=True)
        self.request.write_text(yaml.safe_dump({"technique_id": "T1000", "sigma_rule": self.key}))
        self.result = self.root / "tests/results/t1000.json"
        write_json(self.result, {"metrics": {"f1_score": 1}})
        compiled = self.rule.parent / "compiled"
        compiled.mkdir()
        for ext in ("lucene", "spl"):
            (compiled / f"t1000.{ext}").write_text('process.name:"attack.exe"')
        self.pack = self.root / "detections/packs/example/pack.yml"
        self.pack.parent.mkdir(parents=True)
        self.pack.write_text(yaml.safe_dump({"name": "test", "version": "1", "quality": {"min_f1": .75},
                                            "rules": [{"path": self.key}]}))

    def audit(self, **kwargs):
        return validation_audit.audit(self.root, **kwargs)

    def test_complete_evidence_passes_and_nested_scores_are_counted(self):
        checks = self.audit()
        self.assertEqual(validation_audit.overall_status(checks), "PASS")
        output = self.root / "output"
        validation_audit.write_report(checks, output)
        report = json.loads((output / "validation-audit.json").read_text())
        self.assertEqual(report["stored_results_expected"], 1)
        self.assertEqual(report["stored_results_read"], 1)
        self.assertEqual(report["average_stored_f1"], 1)

    def test_low_score_fails_cli_instead_of_only_printing_warning(self):
        write_json(self.result, {"metrics": {"f1_score": .4}})
        rc = validation_audit.main(["--root", str(self.root), "--output-dir", str(self.root / "output")])
        self.assertEqual(rc, 1)
        self.assertEqual(validation_audit.overall_status(self.audit()), "FAIL")

    def test_missing_corrupt_or_scoreless_result_cannot_disappear(self):
        for content in (None, "{", "{}", '{"metrics":{"f1_score":NaN}}'):
            if content is None:
                self.result.unlink()
            else:
                self.result.write_text(content)
            checks = self.audit()
            self.assertEqual(len([c for c in checks if c.check == "stored_result"]), 1)
            self.assertEqual(validation_audit.overall_status(checks), "NOT_RUN")

    def test_ingest_errors_override_perfect_f1(self):
        write_json(self.result, {"metrics": {"f1_score": 1}, "validation_details": {"errors": ["bulk ingest failed"]}})
        self.assertEqual(validation_audit.overall_status(self.audit()), "FAIL")

    def test_required_fixtures_compiled_outputs_and_manifests_block_when_missing(self):
        for path in (self.tp, self.tn, self.rule.parent / "compiled/t1000.spl", self.pack, self.request):
            original = path.read_bytes()
            path.unlink()
            with self.subTest(path=path):
                self.assertNotEqual(validation_audit.overall_status(self.audit()), "PASS")
            path.write_bytes(original)

    def test_empty_catalog_unknown_filter_and_unexecuted_evasion_cannot_pass(self):
        for kwargs in ({"technique_filter": "T9999"}, {"include_evasion": True}):
            self.assertNotEqual(validation_audit.overall_status(self.audit(**kwargs)), "PASS")
        self.rule.unlink()
        self.assertNotEqual(validation_audit.overall_status(self.audit()), "PASS")

    def test_eql_artifacts_are_type_aware_and_require_siem_evidence(self):
        request = yaml.safe_load(self.request.read_text())
        request.update(rule_type="eql", compiled_artifact="detections/execution/compiled/t1000_elastic.json")
        self.request.write_text(yaml.safe_dump(request))
        write_json(self.root / request["compiled_artifact"], {"type": "eql", "query": "sequence [process where true]"})
        (self.rule.parent / "compiled/t1000.lucene").unlink()
        self.assertNotEqual(validation_audit.overall_status(self.audit()), "PASS")
        write_json(self.result, {"metrics": {"f1_score": 1}, "validation_method": "elasticsearch_eql"})
        self.assertEqual(validation_audit.overall_status(self.audit()), "PASS")


class AgentQualityGateTests(GateFixture):
    def setUp(self):
        super().setUp()
        self.metrics = {"tp": 1, "fp": 0, "fn": 0, "tn": 1, "precision": 1, "recall": 1,
                        "f1_score": 1, "fp_rate": 0, "tp_rate": 1, "total_attack": 1, "total_benign": 1}
        self.enterContext(patch.object(validation_agent, "REPO_ROOT", self.root))
        self.enterContext(patch.object(validation_agent, "load_scenario", return_value={
            "events": {"attack_sequence": [self.attack], "benign_similar": [self.benign]}}))
        self.enterContext(patch.object(validation_agent.codex_llm, "is_available", return_value=False))
        self.enterContext(patch.object(validation_agent.learnings, "record"))
        self.siem = self.enterContext(patch.object(validation_agent, "validate_against_elasticsearch", return_value=self.metrics))
        self.state = MagicMock()
        compiled = self.rule.with_suffix(".lucene")
        compiled.write_text('process.name:"attack.exe"')
        self.request = {"technique_id": "T1000", "sigma_rule": self.key, "scenario_file": "test.json",
                        "compiled_lucene": compiled.relative_to(self.root).as_posix()}

    def test_valid_metrics_preserve_existing_success_tiers(self):
        self.assertEqual(validation_agent.assess_quality(self.metrics), "auto_deploy")
        self.assertEqual(validation_agent.assess_quality({**self.metrics, "f1_score": .8}), "human_review")
        self.assertEqual(validation_agent.assess_quality({**self.metrics, "f1_score": .74}), "needs_rework")

    def test_missing_population_invalid_scores_and_errors_block_quality(self):
        for change in ({"total_benign": 0}, {"total_attack": 0}, {"total_benign": None},
                       {"f1_score": float("nan")}, {"f1_score": "1"}, {"fp_rate": None},
                       {"errors": ["query failed"]}):
            self.assertEqual(validation_agent.assess_quality({**self.metrics, **change}), "needs_rework")
        self.assertEqual(validation_agent.assess_quality(self.metrics, ["ingest failed"]), "needs_rework")

    def test_siem_ingest_failure_never_transitions_or_grants_eligibility(self):
        self.siem.return_value = {**self.metrics, "errors": ["bulk ingest failed"]}
        result = validation_agent.validate_single(self.request, self.state, "test", use_siem=True)
        self.assertEqual(result["status"], "needs_rework")
        self.state.transition.assert_not_called()
        self.assertFalse(any(c.kwargs.get("auto_deploy_eligible") for c in self.state.update.call_args_list))
        stored = json.loads((self.root / "tests/results/t1000.json").read_text())
        self.assertEqual(stored["validation_details"]["errors"], ["bulk ingest failed"])

    def test_missing_artifact_and_unsupported_siem_fallback_cannot_be_validated(self):
        for rule_type in ("sigma", "eql", "threshold", "unknown"):
            request = {**self.request, "compiled_lucene": "", "rule_type": rule_type}
            self.state.reset_mock()
            result = validation_agent.validate_single(request, self.state, "test", use_siem=False)
            self.assertEqual(result["status"], "needs_rework")
            self.state.transition.assert_not_called()

    def test_early_missing_input_revokes_old_eligibility(self):
        result = validation_agent.validate_single({**self.request, "scenario_file": ""}, self.state, "test")
        self.assertEqual(result["status"], "failed")
        self.state.update.assert_called_once_with("T1000", agent="validation", auto_deploy_eligible=False)

    def test_successful_siem_validation_still_transitions(self):
        result = validation_agent.validate_single(self.request, self.state, "test", use_siem=True)
        self.assertEqual(result["status"], "validated")
        self.assertTrue(result["auto_deploy_eligible"])
        self.state.transition.assert_called_once()

    def test_correlation_projection_preserves_scenario_counts_and_false_positive_rate(self):
        artifact = self.rule.with_suffix(".json")
        write_json(artifact, {"query": "test query", "threshold": {"field": ["host.name"], "value": 3}})
        request = {**self.request, "compiled_artifact": artifact.relative_to(self.root).as_posix()}
        response = {**self.metrics, "tp": 1, "fp": 1, "tn": 0, "precision": .5,
                    "f1_score": .6667, "fp_rate": 1.0, "scoring_unit": "scenario", "errors": []}
        for rule_type in ("eql", "threshold"):
            with self.subTest(rule_type=rule_type), \
                    patch.object(validation_agent, "load_scenario", return_value={"events": {
                        "attack_sequence": [self.attack] * 3, "benign_similar": [self.benign] * 2}}), \
                    patch.object(validation_agent, f"validate_{rule_type}_against_elasticsearch", return_value=response):
                result = validation_agent.validate_single({**request, "rule_type": rule_type}, self.state, "test", use_siem=True)
                self.assertEqual(result["status"], "needs_rework")
                self.assertEqual(result["metrics"]["total_attack"], 1)
                self.assertEqual(result["metrics"]["total_benign"], 1)
                self.assertEqual(result["metrics"]["scoring_unit"], "scenario")
                self.assertEqual(result["metrics"]["fp_rate"], 1.0)
                stored = json.loads((self.root / "tests/results/t1000.json").read_text())
                self.assertEqual(stored["attack_event_count"], 3)
                self.assertEqual(stored["benign_event_count"], 2)

    def test_requested_siem_check_cannot_pass_from_local_fallback(self):
        self.siem.return_value = None
        result = validation_agent.validate_single(self.request, self.state, "test", use_siem=True)
        self.assertEqual(result["status"], "needs_rework")
        self.state.transition.assert_not_called()

    def test_siem_error_status_and_malformed_errors_survive_metrics_projection(self):
        for changes in ({"status": "NOT_RUN"}, {"errors": None}, {"error": "query failed"}):
            self.siem.return_value = {**self.metrics, **changes}
            self.state.reset_mock()
            result = validation_agent.validate_single(self.request, self.state, "test", use_siem=True)
            self.assertEqual(result["status"], "needs_rework")
            self.state.transition.assert_not_called()

    def test_failed_refinement_compilation_cannot_reuse_the_old_query(self):
        self.siem.return_value = {**self.metrics, "f1_score": .5}
        original = self.rule.read_text()
        refined = original.replace("Gate fixture", "Refined fixture")
        with patch.object(validation_agent.codex_llm, "is_available", return_value=True), \
             patch.object(validation_agent.codex_llm, "_load_agent_config", return_value={}), \
             patch.object(validation_agent.codex_llm, "ask", return_value={"success": True, "response": refined}), \
             patch.object(validation_agent, "transpile_sigma", return_value=("", "")):
            result = validation_agent.validate_single(self.request, self.state, "test", use_siem=True)
        self.assertEqual(result["status"], "needs_rework")
        self.assertEqual(self.rule.read_text(), original)
        self.siem.assert_called_once()
        self.state.transition.assert_not_called()


class WorkflowGateTests(unittest.TestCase):
    """Execute the actual shell paths that used to hide Git/report failures."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.temp = Path(temp.name)
        workflow = yaml.safe_load((REPO_ROOT / ".github/workflows/regression-test.yml").read_text())
        self.steps = workflow["jobs"]["regression"]["steps"]
        self.env = {**os.environ, "RUNNER_TEMP": str(self.temp),
                    "GITHUB_OUTPUT": str(self.temp / "outputs"),
                    "GITHUB_STEP_SUMMARY": str(self.temp / "summary")}

    def run_step(self, name, cwd=REPO_ROOT, **env):
        script = next(s["run"] for s in self.steps if s.get("name") == name)
        return subprocess.run(["bash", "-e", "-o", "pipefail", "-c", script], cwd=cwd,
                              env={**self.env, **env}, capture_output=True, text=True)

    def test_diff_failure_cannot_be_reported_as_no_changed_rules(self):
        result = self.run_step("Find changed rule sources and prepare trusted base", BASE_SHA="invalid-ref-for-test")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.temp / "regression/regression-report.md").exists())

    def test_verified_empty_diff_is_explicitly_not_applicable(self):
        result = self.run_step("Find changed rule sources and prepare trusted base", BASE_SHA="HEAD")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = (self.temp / "regression/regression-report.md").read_text()
        self.assertIn("Overall: NOT_APPLICABLE", report)
        self.assertNotIn("Overall: PASS", report)

    def test_missing_current_report_is_not_replaced_by_committed_report(self):
        result = self.run_step("Publish current-run summary")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NOT_RUN", (self.temp / "summary").read_text())

    def test_initial_master_import_requires_unchanged_reviewed_rule_and_data_trees(self):
        clone = self.reviewed_clone()
        result = self.run_step("Find changed rule sources and prepare trusted base", cwd=clone,
                               BASE_SHA="bd3ce8a2435af2da93990804f3acc129112e2821")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verified import preserves", (self.temp / "regression/regression-report.md").read_text())

    def reviewed_clone(self):
        clone = self.temp / "clone"
        subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", str(REPO_ROOT), str(clone)], check=True)
        subprocess.run(["git", "checkout", "--quiet", "--detach", "0df199533e3077839986d058928374046b0a215a"], cwd=clone, check=True)
        return clone

    def test_initial_import_cannot_hide_a_rule_or_fixture_change(self):
        clone = self.reviewed_clone()
        env = {**os.environ, "GIT_AUTHOR_NAME": "Gate test", "GIT_AUTHOR_EMAIL": "test@example.com",
               "GIT_COMMITTER_NAME": "Gate test", "GIT_COMMITTER_EMAIL": "test@example.com"}
        for path in ("detections/discovery/t1016.yml", "tests/true_positives/t1016_tp.json"):
            with self.subTest(path=path):
                original = (clone / path).read_text()
                (clone / path).write_text(original + "\n")
                subprocess.run(["git", "add", path], cwd=clone, check=True)
                subprocess.run(["git", "commit", "--quiet", "-m", "test changed import input"], cwd=clone, env=env, check=True)
                result = self.run_step("Find changed rule sources and prepare trusted base", cwd=clone,
                                      BASE_SHA="bd3ce8a2435af2da93990804f3acc129112e2821")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.temp / "regression/regression-report.md").exists())
                (clone / path).write_text(original)
                subprocess.run(["git", "add", path], cwd=clone, check=True)
                subprocess.run(["git", "commit", "--quiet", "-m", "restore import input"], cwd=clone, env=env, check=True)


if __name__ == "__main__":
    unittest.main()
