"""Offline contracts for native ES evidence refresh; no SIEM runs in these tests."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "autonomous"))
from orchestration import revalidate_evidence as runner
from orchestration.validation_results import ValidationUnavailable, read_f1, require_no_errors


class RevalidationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.request = self.root / "autonomous/detection-requests/t1000.yml"
        self.rule = self.root / "detections/execution/t1000.yml"
        self.scenario = self.root / "simulator/scenarios/t1000.json"
        self.compiled = self.root / "detections/execution/compiled/t1000.lucene"
        self.output = self.root / "tests/results/t1000.json"
        self.attack = [{"@timestamp": "2026-01-01T00:00:00Z", "process": {"name": "attack.exe"}}] * 2
        self.benign = [{"@timestamp": "2026-01-01T00:00:01Z", "process": {"name": "benign.exe"}}] * 2
        self.write(self.request, yaml.safe_dump({
            "technique_id": "T1000", "sigma_rule": "detections/execution/t1000.yml",
            "scenario_file": "simulator/scenarios/t1000.json",
            "compiled_lucene": "detections/execution/compiled/t1000.lucene",
        }))
        self.write(self.rule, "title: Test rule\n")
        self.write(self.scenario, json.dumps({"events": {"attack_sequence": self.attack, "benign_similar": self.benign}}))
        self.write(self.compiled, 'process.name: "attack.exe"\n')
        self.previous = b'{"previous_evidence": true}\n'
        self.output.parent.mkdir(parents=True)
        self.output.write_bytes(self.previous)
        self.version = self.enterContext(patch.object(runner, "_es_request", return_value=(200, {"version": {"number": "8.17.0"}})))
        self.validators = {kind: self.enterContext(patch.object(runner, name, return_value=self.success(kind)))
                           for kind, name in {"sigma": "validate_against_elasticsearch",
                                              "eql": "validate_eql_against_elasticsearch",
                                              "threshold": "validate_threshold_against_elasticsearch"}.items()}
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.stderr = self.enterContext(contextlib.redirect_stderr(io.StringIO()))

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")

    def success(self, kind="sigma"):
        count = 2 if kind == "sigma" else 1
        return {"method" if kind == "sigma" else "validation_method": "elasticsearch" if kind == "sigma" else f"elasticsearch_{kind}",
                "scoring_unit": "event" if kind == "sigma" else "scenario",
                "tp": count, "fp": 0, "fn": 0, "tn": count,
                "precision": 1.0, "recall": 1.0, "f1_score": 1.0,
                "events_ingested": 4, "index_used": "sim-validation-test", "errors": []}

    def configure(self, kind):
        request = yaml.safe_load(self.request.read_text())
        request["rule_type"] = kind
        self.compiled = self.compiled.with_suffix(".json")
        request["compiled_artifact"] = self.compiled.relative_to(self.root).as_posix()
        self.write(self.request, yaml.safe_dump(request))
        artifact = {"type": kind, "query": "query " + ("long content " * 50)}
        if kind == "threshold":
            artifact.update({"from": "now-11m", "threshold": {
                "field": ["host.name"], "value": 3,
                "cardinality": [{"field": "winlog.event_data.param1", "value": 3}],
            }})
        self.write(self.compiled, json.dumps(artifact))
        self.write(self.rule, yaml.safe_dump({"detection_type": kind, "threshold": {"window": "5m"}}))
        return artifact

    def run_one(self):
        return runner.revalidate(self.root, "T1000", "http://localhost:9200")

    def test_sigma_uses_native_query_and_stores_complete_portable_evidence(self):
        with patch.dict("os.environ", {"ES_USER": "test-user", "ES_PASS": "test-password"}):
            self.assertEqual(self.run_one(), self.output)
        call = self.validators["sigma"].call_args.kwargs
        self.assertEqual(call["compiled_lucene"], 'process.name: "attack.exe"')
        self.assertEqual(call["ingestion_method"], "direct")
        self.assertEqual(call["es_auth"], ("test-user", "test-password"))
        self.assertEqual(call["attack_events"], self.attack)
        self.assertEqual(call["benign_events"], self.benign)
        for kind in ("eql", "threshold"):
            self.validators[kind].assert_not_called()
        result = json.loads(self.output.read_text())
        self.assertEqual(result["validation_method"], "elasticsearch")
        self.assertEqual(result["scoring_unit"], "event")
        self.assertEqual(result["metrics"]["tp"], 2)
        self.assertEqual(result["metrics"]["total_attack"], 2)
        self.assertEqual(result["metrics"]["total_benign"], 2)
        self.assertEqual(result["metrics"]["fp_rate"], 0)
        self.assertEqual(result["metrics"]["tp_rate"], 1)
        self.assertEqual(result["elasticsearch_version"], "8.17.0")
        self.assertEqual(result["siem_targets"], ["elasticsearch"])
        self.assertIn("Scenario validation on Elasticsearch temporary indices", result["validation_scope"])
        self.assertRegex(result["date"], r"^\d{4}-\d{2}-\d{2}T")
        self.assertEqual(result["validation_details"], self.success())
        self.assertEqual(read_f1(result), 1)
        require_no_errors(result)
        self.assertEqual(len(result["input_hashes"]), 4)
        for relative, digest in result["input_hashes"].items():
            self.assertEqual(digest, hashlib.sha256((self.root / relative).read_bytes()).hexdigest())
        self.assertNotIn("test-password", self.output.read_text())
        self.assertEqual(list(self.output.parent.glob("*.tmp")), [])

    def test_eql_preserves_exact_query_and_scenario_scoring(self):
        artifact = self.configure("eql")
        self.run_one()
        call = self.validators["eql"].call_args.kwargs
        self.assertEqual(call["eql_query"], artifact["query"])
        self.assertEqual(call["expected_sequences"], 1)
        self.validators["sigma"].assert_not_called()
        result = json.loads(self.output.read_text())
        self.assertEqual(result["query"], artifact["query"])
        self.assertEqual(result["scoring_unit"], "scenario")
        self.assertEqual(result["metrics"]["tp"], 1)
        self.assertEqual(result["metrics"]["total_attack"], 1)
        self.assertEqual(result["metrics"]["total_benign"], 1)
        self.assertEqual(result["metrics"]["fp_rate"], 0)
        self.assertEqual(result["metrics"]["tp_rate"], 1)
        self.assertEqual(result["attack_event_count"], 2)

    def test_threshold_routes_compiled_group_cardinality_and_lookback(self):
        artifact = self.configure("threshold")
        self.run_one()
        call = self.validators["threshold"].call_args.kwargs
        for key, value in {"base_query": artifact["query"], "window": "11m", "threshold_field": "host.name",
                           "threshold_value": 3, "cardinality_field": "winlog.event_data.param1", "cardinality_value": 3}.items():
            self.assertEqual(call[key], value)
        self.validators["sigma"].assert_not_called()
        result = json.loads(self.output.read_text())
        self.assertEqual(result["validation_method"], "elasticsearch_threshold")
        self.assertEqual(result["metrics"]["tn"], 1)
        self.assertEqual(result["query_parameters"]["window"], "11m")

    def test_missing_inputs_preserve_existing_evidence_without_siem_execution(self):
        for path in (self.request, self.rule, self.scenario, self.compiled):
            original = path.read_bytes()
            path.unlink()
            with self.subTest(path=path), self.assertRaises(ValidationUnavailable):
                self.run_one()
            self.assertEqual(self.output.read_bytes(), self.previous)
            path.write_bytes(original)
        self.version.assert_not_called()
        self.validators["sigma"].assert_not_called()

    def test_empty_or_invalid_populations_cannot_run(self):
        for value in ([], None, [{}], ["bad event"], [{"description": "not a log"}]):
            for name in ("attack_sequence", "benign_similar"):
                events = {"attack_sequence": self.attack, "benign_similar": self.benign}
                events[name] = value
                self.write(self.scenario, json.dumps({"events": events}))
                with self.subTest(value=value, name=name), self.assertRaises(ValidationUnavailable):
                    self.run_one()
                self.assertEqual(self.output.read_bytes(), self.previous)
        self.version.assert_not_called()

    def test_unreachable_es_preserves_existing_evidence_and_cli_fails(self):
        self.version.side_effect = URLError("connection refused")
        code = runner.main(["--repo-root", str(self.root), "--technique", "T1000", "--es-url", "http://localhost:9200"])
        self.assertEqual(code, 1)
        self.assertIn("connection refused", self.stderr.getvalue())
        self.assertEqual(self.output.read_bytes(), self.previous)
        self.validators["sigma"].assert_not_called()

    def test_errors_incomplete_or_failed_metrics_never_replace_evidence(self):
        malformed = [None, {}, {**self.success(), "errors": ["partial ingestion"]},
                     {**self.success(), "events_ingested": 3}, {**self.success(), "tp": 1},
                     {**self.success(), "precision": float("nan")}, {**self.success(), "f1_score": 0.74},
                     {**self.success(), "method": "local_json"}, {**self.success(), "tn": True}]
        for missing in ("errors", "f1_score", "recall", "events_ingested"):
            result = self.success()
            del result[missing]
            malformed.append(result)
        for result in malformed:
            self.validators["sigma"].return_value = result
            with self.subTest(result=result), self.assertRaises(ValidationUnavailable):
                self.run_one()
            self.assertEqual(self.output.read_bytes(), self.previous)

    def test_correlations_require_native_scoring_and_complete_benign_population(self):
        self.configure("eql")
        for update in ({"scoring_unit": "event"}, {"tn": 0}, {"tp": 2}):
            self.validators["eql"].return_value = {**self.success("eql"), **update}
            with self.subTest(update=update), self.assertRaises(ValidationUnavailable):
                self.run_one()
            self.assertEqual(self.output.read_bytes(), self.previous)

    def test_metrics_must_agree_with_confusion_counts_before_saving(self):
        for key in ("precision", "recall", "f1_score"):
            self.validators["sigma"].return_value = {**self.success(), key: 0.9}
            with self.subTest(metric=key), self.assertRaisesRegex(ValidationUnavailable, "conflicts"):
                self.run_one()
            self.assertEqual(self.output.read_bytes(), self.previous)

    def test_three_decimal_native_rounding_is_accepted_and_rates_use_native_units(self):
        result = {**self.success(), "tp": 3, "fp": 1, "fn": 0, "tn": 2,
                  "precision": .75, "recall": 1.0, "f1_score": .857,
                  "events_ingested": 6}
        metrics = runner._check_result(result, "sigma", 3, 3)
        self.assertEqual(metrics["total_attack"], 3)
        self.assertEqual(metrics["total_benign"], 3)
        self.assertEqual(metrics["fp_rate"], .3333)
        self.assertEqual(metrics["tp_rate"], 1)
        with self.assertRaisesRegex(ValidationUnavailable, "conflicts"):
            runner._check_result({**result, "f1_score": .858}, "sigma", 3, 3)

    def test_compiled_correlation_languages_must_match_native_validator(self):
        for kind, language in (("eql", "eql"), ("threshold", "lucene")):
            artifact = self.configure(kind)
            for invalid in ("kuery", "unknown", None, 42):
                self.write(self.compiled, json.dumps({**artifact, "language": invalid}))
                with self.subTest(kind=kind, language=invalid), self.assertRaisesRegex(ValidationUnavailable, "language must"):
                    self.run_one()
                self.assertEqual(self.output.read_bytes(), self.previous)
            self.write(self.compiled, json.dumps({**artifact, "language": language}))
            self.run_one()
            self.validators[kind].assert_called_once()
            self.output.write_bytes(self.previous)

    def test_changed_inputs_during_execution_do_not_save_stale_hashes(self):
        def changed(**_kwargs):
            self.compiled.write_text("changed query")
            return self.success()
        self.validators["sigma"].side_effect = changed
        with self.assertRaisesRegex(ValidationUnavailable, "changed during validation"):
            self.run_one()
        self.assertEqual(self.output.read_bytes(), self.previous)

    def test_failed_atomic_replace_preserves_previous_bytes_and_cleans_temp(self):
        with patch.object(runner.os, "replace", side_effect=OSError("disk failure")), self.assertRaises(OSError):
            self.run_one()
        self.assertEqual(self.output.read_bytes(), self.previous)
        self.assertEqual(list(self.output.parent.glob(".*.tmp")), [])

    def test_cli_deduplicates_selected_ids_and_reports_missing_request_nonzero(self):
        destination = self.root / "new-results"
        code = runner.main(["--repo-root", str(self.root), "--output-dir", str(destination),
                            "--technique", "T1000", "--technique", "T1000", "--technique", "T1001",
                            "--es-url", "http://localhost:9200"])
        self.assertEqual(code, 1)
        self.validators["sigma"].assert_called_once()
        self.assertTrue((destination / "t1000.json").is_file())
        self.assertFalse((destination / "t1001.json").exists())
        self.assertEqual(self.output.read_bytes(), self.previous)

    def test_dotted_variant_id_resolves_canonical_lowercase_request_filename(self):
        technique = "T1059.001_T1547.001_EQL"
        request = yaml.safe_load(self.request.read_text())
        request["technique_id"] = technique
        variant = self.request.with_name("t1059_001_t1547_001_eql.yml")
        self.write(variant, yaml.safe_dump(request))
        result_path = runner.revalidate(self.root, technique, "http://localhost:9200")
        self.assertEqual(result_path.name, "t1059_001_t1547_001_eql.json")
        result = json.loads(result_path.read_text())
        self.assertEqual(result["technique_id"], technique)
        self.assertIn("autonomous/detection-requests/t1059_001_t1547_001_eql.yml", result["input_hashes"])
        self.assertEqual(self.validators["sigma"].call_args.kwargs["technique_id"], technique)

    def test_canonical_filename_does_not_allow_mismatched_request_identity(self):
        request = yaml.safe_load(self.request.read_text())
        request["technique_id"] = "T1000.001"
        self.write(self.request, yaml.safe_dump(request))
        with self.assertRaisesRegex(ValidationUnavailable, "does not match"):
            self.run_one()
        self.version.assert_not_called()
        self.assertEqual(self.output.read_bytes(), self.previous)

    def test_exact_ids_and_explicit_endpoint_are_required(self):
        for technique in ("t1000", "T100", "../T1000", "T1000*", "T1000/../../foo"):
            with self.subTest(technique=technique), self.assertRaises(ValidationUnavailable):
                runner.revalidate(self.root, technique, "http://localhost:9200")
        for endpoint in ("", "localhost:9200", "ftp://localhost", "http://user:pass@localhost:9200", "http://localhost/?token=secret"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValidationUnavailable):
                runner.revalidate(self.root, "T1000", endpoint)
        with self.assertRaises(SystemExit):
            runner.main(["--technique", "T1000"])
        self.version.assert_not_called()


if __name__ == "__main__":
    unittest.main()
