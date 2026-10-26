"""Tests for E2E evidence boundaries; network/scheduler success remains a live test."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("e2e_elastic", ROOT / "pipeline/e2e_elastic.py")
e2e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e2e)


class CaseAndCompilerTests(unittest.TestCase):
    def test_manifest_identifies_context_and_preserves_original_detection_fields(self):
        _, _, cases = e2e.read_case(e2e.DEFAULT_CASE)
        original = copy.deepcopy(cases)
        self.assertEqual([c["expected_alert"] for c in cases], [False, True, True, False, False])
        replay = e2e.replay_cases(cases, "testrun", "2026-10-26T00:00:00.000Z")
        self.assertEqual(cases, original)
        for before, after in zip(cases, replay):
            self.assertEqual(after["event"]["@timestamp"], "2026-10-26T00:00:00.000Z")
            self.assertEqual(after["event"]["labels"]["ade_e2e_run"], "testrun")
            cleaned = copy.deepcopy(after["event"])
            cleaned["@timestamp"] = before["event"]["@timestamp"]
            cleaned["event"].pop("id")
            cleaned.pop("labels")
            self.assertEqual(cleaned, before["event"])

    def test_compile_uses_real_command_and_shared_normalization(self):
        raw = "Parsing Sigma rules...\nwinlog.channel:Microsoft-Windows-Sysmon/Operational AND event.code:1\n"
        with patch.object(e2e.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, raw, "")) as invoke:
            output = e2e.compile_rule(Path("example.yml"))
        self.assertEqual(invoke.call_args.args[0], ["sigma", "convert", "-t", "lucene", "-p", "ecs_windows", "example.yml"])
        self.assertEqual(output["query"], "event.code:1")
        self.assertEqual(output["raw_output"], raw)

    def test_compile_failure_cannot_use_nonempty_stdout(self):
        for rc, output in [(1, "event.code:1"), (0, ""), (0, "Parsing Sigma rules...\n"), (0, "a:b\nc:d")]:
            with self.subTest(rc=rc, output=output), patch.object(e2e.subprocess, "run", return_value=subprocess.CompletedProcess([], rc, output, "")):
                with self.assertRaises(e2e.E2EFailure):
                    e2e.compile_rule(Path("example.yml"))

    def test_endpoints_reject_remote_credentials_and_redirect(self):
        for endpoint in ["https://example.com", "http://u:p@localhost", "file:///tmp/test", "http://localhost/other", "http://localhost?a=b"]:
            with self.subTest(endpoint=endpoint), self.assertRaises(e2e.E2EFailure):
                e2e.check_endpoint(endpoint)
        self.assertEqual(e2e.check_endpoint("http://127.0.0.1:19200/"), "http://127.0.0.1:19200")
        self.assertEqual(e2e.check_endpoint("https://example.com", True), "https://example.com")
        with self.assertRaises(e2e.E2EFailure):
            e2e.NoRedirect().redirect_request(None, None, 302, "", {}, "http://example.com")


class EvidenceTests(unittest.TestCase):
    def metrics(self):
        return {"method": "elasticsearch", "ingestion_method": "direct", "errors": [],
                "tp": 2, "fp": 0, "fn": 0, "tn": 3, "total_attack": 2, "total_benign": 3,
                "events_ingested": 5, "query_hits": 2, "f1_score": 1.0, "index_used": "ade-e2e-test-validation-123"}

    def test_only_complete_actual_es_metrics_pass(self):
        e2e.validate_metrics(self.metrics(), 2, 3, "ade-e2e-test")
        corruptions = [None, {}, {"method": "local_json"}, {"ingestion_method": "cribl"},
                       {"errors": ["partial delivery"]}, {"events_ingested": 4}, {"fp": 1},
                       {"tp": True}, {"tn": 2}, {"index_used": "sim-validation-other"}]
        for change in corruptions:
            result = None if change is None else {} if change == {} else {**self.metrics(), **change}
            with self.subTest(change=change), self.assertRaises(e2e.E2EFailure):
                e2e.validate_metrics(result, 2, 3, "ade-e2e-test")

    def test_query_response_must_be_complete(self):
        valid = {"timed_out": False, "_shards": {"failed": 0}, "hits": {"total": {"value": 1, "relation": "eq"}, "hits": [{"_id": "a"}]}}
        self.assertEqual(len(e2e.checked_hits(valid)), 1)
        for broken in [{}, {**valid, "timed_out": True}, {**valid, "_shards": {"failed": 1}},
                       {**valid, "hits": {"total": {"value": 2, "relation": "eq"}, "hits": [{"_id": "a"}]}}]:
            with self.subTest(broken=broken), self.assertRaises(e2e.E2EFailure):
                e2e.checked_hits(broken)

    def test_scheduler_success_requires_current_execution_timestamp(self):
        start = "2026-10-26T00:00:00Z"
        def rule(status, date=start):
            return {"execution_summary": {"last_execution": {"status": status, "date": date}}}
        self.assertFalse(e2e.execution_succeeded({}, start))
        self.assertFalse(e2e.execution_succeeded(rule("running"), start))
        self.assertFalse(e2e.execution_succeeded(rule("succeeded", "2026-10-25T00:00:00Z"), start))
        self.assertTrue(e2e.execution_succeeded(rule("succeeded"), start))
        for status, date in [("failed", start), ("partial failure", start), ("succeeded", "bad"), ("succeeded", "2026-10-26T00:00:00")]:
            with self.subTest(status=status, date=date), self.assertRaises(e2e.E2EFailure):
                e2e.execution_succeeded(rule(status, date), start)

    def alert(self, case_id, source_index="ade-e2e-test-events", rule_id="ade-e2e-test"):
        return {"_id": "alert-" + case_id, "_index": "alerts", "_source": {
            "kibana.alert.rule.rule_id": rule_id,
            "kibana.alert.rule.execution.type": "scheduled",
            "kibana.alert.rule.execution.uuid": "execution-test",
            "kibana.alert.ancestors": [{"index": source_index, "id": case_id}]}}

    def test_alerts_must_identify_expected_source_cases_for_this_run(self):
        _, _, cases = e2e.read_case(e2e.DEFAULT_CASE)
        alerts = [self.alert("chained_recon"), self.alert("suspicious_parent")]
        args = (cases, "ade-e2e-test", "ade-e2e-test-events", "test")
        self.assertTrue(e2e.verify_alerts(alerts, *args)[0])
        self.assertFalse(e2e.verify_alerts(alerts[:1], *args)[0])
        self.assertFalse(e2e.verify_alerts([], *args)[0])
        invalid = [alerts + [self.alert("context_process")], alerts + alerts[:1],
                   [self.alert("chained_recon", source_index="other-events")],
                   [self.alert("chained_recon", rule_id="another-rule")],
                   [{"_source": {"kibana.alert.rule.rule_id": "ade-e2e-test"}}]]
        for rows in invalid:
            with self.subTest(rows=rows), self.assertRaises(e2e.E2EFailure):
                e2e.verify_alerts(rows, *args)
        manual = self.alert("chained_recon")
        manual["_source"]["kibana.alert.rule.execution.type"] = "manual"
        with self.assertRaises(e2e.E2EFailure):
            e2e.verify_alerts([manual], *args)
        no_uuid = self.alert("chained_recon")
        del no_uuid["_source"]["kibana.alert.rule.execution.uuid"]
        with self.assertRaises(e2e.E2EFailure):
            e2e.verify_alerts([no_uuid], *args)


class CleanupTests(unittest.TestCase):
    class FakeClient:
        def __init__(self, leave_rule=False, fail_delete=False):
            self.calls = []
            self.indices = ["ade-e2e-test-events", "ade-e2e-test-validation-leftover"]
            self.leave_rule, self.fail_delete = leave_rule, fail_delete

        def request(self, target, path, method="GET", data=None, **kwargs):
            self.calls.append((target, path, method, data))
            if path.startswith("/_resolve/index/"):
                return {"indices": [{"name": name} for name in self.indices]}
            if method == "DELETE" and path.startswith("/ade-e2e-test-"):
                if self.fail_delete:
                    raise e2e.E2EFailure("index deletion failed")
                self.indices.remove(path[1:])
            if method == "GET" and "detection_engine/rules" in path:
                return {"rule_id": "ade-e2e-test"} if self.leave_rule else None
            if "_delete_by_query" in path:
                return {"timed_out": False, "failures": [], "deleted": 2, "version_conflicts": 0}
            if path.endswith("/_search"):
                return {"timed_out": False, "_shards": {"failed": 0}, "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}
            return None

    def test_cleanup_removes_leftover_validation_indices_and_verifies_absence(self):
        client = self.FakeClient()
        result = e2e.cleanup(client, "ade-e2e-test", "ade-e2e-test", "ade-e2e-test-template")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(client.indices, [])
        deletion = next(call for call in client.calls if "_delete_by_query" in call[1])
        self.assertEqual(deletion[3], {"query": {"term": {"kibana.alert.rule.rule_id": "ade-e2e-test"}}})

    def test_cleanup_failure_remains_fail_and_other_cleanup_is_attempted(self):
        for option in ("leave_rule", "fail_delete"):
            client = self.FakeClient(**{option: True})
            result = e2e.cleanup(client, "ade-e2e-test", "ade-e2e-test", "ade-e2e-test-template")
            self.assertEqual(result["status"], "FAIL")
            self.assertTrue(result["errors"])
            self.assertTrue(any("_index_template/" in call[1] and call[2] == "DELETE" for call in client.calls))
            self.assertTrue(any("_delete_by_query" in call[1] for call in client.calls))

    def test_intermediate_failure_still_runs_cleanup_and_records_fail(self):
        args = argparse.Namespace(es_url="http://127.0.0.1:19200", kibana_url="http://127.0.0.1:15601",
                                  user="elastic", password="secret", case=e2e.DEFAULT_CASE, timeout=1, poll_interval=0.01)
        with patch.object(e2e, "preflight", return_value={}), patch.object(e2e, "compile_rule", return_value={"query": "event.code:1"}), \
             patch.object(e2e.Client, "request", return_value={"acknowledged": True}), \
             patch("orchestration.validation.validate_against_elasticsearch", return_value=None), \
             patch.object(e2e, "cleanup", return_value={"status": "FAIL", "errors": ["cleanup failure"]}) as cleanup:
            report = e2e.run(args)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["stages"]["query_validation"]["status"], "FAIL")
        self.assertEqual(report["stages"]["cleanup"]["status"], "FAIL")
        cleanup.assert_called_once()
        self.assertNotIn("password", json.dumps(report))

    def test_redaction_reaches_nested_report_values(self):
        self.assertEqual(e2e.redact({"x": ["contains secret"]}, ["secret"]), {"x": ["contains [REDACTED]"]})


if __name__ == "__main__":
    unittest.main()
