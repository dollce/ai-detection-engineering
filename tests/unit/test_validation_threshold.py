"""Threshold query/scoring contracts; mocked ES responses are offline evidence."""

from copy import deepcopy
from datetime import datetime
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "autonomous"))
from orchestration import validation_threshold as threshold


def event(second=0, group="host-a", value="command-a"):
    return {"@timestamp": f"2026-01-01T00:{second // 60:02}:{second % 60:02}.000Z",
            "host.name": group, "process.name": value}


def terms(buckets):
    return {"doc_count_error_upper_bound": 0, "sum_other_doc_count": 0,
            "buckets": buckets}


class FixtureElasticsearch:
    """Minimal fixture transport: only grouping, ids, and timestamp ranges.

    It deliberately does not implement Lucene. Actual query syntax and mapping
    validation require the separate live Elasticsearch run.
    """

    def __init__(self):
        self.docs = {}
        self.queries = []
        self.overrides = {}

    def request(self, url, method="GET", data=None, **kwargs):
        operation = "create"
        response = {"acknowledged": True}
        shards = {"total": 1, "successful": 1, "failed": 0}
        if url.endswith("/_bulk"):
            operation = "bulk"
            lines = data.splitlines()
            items = []
            for action, document in zip(lines[::2], lines[1::2]):
                event_id = json.loads(action)["index"]["_id"]
                self.docs[event_id] = json.loads(document)
                items.append({"index": {"_id": event_id, "status": 201}})
            response = {"errors": False, "items": items}
        elif url.endswith("/_refresh"):
            operation = "refresh"
            response = {"_shards": shards}
        elif url.endswith("/_search"):
            operation = "search"
            self.queries.append(deepcopy(data))
            filters = data["query"]["bool"]["filter"]
            ids = next(f["ids"]["values"] for f in filters if "ids" in f)
            span = next(f["range"]["@timestamp"] for f in filters if "range" in f)
            start, end = datetime.fromisoformat(span["gte"]), datetime.fromisoformat(span["lte"])
            selected = [self.docs[i] for i in ids
                        if start <= datetime.fromisoformat(self.docs[i]["@timestamp"].replace("Z", "+00:00")) <= end]
            group = data["aggs"]["by_group"]
            group_field = group["terms"]["field"]
            buckets = []
            for key in sorted({doc[group_field] for doc in selected if group_field in doc}):
                documents = [doc for doc in selected if doc.get(group_field) == key]
                bucket = {"key": key, "doc_count": len(documents)}
                if "aggs" in group:
                    field = group["aggs"]["distinct_values"]["terms"]["field"]
                    values = {doc[field] for doc in documents if field in doc}
                    bucket["distinct_values"] = terms([
                        {"key": value, "doc_count": sum(doc.get(field) == value for doc in documents)}
                        for value in sorted(values)
                    ])
                buckets.append(bucket)
            response = {"timed_out": False, "_shards": shards,
                        "aggregations": {"by_group": terms(buckets)}}
        if operation in self.overrides:
            override = self.overrides[operation]
            if isinstance(override, Exception):
                raise override
            if callable(override):
                response = override(response)
            else:
                return override
        return 200, response


class ThresholdValidationTests(unittest.TestCase):
    def setUp(self):
        self.es = FixtureElasticsearch()
        self.enterContext(patch.object(threshold, "_check_es_reachable", return_value=True))
        self.enterContext(patch.object(threshold, "_es_request", side_effect=self.es.request))
        self.cleanup = self.enterContext(patch.object(threshold, "_cleanup_index"))

    def validate(self, attack=None, benign=None, **kwargs):
        args = {"base_query": "event.code:1", "threshold_field": "host.name",
                "threshold_value": 2, "window": "10s",
                "attack_events": attack if attack is not None else [event(0), event(1)],
                "benign_events": benign if benign is not None else [event(0)],
                "es_url": "http://fixture.invalid", "es_auth": ("fixture", "fixture")}
        args.update(kwargs)
        return threshold.validate_threshold_against_elasticsearch(**args)

    def test_original_timestamps_and_order_are_preserved_without_mutating_inputs(self):
        attack, benign = [event(20), event(0)], [event(30), event(1)]
        original = deepcopy((attack, benign))
        bulk = threshold._build_threshold_bulk_body("fixture", attack, benign, "T1110", 10)
        documents = [json.loads(line) for line in bulk.splitlines()[1::2]]
        self.assertEqual([e["@timestamp"] for e in documents],
                         [e["@timestamp"] for e in attack + benign])
        self.assertEqual((attack, benign), original)

    def test_attack_and_benign_breaches_are_scored_independently(self):
        result = self.validate(benign=[event(0), event(1)])
        self.assertEqual((result["tp"], result["fp"], result["fn"], result["tn"]), (1, 1, 0, 0))
        self.assertEqual(result["f1_score"], .6667)
        self.assertEqual(result["fp_rate"], 1)
        self.assertEqual((result["total_attack"], result["total_benign"], result["tp_rate"]), (1, 1, 1))
        self.assertEqual(result["scoring_unit"], "scenario")
        self.assertFalse(result["errors"])

    def test_benign_burst_does_not_become_attack_true_positive(self):
        result = self.validate(attack=[event()], benign=[event(0), event(1)])
        self.assertEqual((result["tp"], result["fp"], result["fn"], result["tn"]), (0, 1, 1, 0))

    def test_population_events_cannot_combine_into_a_breach(self):
        result = self.validate(attack=[event()], benign=[event()])
        self.assertEqual((result["tp"], result["fp"], result["fn"], result["tn"]), (0, 0, 1, 1))

    def test_event_count_outside_window_is_not_a_breach(self):
        result = self.validate(attack=[event(0), event(11)], benign=[])
        self.assertEqual((result["tp"], result["fn"], result["tn"]), (0, 1, 0))
        self.assertEqual(result["window_evaluations"], 2)
        for query in self.es.queries:
            span = query["query"]["bool"]["filter"][2]["range"]["@timestamp"]
            self.assertEqual((datetime.fromisoformat(span["lte"]) - datetime.fromisoformat(span["gte"])).total_seconds(), 10)

    def test_sliding_window_checks_later_burst_and_out_of_order_events(self):
        result = self.validate(attack=[event(25), event(0), event(20)], benign=[])
        self.assertEqual((result["tp"], result["fn"]), (1, 0))

    def test_inclusive_window_boundary_is_counted(self):
        result = self.validate(attack=[event(0), event(10)])
        self.assertEqual((result["tp"], result["tn"]), (1, 1))

    def test_distinct_count_requires_raw_count_too(self):
        result = self.validate(attack=[event(0, value="one"), event(1, value="two")],
                               threshold_value=3, cardinality_field="process.name", cardinality_value=2)
        self.assertEqual((result["tp"], result["fn"]), (0, 1))
        self.assertFalse(result["errors"])

    def test_raw_count_requires_distinct_count_too(self):
        result = self.validate(cardinality_field="process.name", cardinality_value=2)
        self.assertEqual((result["tp"], result["fn"]), (0, 1))

    def test_both_threshold_conditions_produce_a_breach(self):
        result = self.validate(attack=[event(0, value="one"), event(1, value="two")],
                               cardinality_field="process.name", cardinality_value=2)
        self.assertEqual((result["tp"], result["tn"]), (1, 1))

    def test_absent_population_does_not_get_a_fabricated_score(self):
        attack_only = self.validate(benign=[])
        self.assertEqual((attack_only["fp"], attack_only["tn"]), (0, 0))
        self.assertEqual(attack_only["total_benign"], 0)
        benign_only = self.validate(attack=[])
        self.assertEqual((benign_only["tp"], benign_only["fn"], benign_only["tn"]), (0, 0, 1))
        self.assertEqual(benign_only["total_attack"], 0)

    def assert_failed(self, result):
        self.assertTrue(result["errors"])
        self.assertEqual(result["f1_score"], 0)
        self.assertEqual((result["tp"], result["fp"], result["fn"], result["tn"]), (0, 0, 0, 0))

    def test_missing_or_invalid_temporal_evidence_fails_before_ingestion(self):
        for value in (None, "", "yesterday", "2026-01-01T00:00:00", 0):
            with self.subTest(timestamp=value):
                self.assert_failed(self.validate(attack=[{"@timestamp": value}]))
        self.assertFalse(self.es.docs)

    def test_invalid_configuration_fails_closed(self):
        for args in ({"window": "0s"}, {"window": "3d"}, {"window": "nonsense"},
                     {"threshold_value": 0}, {"threshold_value": True}, {"base_query": ""},
                     {"cardinality_field": "process.name"}, {"cardinality_value": 2},
                     {"cardinality_field": "process.name", "cardinality_value": 0}):
            with self.subTest(args=args):
                self.assert_failed(self.validate(**args))
        self.assertFalse(self.es.docs)

    def test_ingestion_failure_never_runs_search_or_claims_tn(self):
        for override in (
            (200, {"errors": True, "items": []}),
            (200, {"errors": False, "items": []}),
            (503, {}), RuntimeError("bulk unavailable"),
            lambda r: {**r, "items": [{"index": {"status": 400}}] + r["items"][1:]},
        ):
            with self.subTest(override=override):
                self.es.overrides["bulk"] = override
                self.assert_failed(self.validate())
        self.assertFalse(self.es.queries)
        self.assertTrue(self.cleanup.called)

    def test_refresh_or_index_creation_failure_fails_closed(self):
        for operation, override in (
            ("create", (200, {"acknowledged": False})),
            ("create", (500, {})),
            ("refresh", (200, {"_shards": {"total": 1, "successful": 0, "failed": 1}})),
        ):
            with self.subTest(operation=operation):
                self.es.overrides = {operation: override}
                self.assert_failed(self.validate())
        self.assertFalse(self.es.queries)

    def test_partial_search_timeout_and_truncated_group_results_fail_closed(self):
        for override in (
            lambda r: {**r, "timed_out": True},
            lambda r: {**r, "terminated_early": True},
            lambda r: {**r, "_shards": {"total": 1, "successful": 0, "failed": 1}},
            lambda r: {**r, "aggregations": {}},
            lambda r: {**r, "aggregations": {"by_group": {**terms([]), "sum_other_doc_count": 1}}},
            lambda r: {**r, "aggregations": {"by_group": {**terms([]), "doc_count_error_upper_bound": 1}}},
            (400, {"error": "invalid aggregation field"}),
        ):
            with self.subTest(override=override):
                self.es.overrides = {"search": override}
                self.assert_failed(self.validate())

    def test_cardinality_mapping_error_is_reported_and_cannot_pass(self):
        body = json.dumps({"error": {"reason": "Fielddata is disabled on text fields [param1]"}}).encode()
        error = HTTPError(
            "http://fixture.invalid/_search", 400, "Bad Request", {}, io.BytesIO(body)
        )
        self.addCleanup(error.close)
        self.es.overrides["search"] = error
        result = self.validate(cardinality_field="param1", cardinality_value=2)
        self.assert_failed(result)
        self.assertIn("Fielddata is disabled", result["errors"][0])

    def test_distinct_terms_truncation_fails_closed(self):
        def truncate(response):
            for bucket in response["aggregations"]["by_group"]["buckets"]:
                bucket["distinct_values"]["sum_other_doc_count"] = 1
            return response
        self.es.overrides["search"] = truncate
        self.assert_failed(self.validate(cardinality_field="process.name", cardinality_value=2))

    def test_benign_query_failure_discards_earlier_attack_success(self):
        def fail_benign(response):
            ids = self.es.queries[-1]["query"]["bool"]["filter"][1]["ids"]["values"]
            if ids[0].startswith("ben-"):
                raise RuntimeError("benign search failed")
            return response
        self.es.overrides["search"] = fail_benign
        self.assert_failed(self.validate())

    def test_unreachable_es_remains_the_only_none_result(self):
        with patch.object(threshold, "_check_es_reachable", return_value=False):
            self.assertIsNone(self.validate())
        self.cleanup.assert_not_called()

    def test_bounds_are_explicit_and_fail_before_ingestion(self):
        with patch.object(threshold, "_MAX_EVENTS", 1):
            self.assert_failed(self.validate())
        with patch.object(threshold, "_MAX_WINDOWS", 1):
            self.assert_failed(self.validate())
        self.assertFalse(self.es.docs)


if __name__ == "__main__":
    unittest.main()
