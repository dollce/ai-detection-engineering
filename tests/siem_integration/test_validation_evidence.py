"""Opt-in tests against an isolated Elasticsearch with the setup.sh sim-logs template.

Run with ES_VALIDATION_URL set. Only temporary sim-validation-* indices are written.
"""

from copy import deepcopy
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import sys
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "autonomous"))

from orchestration.validation import validate_against_elasticsearch
from orchestration.validation_eql import validate_eql_against_elasticsearch
from orchestration.validation_threshold import validate_threshold_against_elasticsearch


@unittest.skipUnless(os.environ.get("ES_VALIDATION_URL"), "Set ES_VALIDATION_URL to an isolated ES")
class ValidationEvidenceIntegrationTests(unittest.TestCase):
    def inputs(self, name):
        request = yaml.safe_load((ROOT / "autonomous/detection-requests" / f"{name}.yml").read_text())
        events = json.loads((ROOT / request["scenario_file"]).read_text())["events"]
        artifact = json.loads((ROOT / request["compiled_artifact"]).read_text()) if request.get("compiled_artifact") else None
        return request, events["attack_sequence"], events["benign_similar"], artifact

    def validate(self, name, mutate=None):
        request, attack, benign, artifact = self.inputs(name)
        if mutate:
            mutate(attack, benign)
        kwargs = dict(attack_events=attack, benign_events=benign,
                      technique_id=request["technique_id"],
                      es_url=os.environ["ES_VALIDATION_URL"],
                      es_auth=(os.environ.get("ES_USER", "elastic"), os.environ.get("ES_PASS", "changeme")))
        kind = request.get("rule_type", "sigma")
        if kind == "eql":
            result = validate_eql_against_elasticsearch(artifact["query"], **kwargs)
        elif kind == "threshold":
            threshold = artifact["threshold"]
            cardinality = threshold["cardinality"][0]
            result = validate_threshold_against_elasticsearch(
                artifact["query"], threshold["field"][0], threshold["value"],
                artifact["from"].removeprefix("now-"),
                cardinality_field=cardinality["field"], cardinality_value=cardinality["value"], **kwargs)
        else:
            result = validate_against_elasticsearch((ROOT / request["compiled_lucene"]).read_text().strip(), **kwargs)
        self.assertIsNotNone(result, "Elasticsearch validation must execute")
        return result

    def assert_counts(self, result, expected):
        self.assertEqual(result["errors"], [])
        self.assertEqual(tuple(result[key] for key in ("tp", "fp", "fn", "tn")), expected)

    def test_five_repaired_scenarios(self):
        for name in ("t1016", "t1055_eql", "t1059_001_t1547_001_eql", "t1087_002_eql", "t1489"):
            with self.subTest(name=name):
                result = self.validate(name)
                self.assert_counts(result, (3, 0, 0, 2) if name == "t1016" else (1, 0, 0, 1))
                self.assertEqual(result["f1_score"], 1.0)

    def test_eql_sequence_order_is_required(self):
        def reverse_time(attack, benign):
            attack[0]["@timestamp"], attack[1]["@timestamp"] = attack[1]["@timestamp"], attack[0]["@timestamp"]
        self.assert_counts(self.validate("t1055_eql", reverse_time), (0, 0, 1, 1))

    def test_eql_maxspan_is_required(self):
        def outside_span(attack, benign):
            attack[-1]["@timestamp"] = "2026-04-12T10:02:00.000Z"
        self.assert_counts(self.validate("t1087_002_eql", outside_span), (0, 0, 1, 1))

    def test_eql_benign_sequence_counts_as_false_positive(self):
        def matching_benign(attack, benign):
            benign[:] = deepcopy(attack)
        self.assert_counts(self.validate("t1055_eql", matching_benign), (1, 1, 0, 0))

    def test_threshold_outside_window_does_not_breach(self):
        def spread(attack, benign):
            start = datetime.fromisoformat(attack[0]["@timestamp"].replace("Z", "+00:00"))
            for i, event in enumerate(attack):
                event["@timestamp"] = (start + timedelta(hours=i)).isoformat()
        self.assert_counts(self.validate("t1489", spread), (0, 0, 1, 1))

    def test_threshold_requires_distinct_services(self):
        def one_service(attack, benign):
            for event in attack:
                event["winlog"]["event_data"]["param1"] = "SQL Server (MSSQLSERVER)"
        self.assert_counts(self.validate("t1489", one_service), (0, 0, 1, 1))

    def test_threshold_benign_breach_counts_as_false_positive(self):
        def matching_benign(attack, benign):
            benign[:] = deepcopy(attack)
        self.assert_counts(self.validate("t1489", matching_benign), (1, 1, 0, 0))

    def test_original_timestamp_typo_remains_a_failure(self):
        def malformed(attack, benign):
            benign[-1]["@timestamp"] = "2026-03-21T08:55.47.918Z"
        result = self.validate("t1016", malformed)
        self.assertTrue(result["errors"])
        self.assertIn("Bulk ingest", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
