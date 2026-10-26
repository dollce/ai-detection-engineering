"""
EQL Validation Module — Validates EQL sequence rules against Elasticsearch.

Uses the ES EQL search API (POST /{index}/_eql/search) instead of the
standard _search API used by validation.py. Reuses the ephemeral index
pattern and helper functions from validation.py.

Phase 6 deliverable — Task 6.2: EQL Rule Support.
"""

import json
import urllib.error
from uuid import uuid4

from orchestration.validation import (
    _es_request,
    _check_es_reachable,
    _build_bulk_body,
    _cleanup_index,
)
from orchestration.siem import _load_infra_config


def _checked_response(status: int, response: dict, operation: str,
                      require_shards: bool = False) -> dict:
    """Reject errors and incomplete ES responses before computing any metric."""
    if not 200 <= status < 300 or not isinstance(response, dict):
        raise ValueError(f"{operation}: invalid HTTP response ({status})")
    if response.get("error"):
        raise ValueError(f"{operation}: {response['error']}")
    for flag in ("timed_out", "is_partial", "is_running", "terminated_early"):
        if response.get(flag):
            raise ValueError(f"{operation}: {flag}")
    shards = response.get("_shards")
    if require_shards or shards is not None:
        if (not isinstance(shards, dict) or type(shards.get("total")) is not int
                or shards["total"] <= 0 or type(shards.get("failed")) is not int
                or shards["failed"] != 0 or type(shards.get("successful")) is not int
                or shards["successful"] != shards["total"]):
            raise ValueError(f"{operation}: incomplete or failed shard response")
    return response


def _count_matches(response: dict, expected_ids: set[str], index_name: str,
                   limit: int) -> int:
    """Count complete EQL matches and verify their corpus provenance."""
    hits = response.get("hits")
    if not isinstance(hits, dict):
        raise ValueError("EQL query: missing hits")
    if "sequences" in hits:
        matches = hits["sequences"]
        if not isinstance(matches, list) or any(not isinstance(x, dict) for x in matches):
            raise ValueError("EQL query: malformed sequences")
        event_groups = [match.get("events") for match in matches]
    elif "events" in hits:
        matches = hits["events"]
        if not isinstance(matches, list):
            raise ValueError("EQL query: malformed events")
        event_groups = [[event] for event in matches]
    else:
        raise ValueError("EQL query: missing sequences/events")
    total = hits.get("total")
    if (not isinstance(total, dict) or total.get("relation") != "eq"
            or type(total.get("value")) is not int or total["value"] != len(matches)
            or len(matches) >= limit):
        raise ValueError("EQL query: truncated or inconsistent match count")
    for events in event_groups:
        if not isinstance(events, list) or not events:
            raise ValueError("EQL query: missing sequence events")
        for event in events:
            if (not isinstance(event, dict) or event.get("_id") not in expected_ids
                    or event.get("_index") != index_name):
                raise ValueError("EQL query: match does not belong to the queried corpus")
    return len(matches)


def validate_eql_against_elasticsearch(
    eql_query: str,
    attack_events: list,
    benign_events: list,
    technique_id: str = "",
    es_url: str = None,
    es_auth: tuple = None,
    index_prefix: str = "sim-validation",
    expected_sequences: int = 1,
    cleanup: bool = True,
) -> dict:
    """Execute EQL independently against attack and benign scenario corpora.

    Events retain their timestamps and ordering. Deterministic document IDs
    isolate each population, and returned IDs are checked before scoring.
    TP/FN describe whether the attack scenario meets ``expected_sequences``;
    FP/TN describe whether the independently queried benign scenario matches.
    This is scenario-level evidence, not an event-level confusion matrix.
    None means ES was unreachable; every later failure carries explicit errors.
    """
    if es_url is None or es_auth is None:
        es = _load_infra_config().get("elasticsearch", {})
        es_url = es_url or es.get("url", "http://localhost:9200")
        es_auth = es_auth or (es.get("user", "elastic"), es.get("pass", "changeme"))
    if not _check_es_reachable(es_url, es_auth):
        return None

    index_name = f"{index_prefix}-{uuid4().hex[:8]}"
    result = {
        "validation_method": "elasticsearch_eql", "scoring_unit": "scenario",
        "eql_query": eql_query, "expected_sequences": expected_sequences,
        "sequences_found": 0, "attack_sequences_found": 0, "benign_sequences_found": 0,
        "tp": 0, "fp": 0, "fn": int(bool(attack_events)), "tn": 0,
        "total_attack": int(bool(attack_events)), "total_benign": int(bool(benign_events)),
        "precision": 0.0, "recall": 0.0, "f1_score": 0.0,
        "fp_rate": 0.0, "tp_rate": 0.0, "events_ingested": 0,
        "index_used": index_name, "errors": [],
    }
    created = False
    try:
        if not isinstance(eql_query, str) or not eql_query.strip():
            raise ValueError("Empty EQL query")
        if type(expected_sequences) is not int or expected_sequences < 1:
            raise ValueError("expected_sequences must be a positive integer")
        if not attack_events and not benign_events:
            raise ValueError("No events supplied")
        for event in [*attack_events, *benign_events]:
            if not isinstance(event, dict) or not event:
                raise ValueError("Scenario events must be nonempty objects")
            if not event.get("@timestamp"):
                raise ValueError("EQL scenario events require explicit timestamps")

        status, response = _es_request(
            f"{es_url}/{index_name}", method="PUT", auth=es_auth,
            data={"settings": {"number_of_shards": 1, "number_of_replicas": 0,
                               "index.lifecycle.name": "validation-cleanup"}},
        )
        _checked_response(status, response, "Create index")
        created = True
        if response.get("acknowledged") is not True:
            raise ValueError("Create index: not acknowledged")

        status, response = _es_request(
            f"{es_url}/{index_name}/_bulk", method="POST", auth=es_auth,
            data=_build_bulk_body(index_name, attack_events, benign_events, technique_id),
            content_type="application/x-ndjson", timeout=15,
        )
        _checked_response(status, response, "Bulk ingest")
        count = len(attack_events) + len(benign_events)
        items = response.get("items")
        if response.get("errors") is not False or not isinstance(items, list) or len(items) != count:
            raise ValueError("Bulk ingest: errors or incomplete item responses")
        expected_ids = ([f"atk-{i}" for i in range(len(attack_events))]
                        + [f"ben-{i}" for i in range(len(attack_events), count)])
        for item, expected_id in zip(items, expected_ids):
            indexed = item.get("index", {}) if isinstance(item, dict) else {}
            if (type(indexed.get("status")) is not int or not 200 <= indexed["status"] < 300
                    or indexed.get("error") or indexed.get("_id") != expected_id):
                raise ValueError(f"Bulk ingest: failed item: {indexed}")
        result["events_ingested"] = count
        status, response = _es_request(f"{es_url}/{index_name}/_refresh", method="POST", auth=es_auth)
        _checked_response(status, response, "Refresh index", require_shards=True)

        attack_ids = {f"atk-{i}" for i in range(len(attack_events))}
        benign_ids = {f"ben-{i}" for i in range(len(attack_events), count)}
        counts = {}
        for population, ids in (("attack", attack_ids), ("benign", benign_ids)):
            if not ids:
                continue
            limit = 1000
            status, response = _es_request(
                f"{es_url}/{index_name}/_eql/search", method="POST", auth=es_auth,
                data={"query": eql_query, "filter": {"ids": {"values": sorted(ids)}},
                      "size": limit}, timeout=30,
            )
            _checked_response(status, response, f"EQL {population} query")
            counts[population] = _count_matches(response, ids, index_name, limit)

        attack_count, benign_count = counts.get("attack", 0), counts.get("benign", 0)
        tp = int(bool(attack_ids) and attack_count >= expected_sequences)
        fn = int(bool(attack_ids) and not tp)
        fp = int(bool(benign_ids) and benign_count > 0)
        tn = int(bool(benign_ids) and benign_count == 0)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        result.update(
            sequences_found=attack_count + benign_count,
            attack_sequences_found=attack_count, benign_sequences_found=benign_count,
            tp=tp, fp=fp, fn=fn, tn=tn,
            precision=round(precision, 4), recall=round(recall, 4), f1_score=round(f1, 4),
            fp_rate=float(fp), tp_rate=float(tp),
        )
    except Exception as exc:
        detail = str(exc)
        if isinstance(exc, urllib.error.HTTPError):
            detail += ": " + exc.read().decode("utf-8", errors="replace")[:1000]
        result["errors"].append(f"EQL validation failed: {detail}")
    finally:
        if cleanup and created:
            _cleanup_index(es_url, index_name, es_auth)
    return result


def validate_eql_rule_file(
    rule_path: str,
    attack_scenario_path: str,
    benign_scenario_path: str = None,
) -> dict:
    """
    Convenience wrapper to validate an EQL rule YAML file against scenario JSON files.

    Args:
        rule_path: Path to EQL rule YAML (with detection_type: eql and eql_query)
        attack_scenario_path: Path to attack scenario JSON
        benign_scenario_path: Path to benign scenario JSON (optional)

    Returns:
        Validation result dict with f1, tp, fp, fn, tn metrics.
    """
    import yaml

    with open(rule_path, encoding="utf-8") as f:
        rule = yaml.safe_load(f)

    eql_query = rule.get("eql_query", "")
    if not eql_query:
        return {"error": "No eql_query found in rule", "f1_score": 0.0}

    with open(attack_scenario_path, encoding="utf-8") as f:
        scenario = json.load(f)

    attack_events = scenario.get("attack_events", scenario.get("events", []))
    benign_events = []

    if benign_scenario_path:
        with open(benign_scenario_path, encoding="utf-8") as f:
            benign_scenario = json.load(f)
        benign_events = benign_scenario.get("events", [])

    return validate_eql_against_elasticsearch(
        eql_query=eql_query,
        attack_events=attack_events,
        benign_events=benign_events,
        technique_id=next(
            (t.replace("attack.", "").upper() for t in rule.get("tags", [])
             if t.startswith("attack.t")),
            rule.get("id", ""),
        ),
        expected_sequences=rule.get("eql_min_sequences", 1),
    )
