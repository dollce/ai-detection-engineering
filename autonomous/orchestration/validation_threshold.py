"""Bounded threshold validation using Elasticsearch, with population-level scores.

Each supplied population is one scenario: attack should breach, benign should not.
All event timestamps must be supplied. A sliding window ending at every event time
tests whether a breach exists anywhere in the fixture, independently of wall time.
This validates fixture behavior, not the production rule's scheduling cadence.
"""

import json
import re
import urllib.error
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from orchestration.validation import _es_request, _check_es_reachable, _cleanup_index
from orchestration.siem import _load_infra_config


_MAX_EVENTS = 10000
_MAX_WINDOWS = 1000
_MAX_TERMS = 10000


def _event_time(value) -> datetime:
    """Require an explicit, timezone-qualified timestamp; never invent timing."""
    if not isinstance(value, str) or not value:
        raise ValueError("Every threshold event requires an explicit @timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid threshold @timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError("Threshold @timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _build_threshold_bulk_body(
    index_name: str,
    attack_events: list,
    benign_events: list,
    technique_id: str,
    window_seconds: int,
) -> str:
    """Preserve fixture timestamps and ordering; label populations for provenance.

    ``window_seconds`` remains in the signature for compatibility. The window is
    enforced by the query and must never be used to reshape fixture timestamps.
    """
    lines = []
    event_id = 0
    for prefix, label, events in (
        ("atk", "attack", attack_events), ("ben", "baseline", benign_events)
    ):
        for event in events:
            flat = _flatten_for_threshold(event)
            _event_time(flat.get("@timestamp"))
            flat["_simulation.type"] = label
            flat["_simulation.technique"] = technique_id
            lines.append(json.dumps({"index": {
                "_index": index_name, "_id": f"{prefix}-{event_id}"
            }}))
            lines.append(json.dumps(flat))
            event_id += 1
    return "\n".join(lines) + "\n"


def _flatten_for_threshold(event: dict, parent_key: str = "", sep: str = ".") -> dict:
    """Flatten nested dict into dotted-key format for ES ingest."""
    items = {}
    for key, value in event.items():
        name = f"{parent_key}{sep}{key}" if parent_key else key
        if isinstance(value, dict):
            items.update(_flatten_for_threshold(value, name, sep))
        else:
            items[name] = value
    return items


def _parse_window_to_seconds(window: str) -> int:
    """Parse positive seconds/minutes/hours; reject unsupported windows."""
    match = re.fullmatch(r"([1-9][0-9]*)([smh])", window or "")
    if not match:
        raise ValueError(f"Invalid threshold window: {window!r}")
    return int(match[1]) * {"s": 1, "m": 60, "h": 3600}[match[2]]


def _response(status, response, operation):
    if not 200 <= status < 300 or not isinstance(response, dict) or response.get("error"):
        raise ValueError(f"{operation} returned an unsuccessful or malformed response")
    return response


def _require_complete_shards(response, operation):
    shards = response.get("_shards", {})
    total = shards.get("total", 0)
    if (not isinstance(total, int) or total <= 0 or shards.get("failed") != 0
            or shards.get("successful") != total):
        raise ValueError(f"{operation} did not complete on every shard")


def _complete_buckets(aggregation):
    if (not isinstance(aggregation, dict)
            or aggregation.get("sum_other_doc_count") != 0
            or aggregation.get("doc_count_error_upper_bound") != 0
            or not isinstance(aggregation.get("buckets"), list)):
        raise ValueError("Threshold aggregation is missing, partial, or truncated")
    buckets = aggregation["buckets"]
    for bucket in buckets:
        if (not isinstance(bucket, dict) or "key" not in bucket
                or not isinstance(bucket.get("doc_count"), int)
                or bucket["doc_count"] < 0):
            raise ValueError("Malformed threshold bucket")
    return buckets


def validate_threshold_against_elasticsearch(
    base_query: str,
    threshold_field: str,
    threshold_value: int,
    window: str,
    attack_events: list,
    benign_events: list,
    technique_id: str = "",
    cardinality_field: str = None,
    cardinality_value: int = None,
    es_url: str = None,
    es_auth: tuple = None,
    index_prefix: str = "sim-validation",
    cleanup: bool = True,
) -> dict:
    """Validate one attack scenario and one benign scenario independently.

    A threshold requires the raw event count AND any configured distinct count.
    Distinct values use an exact, bounded terms aggregation. Incomplete ingestion,
    shard results, or truncated aggregations return errors and no passing score.
    None means Elasticsearch was unreachable before validation began.
    """
    if es_url is None or es_auth is None:
        es = _load_infra_config().get("elasticsearch", {})
        if es_url is None:
            es_url = es.get("url", "http://localhost:9200")
        if es_auth is None:
            es_auth = (es.get("user", "elastic"), es.get("pass", "changeme"))
    if not _check_es_reachable(es_url, es_auth):
        return None

    index_name = f"{index_prefix}-{uuid4().hex[:8]}"
    result = {
        "validation_method": "elasticsearch_threshold",
        "base_query": base_query,
        "threshold_field": threshold_field, "threshold_value": threshold_value,
        "cardinality_field": cardinality_field, "cardinality_value": cardinality_value,
        "window": window, "threshold_breaches": 0,
        "attack_threshold_breaches": 0, "benign_threshold_breaches": 0,
        "tp": 0, "fp": 0, "fn": 0, "tn": 0,
        "precision": 0.0, "recall": 0.0, "f1_score": 0.0, "fp_rate": 0.0, "tp_rate": 0.0,
        "total_attack": int(bool(attack_events)), "total_benign": int(bool(benign_events)),
        "events_ingested": 0, "index_used": index_name, "errors": [],
        "scoring_unit": "scenario", "window_evaluations": 0,
        "timestamp_policy": "preserve_supplied",
    }
    created = False
    try:
        if not isinstance(base_query, str) or not base_query.strip():
            raise ValueError("Empty base query")
        if not threshold_field or type(threshold_value) is not int or threshold_value <= 0:
            raise ValueError("Threshold field and positive integer count are required")
        if cardinality_field is not None or cardinality_value is not None:
            if (not cardinality_field or type(cardinality_value) is not int
                    or cardinality_value <= 0):
                raise ValueError("Cardinality field and positive integer count are required together")
        window_seconds = _parse_window_to_seconds(window)
        event_count = len(attack_events) + len(benign_events)
        if not 0 < event_count <= _MAX_EVENTS:
            raise ValueError(f"Threshold validation requires 1..{_MAX_EVENTS} events")
        bulk_body = _build_threshold_bulk_body(
            index_name, attack_events, benign_events, technique_id, window_seconds
        )
        populations = []
        offset = 0
        for prefix, events in (("atk", attack_events), ("ben", benign_events)):
            endpoints = sorted({_event_time(event.get("@timestamp")) for event in events})
            if len(endpoints) > _MAX_WINDOWS:
                raise ValueError(f"Threshold validation exceeds {_MAX_WINDOWS} windows per population")
            ids = [f"{prefix}-{offset + i}" for i in range(len(events))]
            populations.append((ids, endpoints))
            offset += len(events)

        status, response = _es_request(
            f"{es_url}/{index_name}", method="PUT", auth=es_auth,
            data={"settings": {"number_of_shards": 1, "number_of_replicas": 0,
                               "index.lifecycle.name": "validation-cleanup"}},
        )
        response = _response(status, response, "Index creation")
        created = True
        if response.get("acknowledged") is not True:
            raise ValueError("Index creation was not acknowledged")
        status, response = _es_request(
            f"{es_url}/{index_name}/_bulk", method="POST", data=bulk_body,
            auth=es_auth, content_type="application/x-ndjson", timeout=15,
        )
        response = _response(status, response, "Bulk ingest")
        items = response.get("items", [])
        if response.get("errors") is not False or len(items) != event_count:
            raise ValueError("Bulk ingest failed or did not acknowledge every event")
        expected_ids = [event_id for ids, _ in populations for event_id in ids]
        for item, expected_id in zip(items, expected_ids):
            action = item.get("index", {})
            if (action.get("status") not in (200, 201) or action.get("error")
                    or action.get("_id") != expected_id):
                raise ValueError("Bulk ingest did not successfully index every event")
        result["events_ingested"] = event_count
        status, response = _es_request(f"{es_url}/{index_name}/_refresh", method="POST", auth=es_auth)
        _require_complete_shards(_response(status, response, "Refresh"), "Refresh")

        population_breaches = []
        for ids, endpoints in populations:
            breaches = 0
            for end in endpoints:
                group = {"terms": {"field": threshold_field, "size": _MAX_TERMS}}
                if cardinality_field:
                    group["aggs"] = {"distinct_values": {"terms": {
                        "field": cardinality_field, "size": _MAX_TERMS
                    }}}
                query = {
                    "size": 0,
                    "query": {"bool": {"filter": [
                        {"query_string": {"query": base_query, "default_operator": "AND",
                                          "analyze_wildcard": True}},
                        {"ids": {"values": ids}},
                        {"range": {"@timestamp": {
                            "gte": (end - timedelta(seconds=window_seconds)).isoformat(),
                            "lte": end.isoformat(),
                        }}},
                    ]}},
                    "aggs": {"by_group": group},
                }
                status, response = _es_request(
                    f"{es_url}/{index_name}/_search", method="POST", data=query,
                    auth=es_auth, timeout=15,
                )
                response = _response(status, response, "Aggregation query")
                _require_complete_shards(response, "Aggregation query")
                if response.get("timed_out") is not False or response.get("terminated_early"):
                    raise ValueError("Aggregation query timed out or terminated early")
                buckets = _complete_buckets(response.get("aggregations", {}).get("by_group"))
                for bucket in buckets:
                    distinct_ok = True
                    if cardinality_field:
                        distinct_ok = len(_complete_buckets(bucket.get("distinct_values"))) >= cardinality_value
                    if bucket["doc_count"] >= threshold_value and distinct_ok:
                        breaches += 1
                result["window_evaluations"] += 1
                if breaches:
                    break  # One complete positive window proves this population breaches.
            population_breaches.append(breaches)

        attack_breaches, benign_breaches = population_breaches
        tp = int(bool(attack_events) and attack_breaches > 0)
        fn = int(bool(attack_events) and attack_breaches == 0)
        fp = int(bool(benign_events) and benign_breaches > 0)
        tn = int(bool(benign_events) and benign_breaches == 0)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        result.update({
            "threshold_breaches": attack_breaches + benign_breaches,
            "attack_threshold_breaches": attack_breaches,
            "benign_threshold_breaches": benign_breaches,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "f1_score": round(f1, 4), "fp_rate": fp / (fp + tn) if fp + tn else 0.0,
            "tp_rate": round(recall, 4),
        })
        return result
    except Exception as exc:
        detail = str(exc)
        if isinstance(exc, urllib.error.HTTPError):
            try:
                body = json.loads(exc.read().decode("utf-8", errors="replace"))
                error = body.get("error", {})
                if isinstance(error, dict):
                    detail = error.get("reason") or error.get("root_cause", [{}])[0].get("reason") or detail
            except (ValueError, KeyError, IndexError, TypeError, AttributeError):
                pass
        result["errors"].append(f"Threshold validation failed: {detail}")
        return result
    finally:
        if cleanup and created:
            _cleanup_index(es_url, index_name, es_auth)
