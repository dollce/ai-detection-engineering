"""Refresh selected evidence using Elasticsearch only; never deploy or change requests.

Example: python3 autonomous/orchestration/revalidate_evidence.py \
    --technique T1016 --es-url http://localhost:9200

ES_USER and ES_PASS select credentials (local lab defaults otherwise). Only
complete successful scenario results replace stored evidence. This does not
validate production telemetry, Splunk, Cribl, or scheduled alert execution.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import urlsplit

import yaml

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from orchestration.validation import _es_request, validate_against_elasticsearch
from orchestration.validation_eql import validate_eql_against_elasticsearch
from orchestration.validation_threshold import validate_threshold_against_elasticsearch
from orchestration.validation_results import (
    ValidationUnavailable, read_f1, read_json, require_no_errors, score,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
MIN_F1 = 0.75
MAX_EVENTS = 1000


def _inside(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative.strip():
        raise ValidationUnavailable("Missing input path")
    path = (root / relative.replace("\\", "/")).resolve()
    if not path.is_relative_to(root):
        raise ValidationUnavailable("Input path must be inside the repository")
    if not path.is_file():
        raise ValidationUnavailable(f"Missing input: {path}")
    return path


def _yaml(path: Path) -> dict:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise ValidationUnavailable(f"Cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationUnavailable(f"{path}: expected a YAML mapping")
    return value


def _positive_integer(value, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValidationUnavailable(f"{name} must be a positive integer")
    return value


def _population(scenario: dict, name: str) -> list[dict]:
    events = scenario.get("events", {})
    population = events.get(name) if isinstance(events, dict) else None
    if not isinstance(population, list) or not population:
        raise ValidationUnavailable(f"Missing nonempty scenario events.{name}")
    for event in population:
        if not isinstance(event, dict) or not event or not (any(
            key in event for key in ("@timestamp", "event", "process", "host", "winlog",
                                     "user", "file", "registry", "source", "destination",
                                     "message", "cloud", "network")
        ) or any("." in key for key in event)):
            raise ValidationUnavailable(f"Invalid scenario event in {name}")
    return population


def _hashes(root: Path, inputs: list[Path]) -> dict[str, str]:
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in inputs}


def _check_result(result, rule_type: str, attack_count: int, benign_count: int) -> dict:
    if not isinstance(result, dict):
        raise ValidationUnavailable("Elasticsearch validation unavailable; no local fallback")
    require_no_errors(result)
    if "errors" not in result:
        raise ValidationUnavailable("Validation result is missing errors status")
    expected_method = "elasticsearch" if rule_type == "sigma" else f"elasticsearch_{rule_type}"
    if result.get("validation_method", result.get("method")) != expected_method:
        raise ValidationUnavailable("Validation result has an unexpected execution method")
    unit = "event" if rule_type == "sigma" else "scenario"
    if result.get("scoring_unit", "event" if rule_type == "sigma" else None) != unit:
        raise ValidationUnavailable(f"Expected native {unit} scoring")
    for key in ("tp", "fp", "fn", "tn", "events_ingested"):
        value = result.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValidationUnavailable(f"Missing or invalid validation count: {key}")
    if result["events_ingested"] != attack_count + benign_count:
        raise ValidationUnavailable("Incomplete event ingestion")
    positives, negatives = (attack_count, benign_count) if unit == "event" else (1, 1)
    if result["tp"] + result["fn"] != positives or result["tn"] + result["fp"] != negatives:
        raise ValidationUnavailable("Confusion counts do not cover both complete populations")
    metrics = {key: result[key] for key in ("tp", "fp", "fn", "tn")}
    for key in ("precision", "recall"):
        metrics[key] = score(result.get(key), key)
    metrics["f1_score"] = read_f1(result)
    precision = result["tp"] / (result["tp"] + result["fp"]) if result["tp"] + result["fp"] else 0.0
    recall = result["tp"] / positives
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    for key, expected in (("precision", precision), ("recall", recall), ("f1_score", f1)):
        # Sigma rounds to three decimal places, correlations to four.
        if abs(metrics[key] - expected) > 0.00051:
            raise ValidationUnavailable(f"Validation {key} conflicts with confusion counts")
    metrics.update(fp_rate=round(result["fp"] / negatives, 4), tp_rate=round(recall, 4),
                   total_attack=positives, total_benign=negatives)
    if metrics["f1_score"] < MIN_F1:
        raise ValidationUnavailable(f"F1 {metrics['f1_score']:.4f} below required {MIN_F1}")
    metrics["scoring_unit"] = unit
    return metrics


def _atomic_json(path: Path, record: dict) -> None:
    serialized = json.dumps(record, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=f".{path.name}.", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def revalidate(root: Path, technique: str, es_url: str, output_dir: Path | None = None) -> Path:
    """Run one exact request's native validator and atomically save successful evidence."""
    root = root.resolve()
    if not re.fullmatch(r"T\d{4}(?:[._][A-Z0-9]+)*", technique):
        raise ValidationUnavailable(f"Invalid exact technique ID: {technique}")
    url = urlsplit(es_url)
    if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValidationUnavailable("Provide an explicit HTTP(S) ES URL without embedded credentials, query, or fragment")
    es_url = es_url.rstrip("/")
    request_stem = technique.lower().replace(".", "_")
    request_path = _inside(root, f"autonomous/detection-requests/{request_stem}.yml")
    request = _yaml(request_path)
    if request.get("technique_id") != technique:
        raise ValidationUnavailable("Request technique_id does not match the exact requested ID")
    rule_path = _inside(root, request.get("sigma_rule"))
    rule = _yaml(rule_path)
    rule_type = request.get("rule_type", rule.get("detection_type", "sigma"))
    if rule_type not in {"sigma", "eql", "threshold"}:
        raise ValidationUnavailable(f"Unsupported rule type: {rule_type}")
    scenario_path = _inside(root, request.get("scenario_file"))
    scenario = read_json(scenario_path)
    if not isinstance(scenario, dict):
        raise ValidationUnavailable("Scenario must be an object")
    attack, benign = _population(scenario, "attack_sequence"), _population(scenario, "benign_similar")
    if len(attack) + len(benign) > MAX_EVENTS:
        raise ValidationUnavailable(f"Scenario exceeds the bounded {MAX_EVENTS}-event limit")
    artifact_path = _inside(root, request.get("compiled_lucene" if rule_type == "sigma" else "compiled_artifact"))
    artifact = {} if rule_type == "sigma" else read_json(artifact_path)
    if not isinstance(artifact, dict) or (rule_type != "sigma" and artifact.get("type") != rule_type):
        raise ValidationUnavailable("Compiled artifact type does not match the request")
    expected_language = "eql" if rule_type == "eql" else "lucene"
    if "language" in artifact and artifact["language"] != expected_language:
        raise ValidationUnavailable(f"Compiled {rule_type} language must be {expected_language}")
    query = artifact_path.read_text(encoding="utf-8").strip() if rule_type == "sigma" else artifact.get("query")
    if not isinstance(query, str) or not query.strip():
        raise ValidationUnavailable("Missing compiled query")
    inputs = [request_path, rule_path, scenario_path, artifact_path]
    input_hashes = _hashes(root, inputs)
    auth = (os.environ.get("ES_USER", "elastic"), os.environ.get("ES_PASS", "changeme"))
    kwargs = dict(attack_events=attack, benign_events=benign, technique_id=technique,
                  es_url=es_url, es_auth=auth)
    parameters = {}
    if rule_type == "eql":
        parameters["expected_sequences"] = _positive_integer(rule.get("eql_min_sequences", 1), "expected_sequences")
    elif rule_type == "threshold":
        threshold = artifact.get("threshold")
        if not isinstance(threshold, dict):
            raise ValidationUnavailable("Missing compiled threshold configuration")
        fields = threshold.get("field")
        fields = [fields] if isinstance(fields, str) else fields
        if not isinstance(fields, list) or len(fields) != 1 or not isinstance(fields[0], str) or not fields[0]:
            raise ValidationUnavailable("Native validator requires exactly one threshold group field")
        lookback = artifact.get("from", "")
        if not isinstance(lookback, str) or not re.fullmatch(r"now-[1-9]\d*[smh]", lookback):
            raise ValidationUnavailable("Compiled threshold from must be an explicit now-Ns/m/h lookback")
        parameters = {"threshold_field": fields[0],
                      "threshold_value": _positive_integer(threshold.get("value"), "threshold.value"),
                      "window": lookback.removeprefix("now-")}
        cardinality = threshold.get("cardinality", [])
        if not isinstance(cardinality, list) or len(cardinality) > 1:
            raise ValidationUnavailable("Native validator supports at most one cardinality condition")
        if cardinality:
            entry = cardinality[0]
            if not isinstance(entry, dict) or not isinstance(entry.get("field"), str) or not entry["field"]:
                raise ValidationUnavailable("Invalid cardinality field")
            parameters.update(cardinality_field=entry["field"],
                              cardinality_value=_positive_integer(entry.get("value"), "cardinality.value"))
    status, info = _es_request(es_url, auth=auth, timeout=5)
    version = info.get("version", {}).get("number") if isinstance(info, dict) and isinstance(info.get("version"), dict) else None
    if status != 200 or not isinstance(version, str) or not version:
        raise ValidationUnavailable("Cannot verify Elasticsearch version")
    if rule_type == "sigma":
        result = validate_against_elasticsearch(compiled_lucene=query, ingestion_method="direct", **kwargs)
    elif rule_type == "eql":
        result = validate_eql_against_elasticsearch(eql_query=query, **parameters, **kwargs)
    else:
        result = validate_threshold_against_elasticsearch(base_query=query, **parameters, **kwargs)
    metrics = _check_result(result, rule_type, len(attack), len(benign))
    if _hashes(root, inputs) != input_hashes:
        raise ValidationUnavailable("Input files changed during validation; evidence was not saved")
    record = {
        "technique_id": technique, "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "PASS", "sigma_rule": rule_path.relative_to(root).as_posix(),
        "scenario_path": scenario_path.relative_to(root).as_posix(),
        "compiled_artifact": artifact_path.relative_to(root).as_posix(),
        "validation_method": "elasticsearch" if rule_type == "sigma" else f"elasticsearch_{rule_type}",
        "validated_by": "revalidate-evidence", "quality_tier": "validated",
        "validation_scope": "Scenario validation on Elasticsearch temporary indices only; no Splunk, Cribl, production telemetry, or scheduled-alert validation.",
        "siem_targets": ["elasticsearch"], "elasticsearch_version": version,
        "attack_event_count": len(attack), "benign_event_count": len(benign),
        "scoring_unit": metrics["scoring_unit"], "metrics": metrics,
        "query": query, "query_parameters": parameters, "input_hashes": input_hashes,
        "validation_details": result,
    }
    destination = (output_dir if output_dir is not None else root / "tests/results") / f"{technique.lower().replace('.', '_')}.json"
    _atomic_json(destination, record)
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--technique", action="append", required=True, help="Exact request ID; repeat for multiple requests")
    parser.add_argument("--es-url", required=True, help="Explicit Elasticsearch URL; no service discovery or fallback")
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--output-dir", type=Path, help="Defaults to <repo-root>/tests/results")
    args = parser.parse_args(argv)
    failed = False
    for technique in dict.fromkeys(args.technique):
        try:
            path = revalidate(args.repo_root, technique, args.es_url, args.output_dir)
            print(f"PASS {technique}: {path}")
        except (OSError, ValueError, TypeError) as exc:
            failed = True
            print(f"FAIL {technique}: {exc}; existing evidence preserved", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
