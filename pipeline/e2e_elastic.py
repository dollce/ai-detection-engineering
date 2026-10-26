#!/usr/bin/env python3
"""Bounded Elastic E2E: real compilation, ES matching, scheduled alerts, cleanup.

Use --preflight for read-only checks. Results never update detection lifecycle or
historical validation evidence. All mutable resources have a fresh run prefix.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import datetime as dt
import importlib.metadata
import io
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "autonomous"))
DEFAULT_CASE = REPO_ROOT / "tests/e2e/cases/t1059_003.json"
ALERT_INDEX = ".alerts-security.alerts-default"


class E2EFailure(RuntimeError):
    """A required E2E observation failed or was unavailable."""


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def require(condition, message):
    if not condition:
        raise E2EFailure(message)


def check_endpoint(url, allow_remote=False):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme in {"http", "https"} and parsed.hostname, "Endpoint must be an HTTP(S) URL")
    require(not parsed.username and not parsed.password and not parsed.query and not parsed.fragment,
            "Endpoint must not contain credentials, query parameters, or a fragment")
    require(parsed.path in {"", "/"}, "Use a server root URL (default Kibana space only)")
    try:
        local = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        local = parsed.hostname == "localhost"
    require(local or allow_remote, "Only loopback endpoints are allowed; --allow-remote explicitly opts in")
    return url.rstrip("/")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise E2EFailure("HTTP redirects are not accepted for E2E endpoints")


class Client:
    def __init__(self, es_url, kibana_url, user, password):
        self.es_url, self.kibana_url = es_url, kibana_url
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        # Local lab requests must not use a host's HTTP proxy configuration.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, target, path, method="GET", data=None, missing_ok=False, ndjson=False):
        base = self.es_url if target == "es" else self.kibana_url
        body = data.encode() if isinstance(data, str) else json.dumps(data).encode() if data is not None else None
        headers = {"Authorization": self.auth, "kbn-xsrf": "ade-e2e",
                   "Content-Type": "application/x-ndjson" if ndjson else "application/json"}
        req = urllib.request.Request(base + path, data=body, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=15) as response:
                raw = response.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            if missing_ok and exc.code == 404:
                return None
            # Never include response bodies or authentication headers in errors.
            raise E2EFailure(f"{target} {method} {path}: HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise E2EFailure(f"{target} {method} {path}: connection failed ({type(exc.reason).__name__})") from exc
        except (ValueError, TimeoutError) as exc:
            raise E2EFailure(f"{target} {method} {path}: invalid or incomplete response") from exc


def read_case(path, root=REPO_ROOT):
    manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    require(isinstance(manifest, dict), "Case manifest must be an object")
    for key in ("technique_id", "sigma_rule", "cases"):
        require(key in manifest, f"Case manifest is missing {key}")
    rule = (root / manifest["sigma_rule"]).resolve()
    require(rule.is_relative_to(root.resolve()) and rule.is_file(), "Sigma rule must exist inside the repository")
    cases = manifest["cases"]
    require(isinstance(cases, list) and len(cases) > 1, "At least a positive and a negative case are required")
    ids, loaded = set(), []
    for case in cases:
        require(isinstance(case, dict), "Each case must be an object")
        case_id = case.get("case_id")
        require(isinstance(case_id, str) and case_id and case_id not in ids, "Case IDs must be unique nonempty strings")
        require(type(case.get("expected_alert")) is bool, f"{case_id}: expected_alert must be explicit boolean")
        source = (root / case.get("fixture", "")).resolve()
        require(source.is_relative_to(root.resolve()) and source.is_file(), f"{case_id}: fixture must exist inside repository")
        events = json.loads(source.read_text(encoding="utf-8"))
        offset = case.get("event_index")
        require(isinstance(events, list) and type(offset) is int and 0 <= offset < len(events),
                f"{case_id}: invalid fixture event_index")
        require(isinstance(events[offset], dict) and events[offset], f"{case_id}: empty or invalid event")
        ids.add(case_id)
        loaded.append({**case, "event": events[offset]})
    require(any(c["expected_alert"] for c in loaded) and any(not c["expected_alert"] for c in loaded),
            "Both positive and negative cases are required")
    return manifest, rule, loaded


def replay_cases(cases, run_id, timestamp=None):
    """Copy fixture objects; replace stale/placeholder timestamps explicitly."""
    timestamp = timestamp or utc_now()
    replayed = []
    for case in cases:
        event = copy.deepcopy(case["event"])
        event["@timestamp"] = timestamp
        event.setdefault("event", {})["id"] = f"{run_id}:{case['case_id']}"
        event.setdefault("labels", {}).update(ade_e2e_run=run_id, ade_e2e_case=case["case_id"])
        replayed.append({**case, "event": event})
    return replayed


def compile_rule(rule):
    command = ["sigma", "convert", "-t", "lucene", "-p", "ecs_windows", str(rule)]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60, cwd=REPO_ROOT)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise E2EFailure(f"Sigma compiler unavailable or timed out: {type(exc).__name__}") from exc
    require(result.returncode == 0, f"Sigma compilation failed (exit {result.returncode})")
    from orchestration.constants import normalize_lucene_output
    normalized = normalize_lucene_output(result.stdout)
    lines = [line.strip() for line in normalized.splitlines() if line.strip()]
    require(len(lines) == 1, "Sigma must produce exactly one nonempty Lucene query")
    query = lines[0]
    require(not query.startswith(("Error", "Usage:", "Warning")), "Sigma did not produce a query")
    return {"command": command, "returncode": result.returncode,
            "raw_output": result.stdout, "query": query,
            "normalization": "orchestration.constants.normalize_lucene_output"}


def template_payload(prefix):
    return {
        "index_patterns": [prefix + "-*"], "priority": 1000,
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "dynamic_templates": [{"strings_as_keywords": {
                    "match_mapping_type": "string", "mapping": {"type": "keyword"}}}],
                "properties": {
                    "@timestamp": {"type": "date"},
                    "process": {"properties": {
                        "command_line": {"type": "keyword"}, "executable": {"type": "keyword"},
                        "parent": {"properties": {"executable": {"type": "keyword"}}}}},
                    "labels": {"properties": {"ade_e2e_run": {"type": "keyword"},
                                                "ade_e2e_case": {"type": "keyword"}}},
                },
            },
        },
        "_meta": {"purpose": "isolated E2E smoke", "run_prefix": prefix},
    }


def validate_metrics(result, positives, negatives, prefix):
    require(isinstance(result, dict), "Real Elasticsearch validation did not run")
    require(result.get("method") == "elasticsearch" and result.get("ingestion_method") == "direct",
            "Expected direct Elasticsearch validation; fallback is not an E2E pass")
    require(result.get("errors") == [] and not result.get("error"), "Elasticsearch validation reported errors")
    expected = {"tp": positives, "fp": 0, "fn": 0, "tn": negatives,
                "total_attack": positives, "total_benign": negatives,
                "events_ingested": positives + negatives, "query_hits": positives}
    for name, value in expected.items():
        require(type(result.get(name)) is int and result[name] == value,
                f"Elasticsearch validation {name}: expected {value}, got {result.get(name)!r}")
    require(type(result.get("f1_score")) in {int, float} and result["f1_score"] == 1.0,
            "Fixture query validation must have numeric F1=1.0")
    require(str(result.get("index_used", "")).startswith(prefix + "-"), "Validation index escaped this run's scope")
    return result


def checked_hits(response):
    require(isinstance(response, dict) and response.get("timed_out") is False, "Search missing completion evidence or timed out")
    shards = response.get("_shards", {})
    require(type(shards.get("failed")) is int and shards["failed"] == 0, "Search has missing or failed shard evidence")
    hits = response.get("hits", {})
    total = hits.get("total", {})
    require(isinstance(total, dict) and total.get("relation") == "eq" and type(total.get("value")) is int,
            "Search total is missing or incomplete")
    rows = hits.get("hits")
    require(isinstance(rows, list) and total["value"] == len(rows), "Search response omitted or truncated hits")
    return rows


def field(source, path):
    if path in source:
        return source[path]
    value = source
    for segment in path.split("."):
        if not isinstance(value, dict) or segment not in value:
            return None
        value = value[segment]
    return value


def verify_rule(rule, rule_id, index, query):
    require(isinstance(rule, dict) and rule.get("rule_id") == rule_id, "Deployed rule identity is missing or wrong")
    require(rule.get("enabled") is True and rule.get("index") == [index], "Deployed rule is disabled or has unexpected scope")
    require(rule.get("query") == query and rule.get("language") == "lucene" and rule.get("type") == "query",
            "Deployed rule query differs from the compiled query")
    require(rule.get("interval") == "1m" and rule.get("from") == "now-10m", "Unexpected scheduler interval or lookback")
    return rule


def execution_succeeded(rule, earliest):
    execution = rule.get("execution_summary", {}).get("last_execution", {})
    status = execution.get("status")
    require(status not in {"failed", "partial failure"}, f"Rule scheduler reported {status}: {execution.get('message', '')}")
    if status != "succeeded":
        return False
    try:
        actual = dt.datetime.fromisoformat(execution["date"].replace("Z", "+00:00"))
        minimum = dt.datetime.fromisoformat(earliest.replace("Z", "+00:00"))
    except (KeyError, ValueError, TypeError):
        raise E2EFailure("Successful scheduler status has no valid execution timestamp")
    require(actual.tzinfo is not None, "Scheduler execution time must include timezone")
    return actual >= minimum


def verify_alerts(rows, cases, rule_id, source_index, run_id):
    known = {case["case_id"]: case["expected_alert"] for case in cases}
    observed = []
    evidence = []
    for row in rows:
        source = row.get("_source", {})
        require(field(source, "kibana.alert.rule.rule_id") == rule_id, "Alert has wrong or missing rule identity")
        execution_type = field(source, "kibana.alert.rule.execution.type")
        require(execution_type == "scheduled", f"Alert was not created by a scheduled execution: {execution_type!r}")
        execution_uuid = field(source, "kibana.alert.rule.execution.uuid")
        require(isinstance(execution_uuid, str) and execution_uuid,
                "Scheduled alert has no execution UUID")
        ancestors = field(source, "kibana.alert.ancestors")
        require(isinstance(ancestors, list), "Alert is missing source-event ancestry")
        original = [ancestor for ancestor in ancestors if ancestor.get("index") == source_index]
        require(len(original) == 1, "Alert cannot be linked to exactly one source event in this run")
        case_id = original[0].get("id")
        require(case_id in known and known[case_id], f"Unexpected alert for case {case_id!r}")
        # The exact source index and unique rule_id bind this ancestry to run_id,
        # even if Kibana does not copy an arbitrary custom label to the alert.
        require(source_index.startswith("ade-e2e-" + run_id + "-"), "Alert index is outside this run")
        label = field(source, "labels.ade_e2e_run")
        require(label is None or label == run_id, "Alert carries another run's label")
        observed.append(case_id)
        evidence.append({"alert_id": row.get("_id"), "alert_index": row.get("_index"),
                         "rule_id": rule_id, "run_id": run_id, "case_id": case_id,
                         "source_index": source_index, "ancestors": ancestors,
                         "execution_type": execution_type, "execution_uuid": execution_uuid})
    require(len(observed) == len(set(observed)), "Duplicate alerts for the same source case")
    require(len({item["execution_uuid"] for item in evidence}) <= 1,
            "Expected alerts came from different scheduler executions")
    expected = {case_id for case_id, should_alert in known.items() if should_alert}
    return set(observed) == expected, evidence


def alert_query(rule_id):
    return {"term": {"kibana.alert.rule.rule_id": rule_id}}


def search_alerts(client, rule_id):
    response = client.request("es", f"/{ALERT_INDEX}/_search", "POST", {
        "query": alert_query(rule_id), "size": 100, "track_total_hits": True}, missing_ok=True)
    return [] if response is None else checked_hits(response)


def owned_indices(client, prefix):
    response = client.request("es", f"/_resolve/index/{prefix}-*?expand_wildcards=all")
    require(isinstance(response, dict) and isinstance(response.get("indices"), list), "Cannot enumerate owned indices")
    names = [entry["name"] for entry in response["indices"]]
    require(all(name.startswith(prefix + "-") for name in names), "Index discovery escaped this run's scope")
    return names


def cleanup(client, prefix, rule_id, template_name):
    """Attempt all cleanup operations; absence is verified, not presumed."""
    errors, evidence = [], {}
    def attempt(label, action):
        try:
            evidence[label] = action()
        except Exception as exc:
            errors.append(f"{label}: {exc}")
    rule_path = "/api/detection_engine/rules?" + urllib.parse.urlencode({"rule_id": rule_id})
    attempt("delete_rule", lambda: client.request("kibana", rule_path, "DELETE", missing_ok=True))
    def remove_indices():
        names = owned_indices(client, prefix)
        for name in names:
            client.request("es", "/" + urllib.parse.quote(name, safe=""), "DELETE", missing_ok=True)
        require(owned_indices(client, prefix) == [], "Run indices remain after deletion")
        return {"deleted": names, "remaining": []}
    attempt("indices", remove_indices)
    def remove_alerts():
        response = client.request("es", f"/{ALERT_INDEX}/_delete_by_query?refresh=true", "POST",
                                  {"query": alert_query(rule_id)}, missing_ok=True)
        if response is not None:
            require(response.get("timed_out") is False and response.get("failures") == [],
                    "Alert deletion was incomplete")
            require(response.get("version_conflicts", 0) == 0, "Alert deletion had version conflicts")
        require(search_alerts(client, rule_id) == [], "Run alerts remain after deletion")
        return {"deleted": response.get("deleted", 0) if response else 0, "remaining": 0}
    attempt("alerts", remove_alerts)
    attempt("delete_template", lambda: client.request("es", f"/_index_template/{template_name}", "DELETE", missing_ok=True))
    def absent(target, path):
        require(client.request(target, path, missing_ok=True) is None, f"Resource still exists: {path}")
        return True
    attempt("rule_absent", lambda: absent("kibana", rule_path))
    attempt("template_absent", lambda: absent("es", f"/_index_template/{template_name}"))
    return {"status": "FAIL" if errors else "PASS", "errors": errors, "evidence": evidence}


def preflight(client, case_path):
    manifest, rule, cases = read_case(case_path)
    require(shutil.which("sigma") is not None, "sigma CLI is not installed on PATH")
    es = client.request("es", "/")
    health = client.request("es", "/_cluster/health")
    kibana = client.request("kibana", "/api/status")
    require(health.get("status") in {"green", "yellow"} and health.get("timed_out") is False,
            "Elasticsearch is not healthy")
    require(kibana.get("status", {}).get("overall", {}).get("level") == "available", "Kibana is not available")
    versions = {"python": sys.version.split()[0], "elasticsearch": es.get("version", {}).get("number"),
                "kibana": kibana.get("version", {}).get("number")}
    for package in ("sigma-cli", "pySigma", "pySigma-backend-elasticsearch", "pySigma-pipeline-windows"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = "unavailable"
    require(versions["elasticsearch"] and versions["kibana"], "Service version evidence is missing")
    return {"versions": versions, "cluster_health": health["status"],
            "technique_id": manifest["technique_id"], "rule": str(rule), "case_count": len(cases)}


def run(args):
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S").lower() + "-" + uuid.uuid4().hex[:10]
    prefix, rule_id = "ade-e2e-" + run_id, "ade-e2e-" + run_id
    index, template_name = prefix + "-events", prefix + "-template"
    client = Client(args.es_url, args.kibana_url, args.user, args.password)
    report = {
        "schema_version": 1, "run_id": run_id, "status": "FAIL", "started_at": utc_now(),
        "scope": {"es_url": args.es_url, "kibana_url": args.kibana_url,
                  "index_prefix": prefix, "rule_id": rule_id, "case_manifest": str(args.case)},
        "stages": {name: {"status": "NOT_RUN"} for name in (
            "preflight", "compile", "template", "query_validation", "replay", "deploy", "scheduled_alerts", "cleanup")},
        "proof_limits": [
            "This runner replays supplied JSON events; their source and any adversary execution require separate evidence.",
            "Elastic direct ingest only; no Cribl, Splunk, or LLM authoring coverage in this runner.",
            "A successful scheduled execution and exact alert ancestry establish this bounded case only.",
            "Fixture timestamps and run/case metadata are updated in memory; original detection fields stay unchanged.",
            "Lucene output uses the shared project normalization for the lab ECS contract.",
            "Kibana internal execution/audit history is retained; created rules, alerts, indices, and template are removed.",
        ],
    }
    current_stage, resources_attempted = "preflight", False
    def stage(name, operation):
        nonlocal current_stage
        current_stage = name
        report["stages"][name] = {"status": "RUNNING", "started_at": utc_now()}
        evidence = operation()
        report["stages"][name].update(status="PASS", finished_at=utc_now(), evidence=evidence)
        print(f"[{name}] PASS", flush=True)
        return evidence
    try:
        stage("preflight", lambda: preflight(client, args.case))
        manifest, rule_path, original_cases = read_case(args.case)
        compilation = stage("compile", lambda: compile_rule(rule_path))
        query = compilation["query"]
        cases = replay_cases(original_cases, run_id)
        expected = {case["case_id"]: case["expected_alert"] for case in cases}
        report["cases"] = [{key: value for key, value in case.items() if key != "event"} for case in cases]
        report["input_sha256"] = {str(path.relative_to(REPO_ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in {rule_path, *(REPO_ROOT / case["fixture"] for case in cases)}}
        resources_attempted = True
        def install_template():
            response = client.request("es", f"/_index_template/{template_name}", "PUT", template_payload(prefix))
            require(response.get("acknowledged") is True, "Run template creation was not acknowledged")
            return {"name": template_name, "index_patterns": [prefix + "-*"], "acknowledged": True}
        stage("template", install_template)
        def validate():
            from orchestration.validation import validate_against_elasticsearch
            positives = [case["event"] for case in cases if case["expected_alert"]]
            negatives = [case["event"] for case in cases if not case["expected_alert"]]
            result = validate_against_elasticsearch(query, positives, negatives,
                technique_id=manifest["technique_id"], es_url=args.es_url, es_auth=(args.user, args.password),
                index_prefix=prefix + "-validation", ingestion_method="direct")
            validate_metrics(result, len(positives), len(negatives), prefix)
            require(client.request("es", "/" + result["index_used"], missing_ok=True) is None,
                    "Existing validator did not remove its temporary index")
            return result
        stage("query_validation", validate)
        # Fresh replay times keep the scheduled test inside its lookback even if compilation/validation is slow.
        cases = replay_cases(original_cases, run_id)
        replay_started = cases[0]["event"]["@timestamp"]
        def ingest():
            created = client.request("es", "/" + index, "PUT", {})
            require(created.get("acknowledged") is True, "Source index creation was not acknowledged")
            lines = []
            for case in cases:
                lines += [json.dumps({"index": {"_index": index, "_id": case["case_id"]}}), json.dumps(case["event"])]
            response = client.request("es", "/_bulk?refresh=wait_for", "POST", "\n".join(lines) + "\n", ndjson=True)
            require(response.get("errors") is False and len(response.get("items", [])) == len(cases),
                    "Bulk ingest failed or omitted acknowledgements")
            for item in response["items"]:
                require(item.get("index", {}).get("status") in {200, 201} and not item["index"].get("error"), "Bulk item failed")
            count = client.request("es", f"/{index}/_count")
            require(type(count.get("count")) is int and count["count"] == len(cases), "Actual ingest count differs from input")
            require(count.get("_shards", {}).get("failed") == 0, "Ingest count has missing or failed shard evidence")
            rows = checked_hits(client.request("es", f"/{index}/_search", "POST",
                {"query": {"match_all": {}}, "size": len(cases) + 1, "track_total_hits": True}))
            require({row["_id"] for row in rows} == set(expected), "Ingested source IDs differ from cases")
            for row in rows:
                require(field(row["_source"], "labels.ade_e2e_run") == run_id, "Source event lost run ID")
                require(row["_source"].get("@timestamp") == replay_started, "Source event has stale timestamp")
            mapping = client.request("es", f"/{index}/_mapping")
            require(mapping[index]["mappings"]["properties"]["process"]["properties"]["command_line"]["type"] == "keyword",
                    "process.command_line must be mapped as keyword")
            return {"index": index, "count": count["count"], "case_ids": sorted(expected),
                    "timestamp": replay_started, "process_command_line_type": "keyword"}
        stage("replay", ingest)
        payload = {"rule_id": rule_id, "name": "E2E " + run_id,
                   "description": "Disposable " + str(manifest["technique_id"]) + " E2E smoke",
                   "type": "query", "language": "lucene", "query": query, "index": [index],
                   "severity": "low", "risk_score": 21, "interval": "1m", "from": "now-10m", "to": "now",
                   "enabled": True, "max_signals": 100, "tags": ["ade-e2e", run_id], "actions": []}
        def deploy():
            from orchestration import siem
            import yaml
            with tempfile.TemporaryDirectory(prefix="ade-e2e-config-") as directory:
                config_path = Path(directory) / "config.yml"
                config_path.write_text(yaml.safe_dump({"infrastructure": {
                    "elasticsearch": {"url": args.es_url, "user": args.user, "pass": args.password},
                    "kibana": {"url": args.kibana_url}}}), encoding="utf-8")
                config_path.chmod(0o600)
                old_config = siem.CONFIG_PATH
                try:
                    siem.CONFIG_PATH = config_path
                    # Shared deploy helper prints responses; keep them out of report/logs.
                    with contextlib.redirect_stdout(io.StringIO()):
                        result = siem.deploy_elastic_payload({"technique_id": manifest["technique_id"]}, payload)
                finally:
                    siem.CONFIG_PATH = old_config
            require(isinstance(result, dict) and result.get("rule_id") == rule_id and result.get("elastic_id"),
                    "Existing deployment helper did not confirm rule creation")
            actual = client.request("kibana", "/api/detection_engine/rules?rule_id=" + rule_id)
            verify_rule(actual, rule_id, index, query)
            return {"rule_id": rule_id, "elastic_id": result["elastic_id"], "enabled": actual["enabled"],
                    "index": actual["index"], "query": actual["query"], "interval": actual["interval"]}
        stage("deploy", deploy)
        def wait_for_alerts():
            deadline = time.monotonic() + args.timeout
            last_execution, observed = {}, []
            while time.monotonic() < deadline:
                actual = client.request("kibana", "/api/detection_engine/rules?rule_id=" + rule_id)
                verify_rule(actual, rule_id, index, query)
                completed = execution_succeeded(actual, replay_started)
                last_execution = actual.get("execution_summary", {}).get("last_execution", {})
                rows = search_alerts(client, rule_id)
                all_expected, observed = verify_alerts(rows, cases, rule_id, index, run_id)
                report["stages"]["scheduled_alerts"]["last_observation"] = {
                    "execution": last_execution, "alerts": observed, "observed_at": utc_now()}
                if completed and all_expected:
                    return {"execution": last_execution, "alerts": observed, "alert_count": len(observed),
                            "expected_positive_count": sum(expected.values()),
                            "negative_alert_count": 0, "timeout_seconds": args.timeout}
                time.sleep(min(args.poll_interval, max(0, deadline - time.monotonic())))
            raise E2EFailure(f"No complete scheduler and alert evidence within {args.timeout}s; observed {len(observed)} alerts")
        stage("scheduled_alerts", wait_for_alerts)
        report["status"] = "PASS"
    except (Exception, KeyboardInterrupt) as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
        report["stages"].setdefault(current_stage, {}).update(status="FAIL", error=report["error"], finished_at=utc_now())
    finally:
        if resources_attempted:
            try:
                report["stages"]["cleanup"] = cleanup(client, prefix, rule_id, template_name)
            except Exception as exc:
                report["stages"]["cleanup"] = {"status": "FAIL", "errors": [f"Cleanup crashed: {exc}"]}
            if report["stages"]["cleanup"]["status"] != "PASS":
                report["status"] = "FAIL"
        else:
            report["stages"]["cleanup"] = {"status": "NOT_APPLICABLE", "reason": "No resource mutation attempted"}
        report["finished_at"] = utc_now()
    return report


def redact(value, secrets):
    if isinstance(value, dict):
        return {key: redact(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item, secrets) for item in value]
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[REDACTED]")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--es-url", default=os.environ.get("E2E_ES_URL", "http://127.0.0.1:19200"))
    parser.add_argument("--kibana-url", default=os.environ.get("E2E_KIBANA_URL", "http://127.0.0.1:15601"))
    parser.add_argument("--user", default=os.environ.get("E2E_ES_USER", os.environ.get("ES_USER", "elastic")))
    parser.add_argument("--password", default=os.environ.get("E2E_ES_PASSWORD", os.environ.get("ES_PASS", "")),
                        help="Prefer E2E_ES_PASSWORD to avoid exposing a password in shell history")
    parser.add_argument("--case", type=Path, default=DEFAULT_CASE)
    parser.add_argument("--report", type=Path, default=None, help="JSON output; default /tmp/ade-e2e-<run-id>.json")
    parser.add_argument("--timeout", type=int, default=240, help="Maximum scheduled-alert wait in seconds")
    parser.add_argument("--poll-interval", type=float, default=5)
    parser.add_argument("--preflight", action="store_true", help="GET-only readiness checks; no resources or files are written")
    parser.add_argument("--allow-remote", action="store_true", help="Explicitly allow non-loopback lab servers")
    args = parser.parse_args(argv)
    try:
        args.es_url = check_endpoint(args.es_url, args.allow_remote)
        args.kibana_url = check_endpoint(args.kibana_url, args.allow_remote)
        require(args.password, "Set E2E_ES_PASSWORD or provide --password")
        require(1 <= args.timeout <= 900 and 0 < args.poll_interval <= 30, "Timeout must be 1..900s; poll interval must be >0 and <=30s")
        if args.report:
            destination = args.report.resolve()
            require(not destination.is_relative_to((REPO_ROOT / "tests/results").resolve()), "Historical tests/results must not be overwritten")
            require(not destination.exists(), "Report path already exists; use a fresh path")
        if args.preflight:
            evidence = preflight(Client(args.es_url, args.kibana_url, args.user, args.password), args.case)
            print(json.dumps({"status": "READY", "mode": "read_only_preflight", "evidence": evidence}, indent=2))
            return 0
        report = run(args)
        report = redact(report, [args.password, base64.b64encode(f"{args.user}:{args.password}".encode()).decode()])
        output = args.report or Path(tempfile.gettempdir()) / f"ade-e2e-{report['run_id']}.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive creation avoids replacing any previously recorded evidence.
        with output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        print(f"E2E {report['status']}: {output}")
        if report.get("error"):
            print(report["error"], file=sys.stderr)
        return 0 if report["status"] == "PASS" else 1
    except (Exception, KeyboardInterrupt) as exc:
        print(redact(f"E2E preflight/configuration failure: {exc}", [args.password]), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
