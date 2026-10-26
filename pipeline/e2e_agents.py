#!/usr/bin/env python3
"""Live, bounded Codex scenario -> Sigma -> Elastic scheduled-alert E2E.

The real Red Team reasoning entry point and author adapter are exercised. This
smoke does not run the coordinator, mutate lifecycle records, or open Git PRs.
There are exactly two reasoning calls and no deterministic or existing-rule
fallback. --preflight checks login and SIEM readiness without generating files.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "autonomous"))
from orchestration import codex_llm
from orchestration.agents import red_team_agent

TECHNIQUE = "T1059.003"
HOLDOUT = REPO_ROOT / "tests/e2e/cases/t1059_003.json"
ELASTIC_STAGES = ("preflight", "compile", "template", "query_validation", "replay", "deploy", "scheduled_alerts", "cleanup")
AGENT_STAGES = ("preflight", "scenario_generation", "sigma_generation", "case_assembly", "elastic_e2e")
SCENARIO_CONTRACT = """
Additional E2E contract for this single-event Windows Command Shell detector:
- Generate 2-3 independent, positive Sysmon process-create events in attack_events.
  Every positive event must be cmd.exe itself (not an earlier parent/context event).
  Include chained discovery through cmd.exe and cmd.exe running a download utility
  from an unusual user-writable parent. Vary names and arguments; do not use IOCs
  as the intended detection logic. These are inert JSON records, never commands
  to execute. Use example.invalid or documentation IP ranges for network examples.
- Generate 1-2 similar benign cmd.exe process-create events from ordinary installed
  IT tools or Explorer. Ordinary diagnostics and drive mapping should not alert.
- Each event MUST contain nested event.code "1", event.category "process", process
  (name, executable, command_line, parent.name, parent.executable), and _simulation
  with expected_alert (JSON boolean), type (attack or benign_similar), technique
  "T1059.003", and a nonempty description explaining its expected classification.
- Set expected_alert true only for primitive attack events, false for benign ones.
  Do not put contextual parent creation into attack_events.
- Keep the existing top-level JSON contract. Return raw JSON without code fences.
"""
AUTHOR_LESSONS = [
    "Detect observable Windows Command Shell behavior using ECS process fields, not exact sample names or IOCs.",
    "Cover chained reconnaissance and cmd.exe launching download utilities from an unusual user-writable parent. Ordinary IT diagnostics and network-drive mapping are benign.",
    "Every supplied positive is a primitive process event; a non-cmd parent/context event alone must not trigger.",
    "Do not reference _simulation, labels, event.id, timestamps, host names, usernames, or process IDs in detection logic. These are test annotations or incidental identifiers.",
    "Use Sigma ecs_windows-compatible ECS fields. Include id, title, description, author, date, references, logsource, tags, detection, falsepositives, and level. Return raw YAML without fences.",
]


class AgentE2EFailure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise AgentE2EFailure(message)


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def digest(content):
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def save(path, data):
    """Never overwrite an earlier run's evidence."""
    text = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    with Path(path).open("x", encoding="utf-8") as stream:
        stream.write(text)
    return digest(text)


def failure_category(result):
    """Keep CLI diagnostics (which may contain private paths) out of artifacts."""
    error = str(result.get("error") or "").lower()
    if "timed out" in error:
        return "timeout"
    if "invalid json" in error:
        return "invalid_json"
    if "no final response" in error:
        return "empty_response"
    return "adapter_failure"


@contextlib.contextmanager
def capture_reasoning(directory, calls, timeout_override=None):
    """Instrument the actual adapter in this standalone, single-threaded process.

    The wrapper calls the original ask and preserves its restrictive tool policy.
    There is no mock response, fallback, or retry path in the live runner.
    """
    original = codex_llm.ask

    def recorded(**kwargs):
        require(len(calls) < 2, "Reasoning request budget of two calls exceeded")
        require(kwargs.get("allowed_tools") == [], "E2E reasoning must not enable tools")
        agent = kwargs.get("agent_name")
        require(agent == ("red-team" if not calls else "author"), "Unexpected reasoning stage")
        if agent == "red-team":
            kwargs["prompt"] += "\n\n" + SCENARIO_CONTRACT
        if timeout_override is not None:
            kwargs["timeout_seconds"] = timeout_override
        prefix = f"{len(calls) + 1:02d}-{agent}"
        request = {key: kwargs.get(key) for key in (
            "agent_name", "prompt", "system_prompt", "allowed_tools", "max_turns", "timeout_seconds"
        )}
        request_hash = save(directory / f"{prefix}-request.json", request)
        record = {"agent": agent, "status": "RUNNING", "started_at": utc_now(),
                  "timeout_seconds": kwargs["timeout_seconds"], "request_sha256": request_hash,
                  "request_artifact": f"llm/{prefix}-request.json", "retry": False}
        calls.append(record)
        start = time.monotonic()
        try:
            result = original(**kwargs)
            require(isinstance(result, dict), "Adapter returned a non-object result")
            response = result.get("response")
            if not isinstance(response, str):
                response = ""
            record.update(model_selection=result.get("model", "default"),
                          response_sha256=digest(response), response_bytes=len(response.encode()),
                          response_artifact=f"llm/{prefix}-response.txt")
            save(directory / f"{prefix}-response.txt", response)
            valid = result.get("success") is True and bool(response.strip())
            record["status"] = "PASS" if valid else "FAIL"
            if not valid:
                record["failure_category"] = failure_category(result)
                raise AgentE2EFailure(f"{agent} reasoning failed ({record['failure_category']})")
            return result
        except (Exception, KeyboardInterrupt):
            record["status"] = "FAIL"
            raise
        finally:
            record.update(latency_seconds=round(time.monotonic() - start, 3), finished_at=utc_now())

    codex_llm.ask = recorded
    try:
        yield
    finally:
        codex_llm.ask = original


def validate_scenario(result):
    require(isinstance(result, tuple) and len(result) == 3, "Scenario generation returned no usable result")
    attack, benign, metadata = result
    require(isinstance(metadata, dict) and metadata.get("generated_by") == "codex", "Scenario was not generated by Codex")
    for group, events, minimum, maximum, expected in (
        ("attack", attack, 2, 3, True), ("benign", benign, 1, 2, False),
    ):
        require(isinstance(events, list) and minimum <= len(events) <= maximum, f"Invalid {group} event count")
        for event in events:
            require(isinstance(event, dict), f"Invalid {group} event object")
            process, info, label = event.get("process"), event.get("event"), event.get("_simulation")
            require(isinstance(process, dict) and isinstance(info, dict) and isinstance(label, dict),
                    "Scenario requires process, event and explicit _simulation expectations")
            require(info.get("code") == "1" and info.get("category") == "process", "Scenario is not a primitive process-create event")
            require(str(process.get("name", "")).lower() == "cmd.exe", "Context events cannot be assumed positive")
            require(all(isinstance(process.get(key), str) and process[key].strip() for key in ("command_line", "executable")),
                    "Scenario lacks observable process fields")
            parent = process.get("parent")
            require(isinstance(parent, dict) and all(isinstance(parent.get(key), str) and parent[key].strip()
                    for key in ("name", "executable")), "Scenario lacks observable parent fields")
            require(type(label.get("expected_alert")) is bool and label["expected_alert"] is expected,
                    "Scenario expectations must be explicit booleans consistent with their group")
            require(label.get("technique") == TECHNIQUE and label.get("type") == ("attack" if expected else "benign_similar"),
                    "Scenario label has the wrong technique or role")
            require(isinstance(label.get("description"), str) and label["description"].strip(), "Scenario needs expectation rationale")
    return attack, benign, metadata


def validate_rule(result, existing_rule):
    require(isinstance(result, dict) and result.get("success") is True, "Author reasoning failed")
    text = result.get("sigma_yaml")
    require(isinstance(text, str) and text.strip(), "Author returned no Sigma YAML")
    try:
        rule = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise AgentE2EFailure("Author returned malformed YAML") from exc
    require(isinstance(rule, dict), "Author returned a non-object Sigma rule")
    for key in ("id", "title", "description", "author", "date", "status", "references", "tags", "detection", "logsource", "falsepositives", "level"):
        require(bool(rule.get(key)), f"Sigma metadata missing: {key}")
    require(isinstance(rule["detection"], dict) and isinstance(rule["detection"].get("condition"), str)
            and rule["detection"]["condition"].strip(), "Sigma detection condition missing")
    require(isinstance(rule["logsource"], dict) and rule["logsource"].get("category") == "process_creation"
            and rule["logsource"].get("product") == "windows", "Sigma logsource does not match the scenario")
    require(isinstance(rule["tags"], list) and "attack.t1059.003" in rule["tags"], "Sigma technique mapping missing")
    def check_fields(value):
        if isinstance(value, dict):
            for key, item in value.items():
                field = str(key).split("|")[0]
                require(not field.startswith(("_simulation", "labels", "@timestamp")) and field not in
                        {"event.id", "host.name", "user.name", "process.pid", "process.parent.pid"},
                        "Sigma uses test labels or incidental identifiers")
                check_fields(item)
        elif isinstance(value, list):
            for item in value:
                check_fields(item)
    check_fields(rule["detection"])
    require(digest(text.strip()) != digest(existing_rule.read_text(encoding="utf-8").strip()),
            "Generated rule is an exact copy of the existing rule")
    return text


def elastic_command(args, case=None, report=None):
    command = [sys.executable, str(REPO_ROOT / "pipeline/e2e_elastic.py"),
               "--es-url", args.es_url, "--kibana-url", args.kibana_url,
               "--timeout", str(args.timeout), "--poll-interval", str(args.poll_interval)]
    if args.allow_remote:
        command.append("--allow-remote")
    if case is None:
        command.append("--preflight")
    else:
        command += ["--case", str(case), "--report", str(report)]
    return command


def run_elastic(args, case=None, report=None):
    # Authentication stays in environment variables, never argv or report files.
    completed = subprocess.run(elastic_command(args, case, report), capture_output=True, text=True, cwd=REPO_ROOT)
    if case is None:
        require(completed.returncode == 0, "Elastic preflight failed; run pipeline/e2e_elastic.py --preflight for details")
        return {"status": "PASS"}
    require(report.is_file(), "Elastic runner returned no evidence report")
    result = json.loads(report.read_text(encoding="utf-8"))
    require(isinstance(result, dict), "Elastic report is not an object")
    result["process_exit_code"] = completed.returncode
    return result


def codex_version():
    cli = codex_llm._find_codex_cli()
    require(cli is not None, "Codex CLI unavailable")
    completed = subprocess.run([cli, "--version"], capture_output=True, text=True, timeout=10)
    version = completed.stdout.strip()
    require(completed.returncode == 0 and version.startswith("codex-cli ") and len(version) < 120,
            "Codex CLI version evidence unavailable")
    return version


def preflight(args):
    require(codex_llm.is_available(), "Codex CLI login unavailable; live reasoning cannot run")
    version = codex_version()
    run_elastic(args)
    return {"codex_login": "PASS", "codex_cli_version": version, "elastic_readiness": "PASS", "reasoning_calls": 0}


def run(args):
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S").lower() + "-" + uuid.uuid4().hex[:10]
    directory = (args.output_dir or REPO_ROOT / "artifacts/e2e" / run_id).resolve()
    require(directory.is_relative_to((REPO_ROOT / "artifacts/e2e").resolve()), "Evidence directory must be below artifacts/e2e")
    directory.mkdir(parents=True, exist_ok=False)
    llm_dir = directory / "llm"
    llm_dir.mkdir()
    report = {"schema_version": 1, "run_id": run_id, "status": "FAIL", "started_at": utc_now(),
              "scope": "Live Red Team reasoning + author adapter + real Elastic scheduled alerts",
              "reasoning_call_limit": 2, "automatic_retries": 0, "calls": [],
              "stages": {name: {"status": "NOT_RUN"} for name in AGENT_STAGES},
              "model_evidence": "model_selection records the requested adapter model or CLI default; provider-resolved model is not observed",
              "proof_limits": ["Synthetic fixture smoke, not live endpoint telemetry or production accuracy.",
                               "Coordinator, Git/PR workflow, lifecycle transitions, Cribl and Splunk are outside this run.",
                               "Fixed holdout events are not sent to either model; both holdout and generated cases must pass."]}
    boundary = "preflight"
    try:
        report["stages"][boundary] = {"status": "PASS", **preflight(args)}
        request_source = REPO_ROOT / "autonomous/detection-requests/t1059_003.yml"
        source = yaml.safe_load(request_source.read_text(encoding="utf-8"))
        request = {"technique_id": TECHNIQUE, "title": source["title"], "mitre_tactic": "execution",
                   "source": "Bounded synthetic Windows Command Shell behavioral detection exercise"}
        save(llm_dir / "detection-request.json", request)
        report["request_source_sha256"] = digest(request_source.read_bytes())
        report["entry_points"] = ["red_team_agent.generate_scenario_with_codex", "codex_llm.ask_for_sigma_rule"]
        with capture_reasoning(llm_dir, report["calls"], args.llm_timeout):
            boundary = "scenario_generation"
            with contextlib.redirect_stdout(io.StringIO()):
                scenario = red_team_agent.generate_scenario_with_codex(TECHNIQUE, request)
            # Require strict raw JSON even though the legacy helper accepts fences.
            raw = (llm_dir / "01-red-team-response.txt").read_text(encoding="utf-8")
            try:
                require(isinstance(json.loads(raw), dict), "Scenario raw response is not a JSON object")
            except json.JSONDecodeError as exc:
                raise AgentE2EFailure("Scenario raw response is not valid JSON") from exc
            attack, benign, metadata = validate_scenario(scenario)
            save(llm_dir / "scenario-metadata.json", metadata)
            save(llm_dir / "attack_events.json", attack)
            save(llm_dir / "benign_events.json", benign)
            report["stages"][boundary] = {"status": "PASS", "attack_events": len(attack), "benign_events": len(benign)}
            boundary = "sigma_generation"
            result = codex_llm.ask_for_sigma_rule(TECHNIQUE, request["title"], attack, benign,
                                                existing_rule_yaml="", lessons=AUTHOR_LESSONS)
            raw_rule = (llm_dir / "02-author-response.txt").read_text(encoding="utf-8")
            require(not raw_rule.strip().startswith("```"), "Author response must be raw YAML")
            rule = validate_rule(result, REPO_ROOT / "detections/execution/t1059_003.yml")
            require(rule.strip() == raw_rule.strip(), "Rule output differs from the recorded live response")
            rule_path = llm_dir / "generated_sigma.yml"
            rule_sha = save(rule_path, rule)
            report["stages"][boundary] = {"status": "PASS", "sha256": rule_sha, "source": "live_codex_response"}
        require(len(report["calls"]) == 2 and all(call["status"] == "PASS" for call in report["calls"]), "Both live reasoning calls are required")
        boundary = "case_assembly"
        holdout = json.loads(HOLDOUT.read_text(encoding="utf-8"))
        cases = []
        for group, events in (("attack", attack), ("benign", benign)):
            cases += [{"case_id": f"generated_{group}_{index}",
                       "fixture": str((llm_dir / f"{group}_events.json").relative_to(REPO_ROOT)),
                       "event_index": index, "expected_alert": event["_simulation"]["expected_alert"]}
                      for index, event in enumerate(events)]
        require([item["expected_alert"] for item in holdout["cases"]] == [False, True, True, False, False],
                "Holdout expectations changed; review before running")
        cases += [{**case, "case_id": "holdout_" + case["case_id"]} for case in holdout["cases"]]
        manifest = {"technique_id": TECHNIQUE, "sigma_rule": str(rule_path.relative_to(REPO_ROOT)), "cases": cases}
        manifest_path = llm_dir / "case.json"
        save(manifest_path, manifest)
        report["holdout_manifest_sha256"] = digest(HOLDOUT.read_bytes())
        report["stages"][boundary] = {"status": "PASS", "generated_count": len(attack) + len(benign), "holdout_count": 5}
        boundary = "elastic_e2e"
        elastic_path = directory / "elastic-report.json"
        elastic = run_elastic(args, manifest_path, elastic_path)
        report["elastic"] = elastic
        report["elastic_report"] = str(elastic_path.relative_to(REPO_ROOT))
        require(elastic.get("process_exit_code") == 0 and elastic.get("status") == "PASS",
                "Elastic E2E exit status did not pass")
        require(isinstance(elastic.get("stages"), dict) and all(
                isinstance(elastic["stages"].get(name), dict) and elastic["stages"][name].get("status") == "PASS"
                for name in ELASTIC_STAGES), "Elastic E2E lacks PASS evidence for every required stage")
        report["stages"][boundary] = {"status": "PASS"}
        report["status"] = "PASS"
    except (Exception, KeyboardInterrupt) as exc:
        # No adapter stderr, credentials or environment dumps are persisted.
        message = str(exc) if isinstance(exc, AgentE2EFailure) else f"{type(exc).__name__} in {boundary}"
        report["failure_boundary"] = boundary
        report["stages"][boundary] = {"status": "FAIL", "error": message}
    finally:
        report["finished_at"] = utc_now()
        save(directory / "report.json", report)
    return report, directory / "report.json"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", action="store_true", help="Read-only Codex login and SIEM readiness check")
    parser.add_argument("--output-dir", type=Path, help="Fresh evidence directory under artifacts/e2e")
    parser.add_argument("--es-url", default=os.environ.get("E2E_ES_URL", "http://127.0.0.1:19200"))
    parser.add_argument("--kibana-url", default=os.environ.get("E2E_KIBANA_URL", "http://127.0.0.1:15601"))
    parser.add_argument("--timeout", type=int, default=240, help="Scheduled-alert wait limit, seconds")
    parser.add_argument("--poll-interval", type=float, default=5)
    parser.add_argument("--llm-timeout", type=int, help="Per-call timeout override, 1-300 seconds; default agent limits 60/90")
    parser.add_argument("--allow-remote", action="store_true")
    args = parser.parse_args(argv)
    try:
        require(1 <= args.timeout <= 900 and args.poll_interval > 0, "Invalid scheduled-alert wait bounds")
        require(args.llm_timeout is None or 1 <= args.llm_timeout <= 300, "Invalid reasoning timeout")
        if args.preflight:
            print(json.dumps({"status": "READY", **preflight(args)}))
            return 0
        report, path = run(args)
        print(f"Agent E2E {report['status']}: {path}")
        if report["status"] != "PASS":
            print(f"Failed at {report['failure_boundary']}: {report['stages'][report['failure_boundary']]['error']}", file=sys.stderr)
        return 0 if report["status"] == "PASS" else 1
    except (Exception, KeyboardInterrupt) as exc:
        print(f"Agent E2E configuration/preflight failed: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
