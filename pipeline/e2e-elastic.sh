#!/usr/bin/env bash
# One isolated Compose project per invocation. Never operates on the standing lab.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
FIXTURE_ONLY=0
PREFLIGHT_ONLY=0
STARTUP_TIMEOUT=600
ALERT_TIMEOUT=240
LLM_TIMEOUT=""

usage() {
    cat <<'EOF'
Usage: bash pipeline/e2e-elastic.sh [options]

Starts a fresh loopback-only Elastic lab, runs live LLM generation and scheduled
alert verification, saves evidence, then removes only this run's Compose project.

  --fixture-only             Skip LLM generation; replay the fixed five-case smoke
  --preflight                Read-only tool, login, Docker, Compose and port checks
  --startup-timeout SECONDS  Docker Compose readiness limit (default 600)
  --timeout SECONDS          Scheduled-alert wait limit (default 240)
  --llm-timeout SECONDS      Each of the two Codex reasoning calls (1..300)
  -h, --help                 Show this help

Prerequisites: .venv from tests/e2e/requirements.txt, Docker Compose >= 2.24.4,
Docker running, and (unless --fixture-only) Codex CLI logged in.
Ports: ADE_E2E_ES_PORT=19200, ADE_E2E_KIBANA_PORT=15601, both bound to 127.0.0.1.
Evidence: artifacts/e2e/<unique-run>/stack-report.json and runner/service logs.
EOF
}

while (($#)); do
    case "$1" in
        --fixture-only) FIXTURE_ONLY=1; shift ;;
        --preflight) PREFLIGHT_ONLY=1; shift ;;
        --startup-timeout|--timeout|--llm-timeout)
            (($# >= 2)) || { echo "Missing value for $1" >&2; exit 2; }
            case "$1" in
                --startup-timeout) STARTUP_TIMEOUT="$2" ;;
                --timeout) ALERT_TIMEOUT="$2" ;;
                --llm-timeout) LLM_TIMEOUT="$2" ;;
            esac
            shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

cd -- "$REPO_ROOT"
PYTHON="$REPO_ROOT/.venv/bin/python"
export PATH="$REPO_ROOT/.venv/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1
export ADE_E2E_ES_PORT="${ADE_E2E_ES_PORT:-19200}"
export ADE_E2E_KIBANA_PORT="${ADE_E2E_KIBANA_PORT:-15601}"
# These credentials belong only to the disposable Compose stack's lab contract.
export E2E_ES_USER=elastic
export E2E_ES_PASSWORD=changeme
export E2E_ES_URL="http://127.0.0.1:$ADE_E2E_ES_PORT"
export E2E_KIBANA_URL="http://127.0.0.1:$ADE_E2E_KIBANA_PORT"

command -v python3 >/dev/null || { echo "python3 is required to record E2E evidence" >&2; exit 1; }
RUN_ID="$(date -u +%Y%m%dT%H%M%S | tr '[:upper:]' '[:lower:]')-$(python3 -c 'import uuid; print(uuid.uuid4().hex[:10])')"
PROJECT="ade-e2e-$RUN_ID"
export COMPOSE_PROJECT_NAME="$PROJECT"
COMPOSE=(docker compose --project-name "$PROJECT" --project-directory "$REPO_ROOT"
    -f "$REPO_ROOT/docker-compose.yml" -f "$REPO_ROOT/tests/e2e/compose.override.yml" --profile elastic)
ARTIFACT_DIR="$REPO_ROOT/artifacts/e2e/$RUN_ID"
STAGE=preflight
START_ATTEMPTED=0
RUNNER_EXIT=1
CHECKED_REPORT=""
CLEANUP_STATUS=NOT_APPLICABLE
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

finish() {
    local original_exit=$?
    trap - EXIT INT TERM
    set +e
    local cleanup_exit=0
    if [[ "$START_ATTEMPTED" == 1 ]]; then
        CLEANUP_STATUS=FAIL
        "${COMPOSE[@]}" ps --all --format json > "$ARTIFACT_DIR/compose-ps.json" 2> "$ARTIFACT_DIR/compose-ps.stderr"
        "${COMPOSE[@]}" logs --no-color --timestamps elasticsearch kibana-setup kibana > "$ARTIFACT_DIR/services.log" 2>&1
        local logs_exit=$?
        "${COMPOSE[@]}" down --volumes --remove-orphans --timeout 30 > "$ARTIFACT_DIR/cleanup.log" 2>&1
        cleanup_exit=$?
        [[ "$logs_exit" == 0 ]] || cleanup_exit=1
        # All three inventories must succeed and be empty. Failed inventory is not absence.
        for kind in container volume network; do
            case "$kind" in
                container) docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" ;;
                volume) docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT" ;;
                network) docker network ls -q --filter "label=com.docker.compose.project=$PROJECT" ;;
            esac > "$ARTIFACT_DIR/remaining-$kind.txt" 2> "$ARTIFACT_DIR/remaining-$kind.stderr"
            if [[ $? != 0 || -s "$ARTIFACT_DIR/remaining-$kind.txt" ]]; then
                cleanup_exit=1
            fi
        done
        [[ "$cleanup_exit" == 0 ]] && CLEANUP_STATUS=PASS
    fi
    local final_status=FAIL
    [[ "$original_exit" == 0 && "$RUNNER_EXIT" == 0 && -n "$CHECKED_REPORT" && "$CLEANUP_STATUS" == PASS ]] && final_status=PASS
    python3 - "$ARTIFACT_DIR/stack-report.json" "$PROJECT" "$RUN_ID" "$STARTED_AT" "$STAGE" \
        "$final_status" "$original_exit" "$RUNNER_EXIT" "$CLEANUP_STATUS" "$CHECKED_REPORT" "$FIXTURE_ONLY" <<'PY'
import datetime, json, pathlib, sys
(path, project, run_id, started, stage, status, process_exit, runner_exit,
 cleanup_status, checked_report, fixture_only) = sys.argv[1:]
report = {
    "schema_version": 1, "run_id": run_id, "compose_project": project,
    "status": status, "last_stage": stage, "started_at": started,
    "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "mode": "fixed_fixture" if fixture_only == "1" else "live_llm_and_elastic",
    "process_exit_code": int(process_exit), "runner_exit_code": int(runner_exit),
    "verified_runner_report": checked_report or None,
    "stack_cleanup": {"status": cleanup_status,
                      "evidence": ["cleanup.log", "remaining-container.txt", "remaining-volume.txt", "remaining-network.txt"]
                      if cleanup_status != "NOT_APPLICABLE" else []},
    "proof_limits": ["Synthetic Sysmon events; no real attack process or endpoint sensor.",
                     "Elastic only; Cribl, Splunk, coordinator, Git/PR and lifecycle deployment are outside this run."]
}
with pathlib.Path(path).open("x", encoding="utf-8") as stream:
    json.dump(report, stream, indent=2)
    stream.write("\n")
PY
    local report_exit=$?
    echo "E2E $final_status: $ARTIFACT_DIR/stack-report.json"
    if [[ "$final_status" != PASS || "$report_exit" != 0 ]]; then
        echo "Inspect runner.log, startup.log and cleanup.log when present." >&2
        exit 1
    fi
    exit 0
}

# Preflight-only has no filesystem, container, volume or model side effects.
if [[ "$PREFLIGHT_ONLY" == 0 ]]; then
    mkdir -p -- "$REPO_ROOT/artifacts/e2e"
    mkdir -- "$ARTIFACT_DIR"
    trap finish EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
fi

[[ -x "$PYTHON" ]] || { echo "Create .venv and install tests/e2e/requirements.txt first" >&2; exit 1; }
command -v sigma >/dev/null || { echo "sigma CLI is missing from .venv/bin" >&2; exit 1; }
command -v docker >/dev/null || { echo "Docker is not installed" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker is not running or is inaccessible" >&2; exit 1; }
"$PYTHON" - "$STARTUP_TIMEOUT" "$ALERT_TIMEOUT" "$LLM_TIMEOUT" "$(docker compose version --short)" <<'PY'
import re, socket, os, sys
startup, alert, llm, version = sys.argv[1:]
for label, value, low, high in (("startup timeout", startup, 1, 1800), ("alert timeout", alert, 1, 900)):
    if not value.isdigit() or not low <= int(value) <= high:
        raise SystemExit(f"Invalid {label}: must be {low}..{high}")
if llm and (not llm.isdigit() or not 1 <= int(llm) <= 300):
    raise SystemExit("LLM timeout must be 1..300")
match = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
if not match or tuple(map(int, match.groups())) < (2, 24, 4):
    raise SystemExit("Docker Compose 2.24.4+ is required for isolated port overrides")
ports = [int(os.environ[name]) for name in ("ADE_E2E_ES_PORT", "ADE_E2E_KIBANA_PORT")]
if len(set(ports)) != 2 or any(not 1 <= port <= 65535 for port in ports):
    raise SystemExit("Choose two distinct valid E2E ports")
for port in ports:
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError as exc:
            raise SystemExit(f"Loopback port {port} is already in use or unavailable; no service was changed") from exc
import yaml
from importlib.metadata import version
for package in ("sigma-cli", "pySigma", "pySigma-backend-elasticsearch"):
    version(package)
PY
"${COMPOSE[@]}" config --quiet
if [[ "$FIXTURE_ONLY" == 0 ]]; then
    command -v codex >/dev/null || { echo "Codex CLI is required for the default LLM E2E" >&2; exit 1; }
    codex login status >/dev/null 2>&1 || { echo "Run codex login before the LLM E2E" >&2; exit 1; }
fi
if [[ "$PREFLIGHT_ONLY" == 1 ]]; then
    echo "READY: tools, Docker, Compose, login (when required), and loopback ports. No resources created."
    exit 0
fi

# Refuse to adopt existing resources, even in the unlikely event of a name collision.
for kind in container volume network; do
    case "$kind" in
        container) existing="$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")" ;;
        volume) existing="$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT")" ;;
        network) existing="$(docker network ls -q --filter "label=com.docker.compose.project=$PROJECT")" ;;
    esac
    [[ -z "$existing" ]] || { echo "Generated project name already owns $kind resources; refusing adoption" >&2; exit 1; }
done

STAGE=startup
START_ATTEMPTED=1
echo "Starting isolated project $PROJECT; readiness timeout ${STARTUP_TIMEOUT}s"
if ! "${COMPOSE[@]}" up --detach --wait --wait-timeout "$STARTUP_TIMEOUT" elasticsearch kibana-setup kibana > "$ARTIFACT_DIR/startup.log" 2>&1; then
    echo "Isolated stack failed readiness; see $ARTIFACT_DIR/startup.log" >&2
    exit 1
fi

STAGE=runner
if [[ "$FIXTURE_ONLY" == 1 ]]; then
    RUNNER=("$PYTHON" "$REPO_ROOT/pipeline/e2e_elastic.py" --report "$ARTIFACT_DIR/elastic-report.json" --timeout "$ALERT_TIMEOUT")
    RUNNER_REPORT="$ARTIFACT_DIR/elastic-report.json"
else
    RUNNER=("$PYTHON" "$REPO_ROOT/pipeline/e2e_agents.py" --output-dir "$ARTIFACT_DIR/agents" --timeout "$ALERT_TIMEOUT")
    [[ -z "$LLM_TIMEOUT" ]] || RUNNER+=(--llm-timeout "$LLM_TIMEOUT")
    RUNNER_REPORT="$ARTIFACT_DIR/agents/report.json"
fi
echo "Running E2E; progress and errors: $ARTIFACT_DIR/runner.log"
if "${RUNNER[@]}" > "$ARTIFACT_DIR/runner.log" 2>&1; then
    RUNNER_EXIT=0
else
    RUNNER_EXIT=$?
fi
STAGE=evidence
"$PYTHON" - "$RUNNER_REPORT" "$RUNNER_EXIT" "$FIXTURE_ONLY" <<'PY'
import json, pathlib, sys
path, process_exit, fixture_only = sys.argv[1:]
if int(process_exit) != 0:
    raise SystemExit(f"E2E runner failed with exit {process_exit}")
try:
    report = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
except (OSError, ValueError) as exc:
    raise SystemExit("E2E runner did not produce a readable evidence report") from exc
if report.get("status") != "PASS":
    raise SystemExit("E2E evidence does not report PASS")
elastic = report if fixture_only == "1" else report.get("elastic", {})
if elastic.get("status") != "PASS" or elastic.get("stages", {}).get("cleanup", {}).get("status") != "PASS":
    raise SystemExit("Elastic scheduled-alert evidence or cleanup is incomplete")
for stage in ("preflight", "compile", "template", "query_validation", "replay", "deploy", "scheduled_alerts", "cleanup"):
    if elastic.get("stages", {}).get(stage, {}).get("status") != "PASS":
        raise SystemExit(f"Required Elastic stage did not pass: {stage}")
if fixture_only != "1":
    for stage in ("preflight", "scenario_generation", "sigma_generation", "case_assembly", "elastic_e2e"):
        if report.get("stages", {}).get(stage, {}).get("status") != "PASS":
            raise SystemExit(f"Required agent stage did not pass: {stage}")
    calls = report.get("calls")
    if not isinstance(calls, list) or len(calls) != 2 or any(
            not isinstance(call, dict) or call.get("status") != "PASS" for call in calls):
        raise SystemExit("Both successful live model calls require evidence")
PY
CHECKED_REPORT="${RUNNER_REPORT#"$REPO_ROOT/"}"
STAGE=cleanup
# The EXIT trap saves service logs, tears down this unique project, and emits the final verdict.
