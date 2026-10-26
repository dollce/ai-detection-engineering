#!/usr/bin/env bash
# Run PHP2Shell against disposable loopback labs and keep each run's evidence.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LAB_DIR="$REPO_ROOT/tests/e2e/php2shell"
PYTHON="$REPO_ROOT/.venv/bin/python"
MODEL=gpt-daybreak-blue-latest
SCENARIO="$LAB_DIR/scenario.txt"
POC="${PHP2SHELL_POC:-$HOME/workspace/StealMyBitcoin-PoC/stealmybitcoin_poc.py}"
PREFLIGHT_ONLY=0
STARTUP_TIMEOUT=600
ALERT_TIMEOUT=240
LLM_TIMEOUT=180
POC_TIMEOUT=180

usage() {
    cat <<'EOF'
Usage: bash pipeline/e2e-php2shell.sh [options]

Run the operator's PHP2Shell scenario through two live Daybreak calls, a local
nginx/PHP lab, the selected local PoC, and scheduled Elastic alert verification.
Two unique Docker Compose projects are removed after the run; evidence is kept.

  --preflight                Read-only dependency, login, Compose and port checks
  --scenario PATH            Operator scenario (default tests/e2e/php2shell/scenario.txt)
  --poc PATH                 Local StealMyBitcoin PoC Python file
  --startup-timeout SECONDS  Compose readiness limit (default 600)
  --timeout SECONDS          Scheduled-alert wait limit (default 240)
  --llm-timeout SECONDS      Limit for each Daybreak call (default 180)
  --poc-timeout SECONDS      Local PoC run limit (default 180)
  -h, --help                 Show this help

Ports: ADE_E2E_ES_PORT=19200, ADE_E2E_KIBANA_PORT=15601,
       PHP2SHELL_LAB_PORT=18167; all are bound to 127.0.0.1.
Evidence: artifacts/e2e/php2shell-<unique-run>/stack-report.json.
EOF
}

while (($#)); do
    case "$1" in
        --preflight) PREFLIGHT_ONLY=1; shift ;;
        --scenario|--poc|--startup-timeout|--timeout|--llm-timeout|--poc-timeout)
            (($# >= 2)) || { echo "Missing value for $1" >&2; exit 2; }
            case "$1" in
                --scenario) SCENARIO="$2" ;;
                --poc) POC="$2" ;;
                --startup-timeout) STARTUP_TIMEOUT="$2" ;;
                --timeout) ALERT_TIMEOUT="$2" ;;
                --llm-timeout) LLM_TIMEOUT="$2" ;;
                --poc-timeout) POC_TIMEOUT="$2" ;;
            esac
            shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

cd -- "$REPO_ROOT"
export PATH="$REPO_ROOT/.venv/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1
export ADE_E2E_ES_PORT="${ADE_E2E_ES_PORT:-19200}"
export ADE_E2E_KIBANA_PORT="${ADE_E2E_KIBANA_PORT:-15601}"
export PHP2SHELL_LAB_PORT="${PHP2SHELL_LAB_PORT:-18167}"
# Credentials and URLs below belong only to this run's disposable Elastic lab.
export E2E_ES_USER=elastic
export E2E_ES_PASSWORD=changeme
export E2E_ES_URL="http://127.0.0.1:$ADE_E2E_ES_PORT"
export E2E_KIBANA_URL="http://127.0.0.1:$ADE_E2E_KIBANA_PORT"

elastic_compose() {
    COMPOSE_PROJECT_NAME="$ELASTIC_PROJECT" docker compose --project-name "$ELASTIC_PROJECT" \
        --project-directory "$REPO_ROOT" -f "$REPO_ROOT/docker-compose.yml" \
        -f "$REPO_ROOT/tests/e2e/compose.override.yml" --profile elastic "$@"
}

php_compose() {
    COMPOSE_PROJECT_NAME="$PHP_PROJECT" docker compose --project-name "$PHP_PROJECT" \
        --project-directory "$LAB_DIR" -f "$LAB_DIR/lab-compose.yml" "$@"
}

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
[[ -x "$PYTHON" ]] || { echo "Create .venv and install tests/e2e/requirements.txt first" >&2; exit 1; }
command -v sigma >/dev/null || { echo "sigma CLI is missing from .venv/bin" >&2; exit 1; }
command -v docker >/dev/null || { echo "Docker is not installed" >&2; exit 1; }
command -v codex >/dev/null || { echo "Codex CLI is required for Daybreak calls" >&2; exit 1; }
[[ -f "$SCENARIO" ]] || { echo "Scenario file is unavailable: $SCENARIO" >&2; exit 1; }
[[ -f "$POC" ]] || { echo "Local PoC file is unavailable: $POC" >&2; exit 1; }
SCENARIO="$("$PYTHON" -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve())' "$SCENARIO")"
POC="$("$PYTHON" -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve())' "$POC")"
docker info >/dev/null 2>&1 || { echo "Docker is not running or is inaccessible" >&2; exit 1; }
codex login status >/dev/null 2>&1 || { echo "Run codex login before this E2E" >&2; exit 1; }

"$PYTHON" - "$STARTUP_TIMEOUT" "$ALERT_TIMEOUT" "$LLM_TIMEOUT" "$POC_TIMEOUT" \
    "$(docker compose version --short)" <<'PY'
import os, re, socket, sys
from importlib.metadata import version

if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11+ is required by the selected local PoC")
startup, alert, llm, poc, compose_version = sys.argv[1:]
for label, value, high in (("startup", startup, 1800), ("alert", alert, 900),
                           ("Daybreak", llm, 300), ("PoC", poc, 900)):
    if not value.isdigit() or not 1 <= int(value) <= high:
        raise SystemExit(f"Invalid {label} timeout: choose 1..{high} seconds")
match = re.search(r"(\d+)\.(\d+)\.(\d+)", compose_version)
if not match or tuple(map(int, match.groups())) < (2, 24, 4):
    raise SystemExit("Docker Compose 2.24.4+ is required for isolated port overrides")
ports = []
for key in ("ADE_E2E_ES_PORT", "ADE_E2E_KIBANA_PORT", "PHP2SHELL_LAB_PORT"):
    value = os.environ[key]
    if not value.isdigit() or not 1 <= int(value) <= 65535:
        raise SystemExit(f"Invalid loopback port: {key}")
    ports.append(int(value))
if len(set(ports)) != len(ports):
    raise SystemExit("Choose three distinct loopback ports")
for port in ports:
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError as exc:
            raise SystemExit(f"Loopback port {port} is already occupied; no service was changed") from exc
for package in ("sigma-cli", "pySigma", "pySigma-backend-elasticsearch", "PyYAML"):
    version(package)
PY

# Compose config is read-only. The names also keep root Compose's explicit
# container/network overrides scoped to this unique project.
RUN_ID="$(date -u +%Y%m%dT%H%M%S | tr '[:upper:]' '[:lower:]')-$(python3 -c 'import uuid; print(uuid.uuid4().hex[:10])')"
ELASTIC_PROJECT="ade-e2e-$RUN_ID"
PHP_PROJECT="ade-e2e-php-$RUN_ID"
elastic_compose config --quiet
php_compose config --quiet
if [[ "$PREFLIGHT_ONLY" == 1 ]]; then
    echo "READY: Docker, Compose, .venv, Codex login, PoC, scenario and loopback ports. No resources created."
    exit 0
fi

RUN_DIR="$REPO_ROOT/artifacts/e2e/php2shell-$RUN_ID"
RUNNER_DIR="$RUN_DIR/php2shell"
RUNNER_REPORT="$RUNNER_DIR/report.json"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STAGE=startup
ELASTIC_ATTEMPTED=0
PHP_ATTEMPTED=0
ELASTIC_CLEANUP=NOT_APPLICABLE
PHP_CLEANUP=NOT_APPLICABLE
RUNNER_EXIT=1
CHECKED_REPORT=""
mkdir -p -- "$REPO_ROOT/artifacts/e2e"
mkdir -- "$RUN_DIR"

owned_resources() {
    local project="$1" kind="$2"
    case "$kind" in
        container) docker ps -aq --filter "label=com.docker.compose.project=$project" ;;
        volume) docker volume ls -q --filter "label=com.docker.compose.project=$project" ;;
        network) docker network ls -q --filter "label=com.docker.compose.project=$project" ;;
    esac
}

cleanup_project() {
    local label="$1" project="$2" compose_function="$3"
    local evidence_exit=0 down_exit=0 inventory_exit=0 kind
    "$compose_function" ps --all --format json > "$RUN_DIR/$label-compose-ps.json" \
        2> "$RUN_DIR/$label-compose-ps.stderr" || evidence_exit=1
    "$compose_function" logs --no-color --timestamps > "$RUN_DIR/$label-services.log" 2>&1 || evidence_exit=1
    "$compose_function" down --volumes --remove-orphans --timeout 30 \
        > "$RUN_DIR/$label-cleanup.log" 2>&1 || down_exit=1
    for kind in container volume network; do
        owned_resources "$project" "$kind" > "$RUN_DIR/$label-remaining-$kind.txt" \
            2> "$RUN_DIR/$label-remaining-$kind.stderr" || inventory_exit=1
        [[ ! -s "$RUN_DIR/$label-remaining-$kind.txt" ]] || inventory_exit=1
    done
    [[ "$evidence_exit" == 0 && "$down_exit" == 0 && "$inventory_exit" == 0 ]]
}

finish() {
    local original_exit=$?
    trap - EXIT INT TERM
    set +e
    if [[ "$PHP_ATTEMPTED" == 1 ]]; then
        PHP_CLEANUP=FAIL
        cleanup_project php "$PHP_PROJECT" php_compose && PHP_CLEANUP=PASS
    fi
    if [[ "$ELASTIC_ATTEMPTED" == 1 ]]; then
        ELASTIC_CLEANUP=FAIL
        cleanup_project elastic "$ELASTIC_PROJECT" elastic_compose && ELASTIC_CLEANUP=PASS
    fi
    local status=FAIL
    [[ "$original_exit" == 0 && "$RUNNER_EXIT" == 0 && -n "$CHECKED_REPORT" && \
       "$PHP_CLEANUP" == PASS && "$ELASTIC_CLEANUP" == PASS ]] && status=PASS
    python3 - "$RUN_DIR/stack-report.json" "$RUN_ID" "$STARTED_AT" "$STAGE" \
        "$status" "$original_exit" "$RUNNER_EXIT" "$CHECKED_REPORT" \
        "$ELASTIC_PROJECT" "$PHP_PROJECT" "$ELASTIC_CLEANUP" "$PHP_CLEANUP" "$MODEL" <<'PY'
import datetime, json, pathlib, sys

(path, run_id, started, stage, status, process_exit, runner_exit, checked_report,
 elastic_project, php_project, elastic_cleanup, php_cleanup, model) = sys.argv[1:]
report = {
    "schema_version": 1, "run_id": run_id, "status": status,
    "started_at": started, "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "last_stage": stage, "requested_model": model,
    "compose_projects": {"elastic": elastic_project, "php2shell": php_project},
    "process_exit_code": int(process_exit), "runner_exit_code": int(runner_exit),
    "verified_runner_report": checked_report or None,
    "stack_cleanup": {"elastic": elastic_cleanup, "php2shell": php_cleanup},
    "proof_limits": [
        "AWS custom HTTP predicate covers suspicious CVE-2026-109619 requests, not all PHP2Shell behavior.",
        "The PoC is confined to this loopback lab; Elastic receives lab observations and generated cases, not production telemetry.",
    ],
}
with pathlib.Path(path).open("x", encoding="utf-8") as stream:
    json.dump(report, stream, indent=2)
    stream.write("\n")
PY
    local report_exit=$?
    echo "PHP2Shell E2E $status: $RUN_DIR/stack-report.json"
    if [[ "$status" != PASS || "$report_exit" != 0 ]]; then
        echo "Inspect runner.log, startup logs, service logs and cleanup logs in $RUN_DIR" >&2
        exit 1
    fi
    exit 0
}

trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# A name collision must fail before attempting startup; never adopt another run.
for project in "$ELASTIC_PROJECT" "$PHP_PROJECT"; do
    for kind in container volume network; do
        existing="$(owned_resources "$project" "$kind")"
        [[ -z "$existing" ]] || { echo "Generated project $project already has $kind resources" >&2; exit 1; }
    done
done

STAGE=elastic_startup
ELASTIC_ATTEMPTED=1
echo "Starting isolated Elastic project $ELASTIC_PROJECT"
elastic_compose up --detach --wait --wait-timeout "$STARTUP_TIMEOUT" \
    elasticsearch kibana-setup kibana > "$RUN_DIR/elastic-startup.log" 2>&1

STAGE=php_startup
PHP_ATTEMPTED=1
echo "Starting isolated PHP project $PHP_PROJECT"
php_compose up --detach --wait --wait-timeout "$STARTUP_TIMEOUT" php nginx \
    > "$RUN_DIR/php-startup.log" 2>&1
NGINX_CONTAINER="$(php_compose ps -q nginx)"
PHP_CONTAINER="$(php_compose ps -q php)"
[[ -n "$NGINX_CONTAINER" && -n "$PHP_CONTAINER" ]] || {
    echo "PHP lab containers were not found in the owned project" >&2; exit 1;
}

STAGE=runner
echo "Running Daybreak + PoC + Elastic E2E; progress: $RUN_DIR/runner.log"
if "$PYTHON" "$REPO_ROOT/pipeline/e2e_php2shell.py" --scenario "$SCENARIO" \
    --poc "$POC" --lab-port "$PHP2SHELL_LAB_PORT" \
    --lab-url "http://127.0.0.1:$PHP2SHELL_LAB_PORT/php-version.php" \
    --nginx-container "$NGINX_CONTAINER" --php-container "$PHP_CONTAINER" \
    --model "$MODEL" --llm-timeout "$LLM_TIMEOUT" --poc-timeout "$POC_TIMEOUT" \
    --alert-timeout "$ALERT_TIMEOUT" --output-dir "$RUNNER_DIR" \
    > "$RUN_DIR/runner.log" 2>&1; then
    RUNNER_EXIT=0
else
    RUNNER_EXIT=$?
fi

STAGE=evidence
"$PYTHON" - "$RUNNER_REPORT" "$RUNNER_EXIT" "$MODEL" <<'PY'
import json, pathlib, sys

path, runner_exit, model = pathlib.Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
if runner_exit != 0:
    raise SystemExit(f"PHP2Shell runner exited with status {runner_exit}")
try:
    report = json.loads(path.read_text(encoding="utf-8"))
except (OSError, ValueError) as exc:
    raise SystemExit("PHP2Shell runner did not produce a readable report") from exc
if report.get("status") != "PASS" or report.get("requested_model") != model:
    raise SystemExit("PHP2Shell runner verdict or requested model is invalid")
for stage in ("preflight", "http_controls", "scenario_generation", "rule_generation",
              "poc", "elastic_e2e"):
    if report.get("stages", {}).get(stage, {}).get("status") != "PASS":
        raise SystemExit(f"Required PHP2Shell stage did not pass: {stage}")
poc = report["stages"]["poc"]
if poc.get("execution_proof_verified") is not True or poc.get("predicate_matches", 0) < 1:
    raise SystemExit("PoC execution proof or observable AWS predicate match is missing")
calls = report.get("calls")
if (not isinstance(calls, list) or len(calls) != 2 or
        {call.get("role") for call in calls if isinstance(call, dict)} != {"red-team", "author"} or
        any(not isinstance(call, dict) or call.get("requested_model") != model or
            call.get("adapter_success") is not True for call in calls)):
    raise SystemExit("Two successful live Daybreak calls are required")
elastic = report.get("elastic")
if not isinstance(elastic, dict) or elastic.get("status") != "PASS":
    raise SystemExit("Nested Elastic verification did not pass")
for stage in ("preflight", "compile", "template", "query_validation", "replay",
              "deploy", "scheduled_alerts", "cleanup"):
    if elastic.get("stages", {}).get(stage, {}).get("status") != "PASS":
        raise SystemExit(f"Required Elastic stage did not pass: {stage}")
PY
CHECKED_REPORT="${RUNNER_REPORT#"$REPO_ROOT/"}"
STAGE=cleanup
# The EXIT trap captures service logs, removes both owned projects, and records the verdict.
