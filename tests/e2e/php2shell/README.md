# PHP2Shell local end-to-end run

This terminal run takes the operator scenario in `scenario.txt` through two live
Daybreak calls, real HTTP controls and the selected local StealMyBitcoin PoC,
then checks a scheduled Elastic Security alert. Nginx records the three HTTP
conditions used in the public AWS custom rule: a POST, a `PHPSESSID` cookie key
or body token, and a `PHP_SESSION_UPLOAD_PROGRESS` body token. The rule targets
suspicious CVE-2026-109619 requests. It is not an AWS WAF deployment or proof
of coverage for CVE-2026-109618.

## Prepare

Run from the repository root with Python 3.11+, Docker Compose 2.24.4+, a
running Docker engine, and a logged-in Codex CLI. Docker needs enough memory for
the disposable Elasticsearch and Kibana containers (about 4 GB combined), plus
the nginx/PHP lab. The PoC source must be present locally; this workflow does
not download or edit it.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r tests/e2e/requirements.txt
codex login
bash pipeline/e2e-php2shell.sh --preflight
```

The default PoC path is `~/workspace/StealMyBitcoin-PoC/stealmybitcoin_poc.py`.
Use `--poc /absolute/path/to/stealmybitcoin_poc.py` or set `PHP2SHELL_POC` if
it lives elsewhere. Preflight checks the files, dependencies, login, Compose
config, and three available loopback ports. It creates no containers or
artifacts and makes no model call.

## Run

```bash
make e2e-php2shell
# Equivalent:
bash pipeline/e2e-php2shell.sh
```

The wrapper creates unique `ade-e2e-<run>` and `ade-e2e-php-<run>` Compose
projects. Elastic/Kibana use `127.0.0.1:19200` and `127.0.0.1:15601`; nginx
uses `127.0.0.1:18167`. The PHP service is reachable only through this nginx
lab. Occupied ports fail preflight, so running user services are left alone.
Change the local ports for a run with:

```bash
ADE_E2E_ES_PORT=19300 ADE_E2E_KIBANA_PORT=15602 \
PHP2SHELL_LAB_PORT=18168 make e2e-php2shell
```

The PoC target is always the exact loopback URL
`http://127.0.0.1:<PHP2SHELL_LAB_PORT>/php-version.php`. The Python runner
checks that this port belongs to the run's nginx container and sends PoC output
to the run's evidence directory. The scenario and PoC source are copied into the
run directory before use, with their hashes recorded in the report. The wrapper
passes the nginx and PHP container IDs from its own Compose project;
it never selects a similarly named container from another project.

To use a different operator scenario or bound an individual stage:

```bash
bash pipeline/e2e-php2shell.sh --scenario /absolute/path/to/scenario.txt \
  --poc /absolute/path/to/stealmybitcoin_poc.py \
  --startup-timeout 900 --llm-timeout 180 --poc-timeout 180 --timeout 300
```

`--timeout` is the scheduled-alert wait. Daybreak is fixed to
`gpt-daybreak-blue-latest`; if the model or login is unavailable, the run fails
with evidence instead of substituting another model. Both Compose projects and
their volumes are removed after success, failure, or interruption. Existing
services and historical evidence are not part of cleanup.

## Review the result

Every started run gets a fresh ignored directory under
`artifacts/e2e/php2shell-<run>/`. The final verdict is `stack-report.json`.
`PASS` requires both live model calls, valid nginx HTTP observations, PoC
execution proof and at least one observed request matching the AWS predicate,
the generated Sigma rule, a scheduled Elastic alert with the expected case
ancestry, and successful removal of this run's temporary rules and containers.
A missing stage or failed cleanup produces `FAIL` and a nonzero exit.
The PoC can fail its execution proof on a particular run even when its HTTP
attempts are detected and Elastic alerts are verified. That remains an overall
`FAIL`; inspect the separate `poc` and `elastic_e2e` stages to see which path
succeeded. The wrapper makes one PoC attempt and does not retry it automatically.

| File | Evidence |
| --- | --- |
| `stack-report.json` | Overall verdict, Compose project IDs, runner report path, cleanup status |
| `runner.log` | Stage progress and failure details |
| `elastic-startup.log`, `php-startup.log` | Docker startup and readiness output |
| `elastic-services.log`, `php-services.log` | Captured service logs before teardown |
| `elastic-cleanup.log`, `php-cleanup.log`, `*-remaining-*.txt` | Owned-project removal and inventory checks |
| `php2shell/report.json` | Per-stage Daybreak, HTTP, PoC and Elastic verdicts |
| `php2shell/operator-scenario.txt`, `php2shell/poc-source.py` | Exact input snapshots used in this run |
| `php2shell/llm/` | Two model requests, responses and hashes |
| `php2shell/http-observations.json`, `php2shell/poc-observations.json` | Nginx-derived request flags and independent predicate labels |
| `php2shell/poc/`, `php2shell/poc-stdout.txt`, `php2shell/poc-stderr.txt` | Local PoC proof and process output |
| `php2shell/generated-php2shell.yml`, `php2shell/cases/` | Generated rule and replay manifest |
| `php2shell/elastic-report.json` | Query, rule scheduler, alert and temporary-resource evidence |

The generated rule and replayed events are lab artifacts. The result measures
the local HTTP predicate and Elastic path, not production telemetry, AWS
managed rules, or live detection coverage outside this disposable lab. Review
the retained PoC and model output before sharing it.
