# Local end-to-end smoke test

This optional automated smoke follows two live Codex reasoning calls through an
actual scheduled Elastic Security alert. It is a fixed starting case, not an
interactive session for supplying and reviewing arbitrary user scenarios. This is a bounded synthetic-log test, not an execution of
Fawkes or a measurement of production detection accuracy.

## Prepare once

Use Python 3.10 or newer, a running Docker engine with Docker Compose 2.24.4 or
newer, and enough memory for the disposable Elasticsearch and Kibana containers
(approximately 4 GB combined, plus Docker overhead). The default run also requires
an installed Codex CLI and an authenticated `codex login` session.

From the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r tests/e2e/requirements.txt
codex login
bash pipeline/e2e-elastic.sh --preflight
```

Dependencies are installed only into `.venv`; the wrapper does not install Python
packages or alter the user's Codex configuration. Preflight checks tools, Docker,
Compose compatibility, login, and available loopback ports without creating a
container, artifact, or reasoning call.

## Run

```bash
make e2e
# Equivalent:
bash pipeline/e2e-elastic.sh
```

The wrapper creates a unique `ade-e2e-<timestamp>-<random>` Compose project and
starts only Elasticsearch, the Kibana password setup service, and Kibana. Published
ports bind to `127.0.0.1:19200` and `127.0.0.1:15601`. It does not start the standing
lab, simulator, Splunk, Cribl, or MCP services. An occupied port fails before any
container starts. To use different local ports:

```bash
ADE_E2E_ES_PORT=19300 ADE_E2E_KIBANA_PORT=15602 make e2e
```

The full run calls the project's Red Team scenario-generation entry point and
Sigma-authoring adapter with live Codex reasoning, then tests the generated rule
against both generated cases and five fixed holdout events. The holdout events
are not sent to the model. No generated fallback is accepted and there are no
automatic model retries. Model output, generated fixtures, the Sigma rule, and
reports are retained for inspection.

For deterministic infrastructure calibration without any model calls:

```bash
make e2e-fixture
# Equivalent:
bash pipeline/e2e-elastic.sh --fixture-only
```

This uses the existing T1059.003 Sigma rule. Its fixed manifest marks two events as
expected alerts and three as non-alerting, including the contextual process event
in the TP fixture. Fixture files are never modified. Their replay copies receive
current UTC timestamps and run/case metadata.

Limits can be changed explicitly:

```bash
bash pipeline/e2e-elastic.sh --startup-timeout 900 --timeout 300 --llm-timeout 180
```

`--startup-timeout` bounds Compose's service-readiness wait (default 600 seconds;
image downloads are handled by Docker and may take additional time).
`--timeout` bounds the scheduled-alert wait (default 240 seconds). `--llm-timeout`
sets the limit for each of two model calls; absent this option, the project agent
limits apply. `Ctrl-C` attempts cleanup and reports failure.

## Evidence and pass criteria

Each run creates a fresh ignored directory under `artifacts/e2e/`. Its
`stack-report.json` is the final verdict. A zero process exit alone is insufficient:

- The actual Sigma compiler exits successfully and emits a nonempty query. The
  query uses the same Lucene normalization as the project adapter.
- The existing Elasticsearch validator performs real query validation with no
  errors or fallback. Source event counts and individual IDs are verified again
  in a run-specific index with explicit keyword mappings.
- The deployed rule is enabled, searches only that run's index, and preserves the
  compiled query. A successful scheduler execution must occur after replay.
- Alerts are linked by rule ID and source-event ancestry to exactly the expected
  positive cases. Contextual and benign cases must have no alerts.
- The temporary rule, alerts, indices, and index template are deleted and their
  absence is checked. The wrapper then removes only its own Compose project and
  volumes, and checks that its containers, volumes, and network are absent.

A missing report, skipped required step, query error, fallback, timeout, unexpected
alert, or failed cleanup produces `FAIL` and a nonzero exit. Historical
`tests/results/`, detection-request lifecycle files, existing rules, and `sim-*`
templates are not rewritten.

Useful files:

| File in the run directory | Contents |
| --- | --- |
| `stack-report.json` | Overall test and Compose cleanup verdict |
| `runner.log` | Runner output and failure details |
| `startup.log`, `services.log` | Compose startup and captured service logs |
| `cleanup.log`, `remaining-*.txt` | Teardown result and remaining-resource checks |
| `agents/report.json` | Full LLM run, call evidence, holdout and Elastic result |
| `agents/llm/` | Generated artifacts and captured model evidence |
| `agents/elastic-report.json` | Per-stage query, scheduler and alert evidence |
| `elastic-report.json` | Corresponding report for `--fixture-only` |

Kibana internal execution/audit history is not selectively rewritten by the
Python runner. The wrapper destroys the disposable stack's own volumes after
saving logs. Report artifacts remain on disk; review them before sharing because
they contain model output and synthetic log data.

## Use an already running isolated lab

For debugging, the Python runners can use existing endpoints. These commands do
not manage the Compose stack and do not require the ports to be free:

```bash
export PATH="$PWD/.venv/bin:$PATH"
export E2E_ES_USER=elastic
export E2E_ES_PASSWORD=changeme
.venv/bin/python pipeline/e2e_elastic.py --preflight
.venv/bin/python pipeline/e2e_elastic.py --report /tmp/elastic-smoke-new.json
.venv/bin/python pipeline/e2e_agents.py
```

The default endpoints are still ports 19200/15601. Set `E2E_ES_URL` and
`E2E_KIBANA_URL` to change them. Only loopback hosts are accepted unless
`--allow-remote` is explicitly supplied to a Python runner. The shell wrapper
always creates a local isolated lab. It uses the disposable Compose stack's fixed
lab credentials rather than credentials for an existing environment.

The smoke test does not verify endpoint collection, Cribl/Splunk delivery,
coordinator routing, Git/PR operations, or production lifecycle deployment. Those
are separate follow-up E2E paths after this one is stable.
