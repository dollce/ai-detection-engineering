# AI Detection Engineering Lab

A template for building an **AI-powered detection engineering pipeline** using Codex CLI
as an autonomous blue team agent. Deploy a full SIEM lab, generate simulated attack
telemetry, and let an AI agent build, validate, tune, and deploy security detections —
all mapped to the MITRE ATT&CK framework.

## What This Does

An AI agent (Codex CLI) acts as a senior detection engineer, executing the full lifecycle:

```
INTEL → DISCOVER → AUTHOR → VALIDATE → DEPLOY → TUNE → REPORT
```

For each detection the agent:
1. Reads threat intel about the Fawkes C2 agent (59 commands mapped to ATT&CK)
2. Discovers available log data in your SIEM
3. Authors a Sigma rule with full MITRE ATT&CK mapping
4. Validates against simulated attack telemetry (true positive + false positive testing)
5. Deploys to Elastic Security and/or Splunk saved searches
6. Tunes based on alert feedback — adding exclusions, tightening thresholds
7. Updates coverage tracking and commits to git with conventional messages

## Lab Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      Lab Network (Docker)                         │
│                                                                    │
│  ┌──────────────┐    ┌─────────────────┐    ┌─────────────────┐  │
│  │ Log Simulator│───▶│  Cribl Stream   │───▶│ Elasticsearch   │  │
│  │ Fawkes TTPs  │    │ :9000 (Phase 3) │    │ :9200           │  │
│  │ + baseline   │    │ CIM normalize   │───▶│ Kibana :5601    │  │
│  └──────────────┘    │ Log reduction   │    └─────────────────┘  │
│         │             │ Route by tactic │                          │
│         │             │ (streaming path)│    ┌─────────────────┐  │
│         │             └────────┬────────┘───▶│ Splunk          │  │
│         └───────────────────────────────────▶│ :8000 (optional)│  │
│                      ┌───────────────┐       └─────────────────┘  │
│                      │  Codex CLI  │                            │
│                      │  (AI Agent)   │ ◀── MCP: Elasticsearch     │
│                      └───────────────┘                            │
└──────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# 1. Clone the repo
git clone <your-repo-url>
cd ai-detection-engineering

# 2. Run setup (interactive — picks your SIEM, installs tooling)
./setup.sh

# 3. Install/authenticate Codex CLI >= 0.163.0, then launch the AI agent
npm install -g @openai/codex
codex login
codex
# Paste the first-run prompt from PROMPTS.md
```

See [QUICKSTART.md](QUICKSTART.md) for a detailed walkthrough.

## Startup Options

| Command | What Runs |
|---|---|
| `./setup.sh --elastic` | Elasticsearch + Kibana + Simulator |
| `./setup.sh --splunk` | Splunk + Simulator |
| `./setup.sh --both` | Both SIEMs + Simulator |
| `./setup.sh --cribl` | Elastic + Cribl Stream + Simulator |
| `./setup.sh --full` | Everything |

Or use `make setup` for the same interactive experience.

## Credentials

| Service | URL | Username | Password |
|---|---|---|---|
| Kibana | http://localhost:5601 | elastic | changeme |
| Elasticsearch | http://localhost:9200 | elastic | changeme |
| Splunk Web | http://localhost:8000 | admin | BlueTeamLab1! |
| Splunk REST API | https://localhost:8089 | admin | BlueTeamLab1! |
| Splunk HEC | http://localhost:8288 | — | blue-team-lab-hec-token |
| Cribl Stream | http://localhost:9000 | admin | admin |

## Data Sources

### Simulated Telemetry (Always Available)

| Index (Elastic) | Index (Splunk) | Content |
|---|---|---|
| `sim-baseline` | `sysmon` | Normal enterprise Windows/Linux activity |
| `sim-attack` | `attack_simulation` | Fawkes C2 TTP simulations |

Event types generated: Sysmon EID 1, 3, 7, 8, 10, 11, 13, 17/18, 22 + WinEvent 4624, 4104, 7045

### Attack Scenarios

The simulator generates 13 attack scenarios matching Fawkes C2 + Scattered Spider capabilities:
- Process injection (vanilla-injection) — EID 8 + 10
- Registry persistence — EID 13
- PowerShell with bypass flags — EID 1
- Scheduled task creation — EID 1
- Discovery command burst — EID 1
- LSASS token theft — EID 10
- C2 beaconing — EID 3
- AMSI/CLR bypass — EID 7
- Encoded PowerShell / Mimikatz via Script Block — EID 4104
- RMM tool binary drops (AnyDesk, TeamViewer, ScreenConnect) — EID 11
- RMM tool DNS resolution — EID 22
- C2 named pipe communication — EID 17/18
- Malicious service persistence — EID 7045

## Primary Threat: Fawkes C2 Agent

[Fawkes](https://github.com/galoryber/fawkes) is a Golang-based Mythic C2 agent with 59 commands:

| Category | Commands | ATT&CK Techniques |
|---|---|---|
| Process Injection | vanilla-injection, apc-injection, threadless-inject, poolparty, opus | T1055.001-005 |
| Credential Access | steal-token, make-token, keylog | T1134.001, T1056.001 |
| Persistence | persist (registry, startup, schtask, service, crontab) | T1547.001, T1053.005 |
| Defense Evasion | autopatch, start-clr, timestomp, binary-inflation | T1562.001, T1027 |
| Discovery | ps, whoami, net-enum, arp, ifconfig, av-detect | T1057, T1033, T1087 |
| Lateral Movement | socks5, wmi | T1090, T1047 |
| C2 | sleep, domain-fronting, tls-cert-pin | T1071.001 |

Full TTP mapping: [threat-intel/fawkes/fawkes-ttp-mapping.md](threat-intel/fawkes/fawkes-ttp-mapping.md)

## Project Structure

```
ai-detection-engineering/
├── AGENTS.md                    # AI agent instructions (role, workflow, guardrails)
├── PROMPTS.md                   # Starter prompts for the agent
├── QUICKSTART.md                # New user walkthrough
├── docker-compose.yml           # Lab infrastructure (Elastic, Splunk, Cribl, Simulator)
├── setup.sh                     # One-command interactive setup
├── Makefile                     # Quick commands (make setup, make agent, etc.)
├── simulator/                   # Log generator (13 attack + 10 baseline scenarios)
├── autonomous/                  # Patronus multi-agent pipeline
│   ├── orchestration/           # Agent runner, state machine, budget, learnings
│   └── detection-requests/      # Detection lifecycle tracking (YAML per technique)
├── .github/workflows/           # CI/CD — daily agent runs + PR security gate
├── cribl/                       # Cribl Stream MCP server + config
├── pipeline/                    # Deployment & automation scripts
├── detections/                  # Detection-as-Code (Sigma rules by MITRE tactic)
│   └── <tactic>/compiled/       # Transpiled KQL/SPL
├── tests/                       # True positive & true negative test cases
├── templates/                   # Sigma rule template + authoring lessons
├── threat-intel/                # Threat intelligence inputs
│   ├── fawkes/                  # Fawkes C2 → ATT&CK TTP mapping
│   └── analysis/                # Scattered Spider / UNC3944 intel
├── coverage/                    # ATT&CK coverage matrix & detection backlog
├── gaps/                        # Data source and detection gaps
├── tuning/                      # Exclusion lists & tuning changelog
└── pipeline/configure_codex.py # Generate project-local Codex MCP config
```

## Autonomous Agent Pipeline (Patronus)

Ten specialized AI agents + a coordinator run the detection lifecycle end-to-end, triggered by GitHub Actions on a daily schedule or manually:

| Agent | Role | Trigger |
|-------|------|---------|
| Intel | Ingests threat reports, creates detection requests | Daily |
| Red Team (Scenario Engineer) | Generates attack + benign scenarios per technique | On intel merge |
| Author | Authors Sigma/EQL/threshold rules from scenarios | On red-team merge |
| Validation | Validates rules against ES, scores F1, retry-with-feedback | On author merge |
| Deployment | Deploys validated rules to Elastic + Splunk | Post-merge / manual |
| Tuning | Monitors alert health, auto-tunes FP exclusions | Daily |
| Coverage | Gap analysis, technique prioritization, GitHub Issues | Daily |
| Quality | Fleet health scoring, monthly reports | Daily |
| Security | PR gate — secrets scanning, rule quality checks | Every PR to master |
| Coordinator | Routes work by priority + state across agents | Always on |

Each agent creates a feature branch, commits its work, pushes, and opens a PR for human review. See [STATUS.md](STATUS.md) for current pipeline state.

### Codex CLI Integration

Agents invoke `codex exec` for reasoning tasks at key decision points:

| Agent | Reasoning task | Fallback |
|-------|----------------|----------|
| Author | Author Sigma rules from attack/benign event data | Deterministic field extraction |
| Validation | Refine rules when F1 < 0.90, up to two retries | Skip refinement |
| Red Team | Generate scenarios for techniques without hardcoded generators | Hardcoded generators where available |
| Tuning / Quality | Analyze fleet health and recommend actions | Fixed threshold scoring |
| Intel | Select reports and extract MITRE techniques from fetched text | Local reports and regex parsing |
| Security | Review rule quality | Deterministic security checks |

- **Install/authenticate**: Codex CLI **0.163.0 or later** (`npm install -g @openai/codex`), then `codex login`. Check authentication with `codex login status`.
- **Models**: `model: null` in `autonomous/orchestration/config.yml` uses the Codex CLI built-in default. Set a per-agent Codex model ID, or set `CODEX_MODEL` to override all agents. User/project model settings are not inherited by isolated reasoning calls.
- **In CI**: Model calls remain disabled; existing deterministic fallbacks require no Codex credentials.
- **Isolation**: Reasoning calls run from a temporary directory, ignore user/project configuration, and disable shell execution, local image reads, MCP, and app integrations. The read-only sandbox rejects file edits; harmless built-in interaction tools may still be advertised. Authentication still uses the Codex login session. Interactive `codex` reads `AGENTS.md` and the project's MCP config.
- **Intel fetching**: Python fetches report pages and passes text to Codex for analysis. The optional web helper uses native web search without shell access.
- **Responses**: Only the final assistant message enters JSON/YAML validation. CLI failures, empty responses, and timeouts trigger the existing fallback paths.
- **Runtime limits**: Subprocess timeouts bound requests. The legacy `max_turns` argument remains accepted for callers; Codex has no equivalent hard turn limit.
- **Budget**: `budget.py` tracks local estimates, not actual Codex subscription usage or billing.
- **Validation/deployment**: Elasticsearch validation and local CI validation are unchanged; deployment remains post-merge. `--dry-run` on the existing agent runner skips Git operations only and still executes agents.

The old `orchestration.claude_llm` import remains a compatibility shim; it invokes Codex.

Run migration checks from the repository root (Python 3.11+ for the test suite):

```bash
python3 -m unittest discover -s tests/unit -v
CODEX_CLI_INTEGRATION=1 python3 -m unittest discover -s tests/cli_integration -v
```

The first suite mocks model and SIEM calls. The opt-in suite requires the installed
Codex CLI and a loopback socket; it uses an isolated credential directory and a
localhost mock API to check actual tool exposure and read-only enforcement. It does
not contact a live model or SIEM. These checks do not establish live detection F1.
See the official [Codex CLI](https://learn.chatgpt.com/docs/codex/cli) and
[MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) documentation.

### Validation gates

Missing inputs, invalid/non-finite scores, failed checks and empty result sets block
validation. `NOT_RUN` is a blocking result, never a substitute for `PASS`.

- **PR regression** compares each changed rule path with a trusted checkout of the
  PR base, using the same TP/TN fixtures. Variants of one ATT&CK technique are
  evaluated separately. This remains a keyword smoke test; it does not implement
  full Sigma, EQL or threshold semantics. Unsupported rules and missing comparable
  baselines require SIEM validation/review and block this gate. Current F1=0 fails
  even without a baseline. Drops greater than 0.10 fail; drops greater than 0.05 warn.
- **Weekly audit** checks rule metadata, nonempty TP/TN fixtures, type-specific
  compiled artifacts, pack references and stored results (including nested
  `metrics`/`results` scores). It requires stored F1 >= 0.75 and no recorded
  validation errors. It does not rerun detections or establish artifact freshness.
  Requested evasion execution is reported as `NOT_RUN` in this offline job.
- **Validation agent** rejects errors, missing attack/benign populations and
  invalid scores before granting eligibility. A requested Elasticsearch check
  cannot pass by falling back to local matching. EQL/threshold rules require their
  SIEM validation path. Explicit offline Sigma validation remains available.

Run from the repository root:

```bash
python3 -m unittest discover -s tests/unit -v
python3 autonomous/orchestration/validation_audit.py --output-dir /tmp/validation-audit
python3 autonomous/orchestration/regression.py \
  --files detections/discovery/t1016.yml \
  --baseline-root /path/to/trusted-base-checkout \
  --output-dir /tmp/detection-regression
```

The regression CLI exits nonzero for `FAIL`, `NOT_RUN` or empty input. The workflow
uses `NOT_APPLICABLE` only after a successful Git diff proves there are no rule
source changes. CI reports are written outside the checkout so a failed run cannot
reuse a committed report. CI never rewrites accepted regression baselines; optional
reviewed snapshots are stored and read under `tests/results/regression/` by rule path.
Existing invalid evidence must be repaired and revalidated, not relabeled as passing.

### Current Detection Coverage

For live detection counts and pipeline state, see [STATUS.md](STATUS.md).
Full ATT&CK coverage matrix: [coverage/attack-matrix.md](coverage/attack-matrix.md).
Improvement roadmap (Phases 1-8): [ROADMAP.md](ROADMAP.md).

### Repository branch

`master` is the default integration branch. Open feature PRs against `master`;
the agent runner, CI filters, post-merge deployment and cleanup commands use it.
`baseline/claude-cli` retains the reviewed migration history and is no longer the
target for new work. The initial import preserves both Git histories and both MIT
copyright notices. Scheduled agents run from the default branch; SIEM deployment
still requires the configured service credentials and a reviewed merge.

For the initial import only, the regression workflow pins the old LICENSE-only
`master` commit and the reviewed PR #2 merge. It verifies ancestry and identical
rule, fixture, scenario, request and stored-result trees before reporting the
import as `NOT_APPLICABLE`. Any difference blocks that path. Subsequent PRs compare
against their actual `master` base; this does not accept the outstanding SIEM
validation gaps as passing. Deployment also skips this exact initial import so
moving the repository does not redeploy the catalog; later detection merges use
the normal deployment workflow.

## MCP Configuration

`setup.sh` creates the interactive Codex CLI's project-scoped `.codex/config.toml`.
To generate it separately, without starting or changing lab services:

```bash
python3 pipeline/configure_codex.py --siem-mode both --cribl
# Export GITHUB_PERSONAL_ACCESS_TOKEN in your shell for the optional GitHub server.
codex mcp list
```

Codex loads project configuration only after the project is trusted. Existing
`.codex/config.toml` files are preserved. Cribl is included with `--cribl` when
Node.js is installed; GitHub is included when `npx` is installed. The generated
Cribl working directory points at the current checkout/worktree. The Elasticsearch
MCP container uses the `blue-team-lab` network. Select `--siem-mode elastic`,
`both`, or `splunk` to match the lab. Splunk-only mode omits Elasticsearch MCP;
Splunk access continues through the Python REST integration.

Legacy `.mcp.json` files are preserved but are not read by Codex. Port any custom
server entries into `.codex/config.toml`; the generator creates the standard lab
servers. Local `.codex/` files are ignored by Git.

## Cribl Stream (Phase 3 — Completed 2026-03-14)

When running with `--cribl`, Cribl Stream provides a full end-to-end data pipeline:
raw vendor events → Cribl Stream normalization → indexed in SIEM(s).

- **Full data pipeline**: raw vendor events → Cribl Stream → normalized → SIEM
- **CIM normalization**: ECS fields mapped to Splunk CIM aliases
- **Log reduction**: Drop noisy baseline events before indexing
- **Routing**: Attack events to both SIEMs, baseline to Elastic only
- **Attack enrichment**: MITRE technique tags added to events
- **Structured data source gap tracking (YAML)**: gaps documented in `gaps/data-source-gaps.md`

Configure Cribl: `./pipeline/configure-cribl.sh`

## Prerequisites

- **Docker Desktop** (macOS/Windows) or Docker Engine + Compose (Linux)
- **Git**
- **~8 GB RAM**, ~20 GB free disk
- **Codex CLI >= 0.163.0**, authenticated with `codex login`
- **Python 3.10+ + pip** (orchestration, MCP configuration, and sigma-cli transpilation)

## Using as a Template

This project is designed to be forked/cloned and customized:

1. **Fork or clone** this repo
2. **Run `./setup.sh`** to start the lab
3. **Launch Codex CLI** and paste a prompt from `PROMPTS.md`
4. **Watch** the agent discover data, review threat intel, and build detections
5. **Customize**: swap Fawkes for your own threat model, add data sources, etc.

### Customizing the Threat Model

To target a different adversary:
1. Replace `threat-intel/fawkes/` with your own TTP mapping
2. Update `coverage/detection-backlog.md` with your priority techniques
3. Update `AGENTS.md` to reference your threat actor
4. Modify `simulator/simulator.py` to generate matching attack telemetry

## Useful Commands

```bash
# Lab management
docker compose ps                           # Check service status
docker compose logs -f log-simulator        # Watch simulated events
docker compose down                         # Stop everything
docker compose down -v                      # Full reset (delete all data)

# Elasticsearch
curl -u elastic:changeme http://localhost:9200/_cluster/health
curl -u elastic:changeme http://localhost:9200/sim-attack/_count

# Splunk
curl -sk https://localhost:8089/services/server/health -u admin:BlueTeamLab1!

# Sigma transpilation
sigma convert -t lucene -p ecs_windows detections/<tactic>/<rule>.yml
sigma convert -t splunk --without-pipeline detections/<tactic>/<rule>.yml
```

## License

This project is licensed under [MIT](LICENSE).

Third-party components (Elasticsearch, Splunk, Cribl, etc.) have their own licenses.
See [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md) for details. No third-party
binaries are redistributed — Docker pulls official images at runtime.
