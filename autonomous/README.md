# Agent Learnings & Self-Improvement

This directory contains each agent's learning journal. Agents record errors,
inefficiencies, workarounds, and improvement ideas during every run.
Future runs read these notes to avoid repeating mistakes and to adopt
proven solutions.

## How It Works

1. **Every agent run** reads its own journal before starting work
2. **During the run**, the agent appends entries for anything notable
3. **After the run**, the agent writes a brief retrospective
4. **Future runs** check the journal for relevant lessons before each task
5. **Periodically**, the quality monitor reviews ALL journals and
   cross-pollinates lessons between agents

## Journal Format

Each agent has its own file: `learnings/<agent-name>.jsonl`

Entries are append-only JSONL (one JSON object per line):

```json
{
  "timestamp": "2025-03-15T10:30:00Z",
  "agent": "blue-team",
  "run_id": "blue-2025-03-15-001",
  "type": "error | inefficiency | workaround | idea | resolved",
  "category": "sigma | splunk | elastic | mcp | git | data | tuning | process",
  "technique_id": "T1055.001",
  "title": "Sigma wildcard syntax doesn't transpile to SPL correctly",
  "description": "When using |endswith modifier in Sigma, the Splunk backend generates `field=\"*value\"` instead of `field=*value`. This causes zero results in Splunk.",
  "resolution": "Use |contains instead of |endswith for Splunk compatibility, or post-process the SPL output to fix quoting.",
  "status": "resolved | open | wontfix",
  "references": ["detections/defense_evasion/t1055_001.yml", "PR #42"],
  "impact": "high | medium | low",
  "tokens_wasted": 5000,
  "reusable": true
}
```

## Entry Types

| Type | When to Record |
|------|---------------|
| **error** | Something failed — query syntax, API error, deployment failure |
| **inefficiency** | Something worked but wasted tokens/time — unnecessary MCP calls, redundant searches, overly verbose output |
| **workaround** | Found a non-obvious solution to a recurring problem |
| **idea** | Thought of a better approach but didn't implement it this run |
| **resolved** | A previously open issue was fixed — link to the fix |

## 10-Agent Architecture (Phase 4+)

The pipeline uses 10 specialized agents + a coordinator (Phase 4 refactor):

| Agent | Role | Key File |
|-------|------|----------|
| Intel | Ingests threat reports, creates detection requests | `orchestration/agents/intel_agent.py` |
| Red Team | Generates attack + benign scenarios per technique | `orchestration/agents/red_team_agent.py` |
| Author | Authors Sigma/EQL/threshold rules from scenarios | `orchestration/agents/author_agent.py` |
| Validation | Tests rules against ES, scores F1, retry-with-feedback | `orchestration/agents/validation_agent.py` |
| Deployment | Deploys validated rules to Elastic + Splunk | `orchestration/agents/deployment_agent.py` |
| Tuning | Monitors alert health, auto-tunes FP exclusions | `orchestration/agents/tuning_agent.py` |
| Coverage | Gap analysis, technique prioritization, GitHub Issues | `orchestration/agents/coverage_agent.py` |
| Quality | Fleet health scoring, daily monitoring reports | `orchestration/agents/quality_agent.py` |
| Security | PR gate — secrets scanning, rule quality checks | `orchestration/agents/security_agent.py` |
| Coordinator | Routes work by priority + state | `orchestration/agents/coordinator_agent.py` |

Run agents: `cd autonomous && python3 orchestration/agent_runner.py --agent <name>`
Check state: `cd autonomous && python3 orchestration/cli.py status`

## Agent-Specific Guidance

### Intel Agent
- Track: sources that consistently yield good/bad results
- Track: report formats that are hard to parse vs easy
- Improve: which query patterns find the most relevant TTPs per token

### Red Team Agent
- Track: log schema mismatches between scenario output and SIEM expectations
- Track: which Sysmon event codes are hardest to simulate accurately
- Improve: build a library of verified-good event templates per technique

### Author Agent (formerly Blue Team)
- Track: Sigma transpilation failures per backend (Splunk vs Elastic)
- Track: detection logic patterns that consistently produce FPs
- Improve: build a "don't do this" list for detection authoring

### Validation Agent
- Track: F1 failures and root causes (field mapping, scenario mismatch)
- Track: rules that needed multiple refinement iterations
- Improve: refinement prompt patterns that reliably increase F1

### Tuning Agent (formerly Quality Monitor)
- Track: detection decay patterns (rules that degrade over time)
- Track: tuning recommendations that were accepted vs rejected by human
- Improve: refine health score weights based on which metrics predict problems

### Security Agent
- Track: false positive patterns (what triggers secrets scan but isn't a secret)
- Track: which agents produce the most security issues
- Improve: refine scan-patterns.yml to reduce FP rate

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
See the official [Codex CLI](https://learn.chatgpt.com/docs/codex/cli) and
[MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) documentation.
