# Quick Start — For New Users

Welcome! This project lets you run an **AI-powered detection engineering agent** that
autonomously builds security detections against a real C2 framework.

## What You Need

- **Docker Desktop** (Mac/Windows) or Docker + Docker Compose (Linux)
- **Codex CLI 0.163.0 or later**, with an authenticated Codex account
- **Python 3.10+** for orchestration and MCP configuration
- **~8GB RAM** available for the lab
- **30 minutes** for initial setup

## Setup

```bash
# 1. Clone the repo
git clone <your-repo-url>
cd ai-detection-engineering

# 2. Run setup (interactive — picks your SIEM, installs everything)
make setup

# 3. Install and authenticate Codex, then launch
npm install -g @openai/codex
codex login
make agent
```

That's it. The setup script will:
- Install detection tooling (sigma-cli)
- Start your SIEM (Elastic or Splunk — your choice)
- Start a log simulator that generates realistic attack telemetry
- Create project-local Codex MCP configuration (`.codex/config.toml`)
- Initialize git

If you only need to configure Codex for an existing lab, run
`python3 pipeline/configure_codex.py --siem-mode both --cribl`, then `codex mcp list`. The generator
preserves an existing `.codex/config.toml`; legacy `.mcp.json` settings need to be
ported manually. Export `GITHUB_PERSONAL_ACCESS_TOKEN` before launching Codex to use
the optional GitHub MCP server.

Interactive Codex follows `AGENTS.md`. The pipeline's reasoning subprocesses run
with shell/external integrations and project configuration disabled in a read-only
sandbox; Python retains SIEM operations and validation. `--dry-run` on `agent_runner.py` skips Git changes only, not execution.

## What Happens Next

When Codex CLI opens, trust the project so its MCP configuration can load, then paste the **first-run prompt** from `PROMPTS.md`.
The agent will:

1. Discover what data is available in your SIEM
2. Review threat intelligence about the Fawkes C2 agent
3. Identify detection coverage gaps
4. Start building detections — writing Sigma rules, testing them
   against live data, and preparing a PR for post-merge deployment

You can watch it work, ask it questions, or guide it to focus on specific techniques.

## Choose Your Adventure

| I want to... | Do this |
|---|---|
| Just watch the agent work | Paste the first-run prompt and observe |
| Build a specific detection | Use the "Build First Detection" prompt from PROMPTS.md |
| Focus on a specific MITRE tactic | Ask the agent: "Build all persistence detections" |
| See the SIEM UI | Elastic: http://localhost:5601 / Splunk: http://localhost:8000 |
| Add real attack traffic | Follow `mythic-setup.md` to set up Fawkes C2 |
| Write detections manually | Use `templates/sigma-template.yml` as a starting point |

## For Presentations / Knowledge Shares

Great demo flow:

1. Show the lab architecture (README has a diagram)
2. Show the SIEM with simulated logs flowing in
3. Show the Fawkes C2 TTP mapping (`threat-intel/fawkes/fawkes-ttp-mapping.md`)
4. Launch Codex CLI and paste the "Build First Detection" prompt
5. Watch the agent write a Sigma rule, test it, and prepare its review PR
6. Show the MITRE coverage matrix updating in real time
7. Discuss: AI agents performing real security engineering work

## Common Questions

**Q: Is this safe to run?**
A: Yes. The log simulator generates fake events — no real attacks. The optional
Mythic/Fawkes setup should only run on an isolated lab network.

**Q: How are model calls authenticated and configured?**
A: Run `codex login` and check `codex login status`. The pipeline uses the Codex CLI
built-in default model; set `CODEX_MODEL` or an agent model in
`autonomous/orchestration/config.yml` to choose another available Codex model.
Model access and usage limits depend on your account. CI keeps deterministic fallbacks.

**Q: Can I use this with my company's SIEM?**
A: The Sigma rules are portable. Transpile them to your SIEM's query language
and the detections work anywhere. Don't point the agent at production without review.

**Q: Can I swap in a different threat model?**
A: Yes. Replace `threat-intel/fawkes/` with your own TTP mapping, update the backlog,
and modify the simulator to match. See README for details.

**Q: How do I stop everything?**
A: `make down` stops containers (keeps data). `make clean` deletes everything.
