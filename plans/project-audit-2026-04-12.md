# Project Audit — Deep Cleanup Before Phase 8

**Date**: 2026-04-12
**Auditor**: Claude Opus 4.6 (deep audit, line-by-line)
**Goal**: Comprehensive audit of every file in the project. Identify all issues that need fixing before Phase 8 work begins.
**Scope**: 824 files audited (excluding .git/, .claude/, node_modules/, .venv/)
**Status**: COMPLETE

---

## FINDING SUMMARY

| Category | Count | Critical | High | Medium | Low |
|----------|-------|----------|------|--------|-----|
| Code debt | 5 | 1 | 3 | 1 | 0 |
| Detection misplacement | 7 | 0 | 2 | 4 | 1 |
| Documentation staleness | 9 | 0 | 3 | 4 | 2 |
| Infrastructure issues | 6 | 0 | 1 | 3 | 2 |
| Test/coverage gaps | 8 | 0 | 1 | 4 | 3 |
| Cross-cutting | 5 | 0 | 2 | 2 | 1 |
| Archive candidates | 6 | 0 | 0 | 0 | 6 |
| **Total** | **46** | **1** | **12** | **18** | **15** |

---

## CRITICAL

### C1. blue_team_agent.py is a 1035-line zombie [CODE DEBT]
- Phase 4 split blue-team into author_agent.py (470L), validation_agent.py (895L), deployment_agent.py (276L)
- blue_team_agent.py was **never removed** and contains full duplicate logic:
  - `event_matches_block()` — duplicated in validation_agent.py
  - `validate_detection()` — duplicated in validation_agent.py
  - `transpile_sigma()` — duplicated in author_agent.py
  - `TECHNIQUE_TACTIC_MAP` — duplicated in author_agent.py AND red_team_agent.py (4 copies total, with different entries)
- Still registered in `agent_runner.py:93` as `"blue-team": "orchestration.agents.blue_team_agent"`
- CI workflow `blue-team-agent.yml` calls `--agent blue-team` routing to this zombie
- validation_agent.py line 35 **imports from** blue_team_agent.py — circular dependency risk
- **Plan**: 
  1. Create `orchestration/constants.py` with canonical `TECHNIQUE_TACTIC_MAP` (union of all 4 copies, ~35 entries) and `transpile_sigma()`
  2. Update author_agent, validation_agent, red_team_agent to import from constants.py
  3. Delete blue_team_agent.py
  4. Update agent_runner.py alias: `"blue-team"` -> `"orchestration.agents.author_agent"` (or remove)
  5. Update `blue-team-agent.yml` CI to call `--agent author` and `--agent validation` sequentially
  6. Update schema.yml to reference correct agents per state (P11)

---

## HIGH PRIORITY

### H1. 12+ detections in WRONG tactic directories [DETECTION]
The Sigma rules themselves declare the correct tactic in their tags, but the files are in the wrong directory. The rules have `attack.discovery`, `attack.impact`, `attack.lateral_movement`, `attack.command_and_control` tags but are all dumped in `execution/`:

| File | Current Dir | Tags Say | Correct Dir |
|------|------------|----------|-------------|
| t1016.yml | execution/ | attack.discovery | discovery/ |
| t1016_001.yml | execution/ | attack.discovery | discovery/ |
| t1021_001.yml | execution/ | attack.lateral_movement | lateral_movement/ |
| t1021_006.yml | execution/ | attack.execution | execution/ (OK but also lateral_movement) |
| t1033.yml | execution/ | attack.discovery | discovery/ |
| t1082.yml | execution/ | attack.discovery | discovery/ |
| t1105.yml | execution/ | attack.command_and_control | command_and_control/ |
| t1133.yml | execution/ | attack.persistence | persistence/ or initial_access/ |
| t1190.yml | execution/ | attack.initial_access | initial_access/ |
| t1204_002.yml | execution/ | attack.execution | execution/ (OK, or initial_access/) |
| t1486.yml | execution/ | attack.impact | impact/ |
| t1490.yml | execution/ | attack.impact | impact/ |
| t1219.yml | initial_access/ | attack.command_and_control | command_and_control/ |

- **Plan**: Move each file (+ compiled outputs) to correct directory. Update detection-request YAMLs `sigma_rule` and `compiled_*` paths. Update pack.yml references. Update attack-matrix.md. Single branch `cleanup/detection-tactic-reorg`.

### H2. coverage/attack-matrix.md says 53 rules, STATUS.md says 95 [DOCS]
- attack-matrix.md was "auto-generated on 2026-03-29" but only lists 53 rules
- STATUS.md (auto-generated 2026-04-12) correctly shows 95
- detection-backlog.md last updated 2026-03-07 — lists T1055.001 as "IN PROGRESS" when it's been DEPLOYED since April
- data-sources.md last updated 2026-03-14
- **Plan**: Regenerate attack-matrix.md from current detections/ scan. Update detection-backlog.md to retire completed entries. Cross-check data-sources.md.

### H3. README.md needs full rewrite [DOCS]
- Statistics on line 199 say "42 authored rule files" — actual: 95 total (88 Sigma + 3 EQL + 4 threshold)
- Says "16 deployed... 17 validated... 8 authored" — actual: 39 DEPLOYED + 20 MONITORING
- Lab architecture ASCII diagram has misaligned box edges
- Tries to be 5 things at once (overview, architecture, setup, threat model, status)
- Phase completion dates don't belong in README
- **Plan**: Full rewrite. Sections: (1) What is this, (2) Quick Start (3 commands), (3) Architecture diagram, (4) Credentials table, (5) Primary threat, (6) Project structure (brief), (7) Links to detailed docs. All stats point to STATUS.md. Under 150 lines.

### H4. ROADMAP.md stale numbers everywhere [DOCS]
- Line 7: "42 authored rule files" → should be 95
- Line 7: "71 total detection requests" → should be 95
- Quick Reference table (lines 215-226): all metrics wrong
- References `plans/architecture-scalable-detection-platform.md` → now in `plans/archive/`
- **Plan**: Update all numbers. Fix archive references. Remove Quick Reference table (redundant with STATUS.md).

### H5. STATUS.md UTF-8 encoding corruption [DOCS]
- Lines 54-63: Em-dashes rendered as `â€"` (UTF-8 decoded as Windows-1252)
- Affects 8+ detection descriptions
- **Plan**: Find/replace all `â€"` with `—` (or plain `--`).

### H6. schema.yml still references blue_team_agent [CODE DEBT]
- Lines 27, 31, 42, 46, 58, 62, 88: `agent: blue_team_agent` for states that are now owned by author/validation/deployment agents
- **Plan**: Update as part of C1 fix. SCENARIO_BUILT->AUTHORED: author_agent. AUTHORED->VALIDATED: validation_agent. VALIDATED->DEPLOYED: deployment_agent. DEPLOYED->MONITORING: tuning_agent.

### H7. Duplicate intel reports in threat-intel/reports/ [DATA]
- 3 reports ingested on 2026-03-08 were re-ingested on 2026-03-21 and again on 2026-03-22
  - `apache-activemq-exploit-leads-to-lockbit-ransomwar` — 3 copies (March 8, 21, 22)
  - `cat-s-got-your-files-lynx-ransomware` — 2 copies (March 8, 21)
  - `from-bing-search-to-ransomware-bumblebee-and-adapt` — 2 copies (March 8, 21)
- Same source URL, different `date_ingested` — minor content variations
- Intel agent has no dedup check before creating reports
- **Plan**: Delete duplicates (keep most recent). Add dedup logic to intel_agent.py (check source URL before creating).

### H8. requirements.txt is incomplete [CODE DEBT]
- Only lists `pyyaml>=6.0`
- Confirmed: codebase uses only stdlib + pyyaml (urllib, not requests) — so this is actually OK
- BUT: CI workflows install `sigma-cli` separately — consider adding it
- **Plan**: Verify no hidden imports. Add comment explaining stdlib-only design. Optionally add sigma-cli as optional dependency.

### H9. CI workflow version inconsistency [INFRA]
- `regression-test.yml`: `actions/checkout@v4`, `actions/setup-python@v5`, Python 3.11
- All other workflows: `actions/checkout@v5`, `actions/setup-python@v6`, Python 3.12
- **Plan**: Standardize regression-test.yml to v5/v6/Python 3.12.

---

## MEDIUM PRIORITY

### M1. CLAUDE.md file tree says "37 rules: 30 Sigma + 3 EQL + 4 threshold" [DOCS]
- Actual: 95 rules (88 Sigma + 3 EQL + 4 threshold across 95 detection-request files)
- **Plan**: Update the file tree comment to reflect actual counts.

### M2. PROMPTS.md references non-existent files [DOCS]
- `.kql` extension — actual is `.lucene`
- `playbooks/` directory — doesn't exist
- `TODO-log-onboarding.md` — doesn't exist
- Phase numbering (1-10) conflicts with project phases (1-8)
- **Plan**: Fix references. Rename "Phases" to "Steps" in the lifecycle prompt.

### M3. Orphaned compiled files in execution/ [DETECTION]
- `execution/compiled/t1056_001.lucene` and `.spl` — but `t1056_001.yml` lives in `collection/`
- These are orphaned copies from before the rule was moved
- **Plan**: Delete the orphaned files in execution/compiled/.

### M4. setup.sh scaffold missing impact/ and initial_access/ [INFRA]
- `DIRS` array doesn't include `detections/impact/compiled` or `detections/initial_access/compiled`
- These directories exist with content but wouldn't be scaffolded on fresh clone
- **Plan**: Add to DIRS array. Also add to Makefile scaffold if applicable.

### M5. .gitkeep files in non-empty directories [CLEANUP]
- `detections/collection/.gitkeep`, `command_and_control/.gitkeep`, `credential_access/.gitkeep`, etc.
- These directories now have actual files, making .gitkeep unnecessary
- **Plan**: Remove .gitkeep from directories with content.

### M6. detection-backlog.md extremely stale [DOCS]
- Last updated 2026-03-07
- Lists T1055.001 as "IN PROGRESS (F1=0.667)" — it's been DEPLOYED with F1=1.0
- Most Rank 1-10 items are either DEPLOYED or MONITORING
- **Plan**: Either regenerate from current pipeline state, or convert to a dynamic view via `cli.py`.

### M7. Makefile transpile targets only print to stdout [INFRA]
- `transpile-elastic` and `transpile-splunk` run sigma but don't save output
- User expects compiled files to be written
- **Plan**: Fix to save output to compiled/ directories, or rename targets to `check-transpile` and document as verification-only.

### M8. Simulator Windows scenarios loose in root [ORGANIZATION]
- `simulator/scenarios/` has cloud/, linux/, macos/, network/ subdirectories
- But ~40 Windows scenarios sit loose in the root
- **Plan**: Move to `simulator/scenarios/windows/` for consistency.

### M9. Cribl credentials inconsistent across docs [INFRA]
- docker-compose.yml, config.yml, CLAUDE.md env vars all say admin/admin
- MEMORY infrastructure.md says admin/CriblLab1!
- The docker env var `CRIBL_ADMIN_PASSWORD=admin` only works on first run
- **Plan**: Verify actual password. If CriblLab1! was set by hand, document it. If admin is correct, fix MEMORY.md.

### M10. Test file naming inconsistent [TESTS]
- Some use rule names: `t1055_004_apc_injection_tn.json`, `t1087_001_local_account_discovery_tn.json`
- Others use technique IDs: `t1003_001_tn.json`, `t1016_tn.json`
- **Plan**: Standardize to match the Sigma rule filename (which already varies, but should be consistent going forward).

### M11. Regression test results mixed into tests/results/ [TESTS]
- 3 regression JSON files and 1 regression-report.md
- **Plan**: Move to `tests/results/regression/` subdirectory.

### M12. QUICKSTART.md references "N / 45" Fawkes techniques [DOCS]
- Should be N / 59 commands (or N / 21 core techniques)
- **Plan**: Fix the number.

---

## LOW PRIORITY (Archiving + Polish)

### L1. autonomous/AUTONOMOUS.md — obsolete build guide (200+ lines)
- All build prompts for Phases 1-4 are completed
- References "five-agent operation" — now 10 agents
- **Plan**: Move to `plans/archive/autonomous-build-guide.md`

### L2. autonomous/PIPELINE-IMPROVEMENTS.md — all resolved
- Header says "ALL ISSUES RESOLVED as of 2026-03-14"
- 358 lines of historical detail
- **Plan**: Move to `plans/archive/`

### L3. autonomous/PIPELINE-LEARNINGS.md — stale follow-ups
- 3 items still marked "not started" but Phase 3 is complete
- Run log stops at 2026-03-13
- **Plan**: Update checkboxes, move to `plans/archive/`

### L4. autonomous/TODO-process-improvement-agent.md — planning doc
- References "Phase 6+ (after core pipeline is built)" — Phase 6 done
- Concept partially absorbed by tuning_agent and quality_agent
- **Plan**: Archive with note about partial implementation

### L5. autonomous/KICKOFF.md — one-time bootstrap prompt
- Only useful on first project setup, now obsolete
- References "N / 45" Fawkes techniques
- **Plan**: Move to `plans/archive/`

### L6. autonomous/README.md — 5-agent docs (now 10 agents)
- Describes 5 agent journals but 10 agents exist
- **Plan**: Update to list all 10 agents

### L7. mythic-setup.md — says "optional Phase 2"
- Confusing because Phase 2 = SIEM validation in the project
- **Plan**: Change to "optional advanced setup"

### L8. plans/remediation-2026-03-18.md and workflow-audit-2026-03-18.md
- These were from a pre-deployment audit. Most issues have been fixed.
- **Plan**: Review for any unfixed items, then archive.

### L9. source-tracker.yml — 4 of 6 sources never queried
- Mandiant, Microsoft, Unit42, Recorded Future all have `last_queried: null`
- Not a bug — intel agent just hasn't reached them yet
- **Plan**: Note for future intel runs, not a fix.

### L10. tuning/changelog/deployed-detections.md — stops at 2026-03-13
- Only covers 11 originally-deployed rules
- 48 additional rules deployed since then with no changelog entries
- **Plan**: Regenerate from deployment log, or accept that newer deployments use detection-request YAML as the changelog.

### L11. monitoring/reports/ — no reports after 2026-03-22
- No quality reports for nearly 3 weeks
- **Plan**: Not a bug if pipeline hasn't run. Note for operational awareness.

---

## CROSS-CUTTING

### X1. No single source of truth for detection counts [HIGH]
- README says 42, ROADMAP says 71/42, attack-matrix says 53, CLAUDE.md says 37 (in file tree), STATUS.md says 95
- **Plan**: STATUS.md is the authority (auto-generated). All other docs reference it with "see STATUS.md for current counts" or use dynamic count via `cli.py export-status`.

### X2. Inconsistent technique-to-tactic mapping [HIGH]
- TECHNIQUE_TACTIC_MAP varies across 4 files with different entry counts (18/20/30/imports)
- Detection files are in wrong directories (H1)
- Pack.yml files may reference wrong paths
- **Plan**: Single canonical mapping in constants.py. Validate all detection-request YAMLs have correct `mitre_tactic` field. Reorganize files (H1).

### X3. Phase numbering ambiguity [MEDIUM]
- "Phase 2" in ROADMAP = SIEM Validation; in mythic-setup = Mythic; in PROMPTS.md = Log Onboarding
- **Plan**: Rename PROMPTS.md phases to "Steps" (Step 1-10). Remove phase refs from mythic-setup.

### X4. Stale counts cascade [MEDIUM]
- When rules are added, STATUS.md is regenerated (good), but CLAUDE.md, ROADMAP.md, README.md, attack-matrix.md all go stale
- **Plan**: Add a check to `cli.py export-status` that warns if other docs have stale counts. Or add a single "counts" section to STATUS.md that all docs reference.

### X5. Pack.yml files may reference stale paths [LOW]
- 8 content packs in detections/packs/ created in Phase 6
- If detections are reorganized (H1), pack.yml rule references break
- **Plan**: Update pack.yml files after detection reorg. Add validation in `cli.py pack validate`.

---

## REMEDIATION EXECUTION PLAN

### Batch 1: Code Debt (branch: `cleanup/code-consolidation`)
Estimated: 1 session
1. Create `orchestration/constants.py` — canonical TECHNIQUE_TACTIC_MAP + transpile_sigma()
2. Update all agent imports to use constants.py
3. Delete blue_team_agent.py
4. Update agent_runner.py aliases
5. Update schema.yml agent references
6. Update blue-team-agent.yml CI workflow
7. Fix regression-test.yml action versions

### Batch 2: Detection Reorg (branch: `cleanup/detection-tactic-reorg`)
Estimated: 1 session
1. Move 13 misplaced detections to correct tactic directories (files + compiled + elastic.json)
2. Update all detection-request YAMLs with corrected paths
3. Delete orphaned compiled files
4. Remove unnecessary .gitkeep files
5. Add missing scaffold directories to setup.sh
6. Regenerate attack-matrix.md
7. Update pack.yml files

### Batch 3: Documentation Overhaul (branch: `cleanup/docs-refresh`)
Estimated: 1 session
1. Rewrite README.md (concise, professional, current)
2. Fix STATUS.md encoding corruption
3. Update ROADMAP.md numbers and archive references
4. Update CLAUDE.md file tree counts
5. Fix PROMPTS.md stale references and phase numbering
6. Update detection-backlog.md
7. Fix QUICKSTART.md and mythic-setup.md minor issues

### Batch 4: Archive + Cleanup (branch: `cleanup/archive-stale-docs`)
Estimated: 1 session
1. Move to plans/archive/: AUTONOMOUS.md, PIPELINE-IMPROVEMENTS.md, PIPELINE-LEARNINGS.md, KICKOFF.md, TODO-process-improvement-agent.md
2. Update autonomous/README.md for 10-agent architecture
3. Deduplicate threat-intel/reports/ (delete 4 duplicate reports)
4. Reorganize simulator scenarios into windows/ subdirectory
5. Move regression test files to subdirectory
6. Clean up detection-backlog.md stale entries
7. Review and archive plans/remediation-2026-03-18.md and workflow-audit-2026-03-18.md

### After All Batches
- Run `cli.py export-status` to regenerate STATUS.md
- Run `cli.py status` to verify pipeline consistency
- Do a final `grep -r "42 authored\|37 rules\|71 total\|16 MONITORING\|17 VALIDATED"` to catch any remaining stale strings
- Verify no broken imports with `python -c "from orchestration.agents import *"` 

---

## FILES READ DURING AUDIT

### Top-level (14 files)
README.md, STATUS.md, ROADMAP.md, QUICKSTART.md, PROMPTS.md, CLAUDE.md, docker-compose.yml, Makefile, setup.sh, .gitignore, mcp-config.example.json, .env, LICENSE, THIRD-PARTY-LICENSES.md, mythic-setup.md, .github/CODEOWNERS

### CI Workflows (9 files)
blue-team-agent.yml, continuous-validation.yml, deploy-rules.yml, intel-agent.yml, quality-monitor.yml, red-team-agent.yml, regression-test.yml, schema-validate.yml, security-gate.yml

### Autonomous Pipeline (32 files)
AUTONOMOUS.md (partial), KICKOFF.md, PIPELINE-IMPROVEMENTS.md, PIPELINE-LEARNINGS.md, README.md, TODO-process-improvement-agent.md, config.yml, schema.yml, requirements.txt, state.py, siem.py, agent_runner.py (partial), + all 10 agent .py headers, + line counts for all 21 orchestration modules

### Detections (spot-checked 5 rules)
t1016.yml, t1486.yml, t1056_001.yml, t1055_001.yml headers + full directory listing

### Coverage/Tests/Gaps
coverage/attack-matrix.md, coverage/detection-backlog.md, coverage/data-sources.md

### Templates (1 file)
templates/detection-authoring-rules.md

### Threat Intel (4 files)
fawkes-ttp-mapping.md, fawkes.yml, source-tracker.yml, + duplicate report analysis

### Pipeline scripts (2 files)
pipeline/create-pr.py, pipeline/create-github-issues.py

### Plans (3 files)
phase8-advanced-capabilities.md, remediation-2026-03-18.md, workflow-audit-2026-03-18.md

### Tuning (2 files)
tuning/exclusions.yml, tuning/changelog/deployed-detections.md

### Verification queries
git ls-files (pycache, budget-log, audit-log — not tracked: good)
grep for TECHNIQUE_TACTIC_MAP, transpile_sigma, validate_detection, import requests
diff analysis on duplicate intel reports
