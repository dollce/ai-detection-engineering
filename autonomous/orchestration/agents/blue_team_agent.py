"""
Blue Team Agent — COMPATIBILITY SHIM (Phase 4 refactor)

This file has been replaced by three specialized agents:
  - orchestration.agents.author_agent     (SCENARIO_BUILT → AUTHORED)
  - orchestration.agents.validation_agent (AUTHORED → VALIDATED)
  - orchestration.agents.deployment_agent (VALIDATED → DEPLOYED)

The agent_runner.py alias 'blue-team' now resolves to author_agent.
The CI workflow blue-team-agent.yml now calls --agent author.

This shim exists only to prevent ImportError if any external tool still
references blue_team_agent by name.  All symbols are re-exported from
their canonical homes.

Do NOT add logic here.  Add it to the appropriate specialized agent.
"""

# Re-export key symbols so legacy imports don't fail.
from orchestration.constants import (  # noqa: F401
    TECHNIQUE_TACTIC_MAP,
    transpile_sigma,
)
from orchestration.agents.author_agent import (  # noqa: F401
    SYSMON_CATEGORIES,
    load_scenario,
    determine_logsource,
    generate_sigma_rule,
    save_sigma_rule,
    save_compiled,
    save_test_cases,
    _get_nested,
)
from orchestration.agents.validation_agent import (  # noqa: F401
    event_matches_block,
    validate_detection,
)


def run(state_manager):
    """Delegate to author_agent for backward-compat pipeline runs."""
    import importlib
    author = importlib.import_module("orchestration.agents.author_agent")
    return author.run(state_manager)
