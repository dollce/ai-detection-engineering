"""
Shared constants for the Patronus detection engineering pipeline.

This module is the single source of truth for:
  - TECHNIQUE_TACTIC_MAP   — MITRE technique prefix → primary tactic directory
  - TECHNIQUE_PLATFORM_MAP — technique → target platforms (defaults to windows)
  - transpile_sigma()      — Sigma rule → (Lucene, SPL) compilation

Previously duplicated across blue_team_agent.py, author_agent.py,
red_team_agent.py (4 copies with diverging entries).  Any discrepancy
between those copies was resolved in favour of the MITRE ATT&CK v15
primary tactic.

Conflict resolutions (documented):
  T1053 → persistence      (Scheduled Task/Job — primary tactic per MITRE)
  T1078 → initial_access   (Valid Accounts — detection files live in initial_access/)
  T1134 → privilege_escalation  (Access Token Manipulation — primary tactic per MITRE)
"""

import re
import subprocess
from pathlib import Path

# Repo root is three levels up from this file:
#   autonomous/orchestration/constants.py → autonomous/orchestration/ → autonomous/ → <root>
REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# ─── Canonical MITRE technique → tactic directory mapping ──────────
# Union of all 4 prior copies; conflicts resolved per MITRE ATT&CK v15.
# Keys are technique prefixes (first component before the dot).
TECHNIQUE_TACTIC_MAP: dict[str, str] = {
    "T1003": "credential_access",       # OS Credential Dumping
    "T1016": "discovery",               # System Network Configuration Discovery
    "T1021": "lateral_movement",        # Remote Services
    "T1027": "defense_evasion",         # Obfuscated Files or Information
    "T1033": "discovery",               # System Owner/User Discovery
    "T1036": "defense_evasion",         # Masquerading
    "T1046": "discovery",               # Network Service Discovery
    "T1047": "execution",               # Windows Management Instrumentation
    "T1049": "discovery",               # System Network Connections Discovery
    "T1053": "persistence",             # Scheduled Task/Job (primary tactic)
    "T1055": "privilege_escalation",    # Process Injection
    "T1056": "collection",              # Input Capture
    "T1057": "discovery",               # Process Discovery
    "T1059": "execution",               # Command and Scripting Interpreter
    "T1068": "privilege_escalation",    # Exploitation for Privilege Escalation
    "T1069": "discovery",               # Permission Groups Discovery
    "T1070": "defense_evasion",         # Indicator Removal
    "T1071": "command_and_control",     # Application Layer Protocol
    "T1078": "initial_access",          # Valid Accounts
    "T1082": "discovery",               # System Information Discovery
    "T1083": "discovery",               # File and Directory Discovery
    "T1087": "discovery",               # Account Discovery
    "T1090": "command_and_control",     # Proxy
    "T1105": "command_and_control",     # Ingress Tool Transfer
    "T1112": "defense_evasion",         # Modify Registry
    "T1113": "collection",              # Screen Capture
    "T1115": "collection",              # Clipboard Data
    "T1133": "initial_access",          # External Remote Services
    "T1134": "privilege_escalation",    # Access Token Manipulation (primary tactic)
    "T1135": "discovery",               # Network Share Discovery
    "T1190": "initial_access",          # Exploit Public-Facing Application
    "T1197": "defense_evasion",         # BITS Jobs
    "T1204": "execution",               # User Execution
    "T1219": "command_and_control",     # Remote Access Software
    "T1486": "impact",                  # Data Encrypted for Impact
    "T1489": "impact",                  # Service Stop
    "T1490": "impact",                  # Inhibit System Recovery
    "T1497": "defense_evasion",         # Virtualization/Sandbox Evasion
    "T1518": "discovery",               # Software Discovery
    "T1543": "persistence",             # Create or Modify System Process
    "T1547": "persistence",             # Boot or Logon Autostart Execution
    "T1552": "credential_access",       # Unsecured Credentials
    "T1555": "credential_access",       # Credentials from Password Stores
    "T1560": "collection",              # Archive Collected Data
    "T1562": "defense_evasion",         # Impair Defenses
    "T1566": "initial_access",          # Phishing
    "T1569": "execution",               # System Services
    "T1573": "command_and_control",     # Encrypted Channel
    "T1620": "defense_evasion",         # Reflective Code Loading
}

# Techniques that are NOT Windows-primary — override the ["windows"] default
TECHNIQUE_PLATFORM_MAP: dict[str, list[str]] = {
    "T1053.003": ["linux"],             # crontab
    "T1543.001": ["macos"],             # LaunchAgent plist
    "T1552.004": ["linux", "macos"],    # SSH private keys
    "T1555.001": ["macos"],             # macOS keychain
}


def resolve_tactic(technique_id: str, request: dict | None = None) -> str:
    """Return the MITRE tactic directory for a technique ID.

    Falls back to the prefix lookup in TECHNIQUE_TACTIC_MAP.  If request
    is provided and contains a non-empty 'mitre_tactic' field, that value
    takes precedence (allows per-rule overrides).
    """
    if request:
        tactic = request.get("mitre_tactic", "")
        if tactic and tactic not in ("", "unknown"):
            return tactic
    prefix = technique_id.split(".")[0]
    return TECHNIQUE_TACTIC_MAP.get(prefix, "unknown")


def resolve_platforms(technique_id: str) -> list[str]:
    """Return the target platforms for a technique (defaults to ['windows'])."""
    return TECHNIQUE_PLATFORM_MAP.get(technique_id, ["windows"])


def transpile_sigma(rule_path: Path) -> tuple[str, str]:
    """
    Transpile a Sigma rule to Lucene (Elasticsearch) and SPL (Splunk).

    Returns (lucene_query, spl_query).  Empty strings on failure.

    Post-processing applied to Lucene output:
      - Strips 'Parsing Sigma rules...' preamble lines emitted by sigma-cli
      - Strips 'winlog.channel:<channel> AND' prefix added by the ecs_windows
        pipeline (that field is absent in sim-* lab indices)
    """
    lucene = ""
    spl = ""

    try:
        result = subprocess.run(
            ["sigma", "convert", "-t", "lucene", "-p", "ecs_windows", str(rule_path)],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        lucene = result.stdout.strip()
        if result.returncode != 0:
            print(f"    [constants] Lucene transpile warning: {result.stderr.strip()[:200]}")
        # Strip sigma-cli preamble lines ("Parsing Sigma rules...")
        lucene = "\n".join(
            line for line in lucene.splitlines()
            if not line.startswith("Parsing Sigma")
        )
        # Strip winlog.channel prefix added by ecs_windows pipeline
        lucene = re.sub(r"^winlog\.channel:\S+ AND ", "", lucene.strip())
    except Exception as exc:
        print(f"    [constants] Lucene transpile failed: {exc}")

    try:
        result = subprocess.run(
            ["sigma", "convert", "-t", "splunk", "--without-pipeline", str(rule_path)],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        spl = result.stdout.strip()
        if result.returncode != 0:
            print(f"    [constants] SPL transpile warning: {result.stderr.strip()[:200]}")
    except Exception as exc:
        print(f"    [constants] SPL transpile failed: {exc}")

    return lucene, spl
