"""Normalize path fields in detection-request YAMLs.

Fixes two regressions introduced by PR #172:
  1. Windows backslash separators in path fields (break on Linux CI)
  2. scenario_file paths still pointing to simulator/scenarios/ root after
     Batch 4 moved scenarios to simulator/scenarios/windows/

Uses line-level regex replacement to preserve YAML formatting and comments.
Idempotent — safe to re-run.

Run from repo root:
    python3 pipeline/normalize_detection_paths.py
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REQUESTS_DIR = REPO_ROOT / "autonomous" / "detection-requests"
SCENARIOS_WIN = REPO_ROOT / "simulator" / "scenarios" / "windows"

PATH_FIELDS = (
    "scenario_file",
    "sigma_rule",
    "compiled_lucene",
    "compiled_spl",
    "compiled_artifact",
    "compiled_eql",
    "compiled_threshold",
    "intel_report",
)


def _fix_scenario_value(value: str) -> str:
    """Normalize backslashes and migrate old root paths to windows/ subdir."""
    value = value.replace("\\", "/")
    m = re.match(r"^simulator/scenarios/([^/]+\.json)$", value)
    if m:
        candidate = SCENARIOS_WIN / m.group(1)
        if candidate.exists():
            return f"simulator/scenarios/windows/{m.group(1)}"
    return value


def _fix_simple_value(value: str) -> str:
    return value.replace("\\", "/")


def normalize_file(yml_path: Path) -> tuple[bool, list[str]]:
    """Return (changed, notes)."""
    text = yml_path.read_text(encoding="utf-8")
    original = text
    notes: list[str] = []

    for field in PATH_FIELDS:
        pattern = rf"^({re.escape(field)}:\s*)(['\"]?)([^'\"\n]*)(\2)\s*$"

        def replacer(match: re.Match) -> str:
            prefix, quote, raw_value, _close = match.group(1), match.group(2), match.group(3), match.group(4)
            if not raw_value:
                return match.group(0)
            if field == "scenario_file":
                new_value = _fix_scenario_value(raw_value)
            else:
                new_value = _fix_simple_value(raw_value)
            if new_value != raw_value:
                notes.append(f"{field}: {raw_value!r} -> {new_value!r}")
            return f"{prefix}{quote}{new_value}{quote}"

        text = re.sub(pattern, replacer, text, flags=re.MULTILINE)

    if text != original:
        yml_path.write_text(text, encoding="utf-8")
        return True, notes
    return False, []


def main() -> None:
    if not REQUESTS_DIR.exists():
        raise SystemExit(f"detection-requests dir not found: {REQUESTS_DIR}")

    total_changed = 0
    total_field_edits = 0
    for yml in sorted(REQUESTS_DIR.glob("*.yml")):
        if yml.name == "_template.yml":
            continue
        changed, notes = normalize_file(yml)
        if changed:
            total_changed += 1
            total_field_edits += len(notes)
            print(f"[fixed] {yml.name}")
            for n in notes:
                print(f"        {n}")

    print()
    print(f"Files changed: {total_changed}")
    print(f"Field edits:   {total_field_edits}")


if __name__ == "__main__":
    main()
