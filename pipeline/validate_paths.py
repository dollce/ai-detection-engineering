"""Path integrity validator for the detection-engineering repo.

Fails CI if:
  1. Any detection-request YAML references a missing file (scenario_file,
     sigma_rule, compiled_lucene/spl/artifact, intel_report).
  2. Any path field contains a Windows backslash separator (breaks on Linux).
  3. Any markdown file links to `plans/phaseN-*.md` in the wrong location
     (either plans/ root when archived, or plans/archive/ when active).

Runs locally (no repo-state assumptions) — safe to invoke on any branch.

Exit codes: 0 = all clean, 1 = violations found.
"""

import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
REQUESTS_DIR = REPO_ROOT / "autonomous" / "detection-requests"
PLANS_DIR = REPO_ROOT / "plans"
PLANS_ARCHIVE = PLANS_DIR / "archive"

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

# Markdown files to scan for broken plan references
MD_GLOB_ROOTS = ("README.md", "ROADMAP.md", "CLAUDE.md", "STATUS.md", "PROMPTS.md", "QUICKSTART.md")


def validate_detection_requests() -> list[str]:
    errors: list[str] = []
    if not REQUESTS_DIR.exists():
        return [f"detection-requests dir missing: {REQUESTS_DIR}"]

    for yml in sorted(REQUESTS_DIR.glob("*.yml")):
        if yml.name == "_template.yml":
            continue
        try:
            data = yaml.safe_load(yml.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            errors.append(f"{yml.name}: YAML parse error — {exc}")
            continue

        for field in PATH_FIELDS:
            value = data.get(field, "")
            if not value:
                continue
            if "\\" in value:
                errors.append(f"{yml.name}: {field} contains backslash — {value!r}")
                continue
            target = REPO_ROOT / value
            if not target.exists():
                errors.append(f"{yml.name}: {field} references missing file — {value}")
    return errors


def validate_plan_links() -> list[str]:
    """Check markdown files don't link to archived plans at the root path."""
    errors: list[str] = []
    # Collect set of plans that ARE archived (so root-path link is broken)
    if not PLANS_ARCHIVE.exists():
        return []
    archived_names = {p.name for p in PLANS_ARCHIVE.glob("*.md")}
    # Strip _superseded suffix to catch references to the logical name too
    archived_logical = {n.replace("_superseded.md", ".md") for n in archived_names}

    # Regex for markdown link/bare ref: plans/<file>.md but not plans/archive/
    pattern = re.compile(r"(?<!archive/)plans/([a-z0-9_-]+\.md)")

    for md_name in MD_GLOB_ROOTS:
        md = REPO_ROOT / md_name
        if not md.exists():
            continue
        text = md.read_text(encoding="utf-8")
        for match in pattern.finditer(text):
            ref = match.group(1)
            # allowed: plan actually exists at plans/<ref> OR in archive (but link is wrong)
            root_path = PLANS_DIR / ref
            if root_path.exists():
                continue
            if ref in archived_names or ref in archived_logical:
                errors.append(
                    f"{md_name}: link to plans/{ref} is archived — use plans/archive/ prefix"
                )
            else:
                errors.append(f"{md_name}: link to missing plans/{ref}")
    return errors


def main() -> int:
    errors: list[str] = []
    errors.extend(validate_detection_requests())
    errors.extend(validate_plan_links())

    if errors:
        print(f"[validate_paths] {len(errors)} violation(s):")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("[validate_paths] All paths and plan links resolve.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
