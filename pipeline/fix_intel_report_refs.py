"""Remap intel_report references orphaned by PR #172 Batch 4 dedup.

Batch 4 deleted duplicate intel reports (kept 2026-03-22 versions).
Detection-requests still point to deleted 2026-03-08 / 2026-03-21 copies.

Strategy:
  - If a 2026-03-22 (or later) version of the same slug exists, remap there.
  - Otherwise clear intel_report to '' and record loss in tuning/changelog.

One-shot migration. Run once; idempotent.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REQUESTS_DIR = REPO_ROOT / "autonomous" / "detection-requests"
REPORTS_DIR = REPO_ROOT / "threat-intel" / "reports"


def build_slug_index() -> dict[str, str]:
    """Map slug -> most-recent report path (relative to repo root)."""
    by_slug: dict[str, tuple[str, str]] = {}
    for rpt in REPORTS_DIR.glob("*.yml"):
        m = re.match(r"^(\d{4}-\d{2}-\d{2})-(.+)\.yml$", rpt.name)
        if not m:
            continue
        date, slug = m.group(1), m.group(2)
        prior = by_slug.get(slug)
        if not prior or date > prior[0]:
            by_slug[slug] = (date, f"threat-intel/reports/{rpt.name}")
    return {slug: path for slug, (_date, path) in by_slug.items()}


def slug_from_path(path: str) -> str | None:
    m = re.match(r"^threat-intel/reports/\d{4}-\d{2}-\d{2}-(.+)\.yml$", path)
    return m.group(1) if m else None


def main() -> None:
    slug_index = build_slug_index()
    remapped = 0
    cleared = 0
    notes: list[str] = []

    for yml in sorted(REQUESTS_DIR.glob("*.yml")):
        if yml.name == "_template.yml":
            continue
        text = yml.read_text(encoding="utf-8")
        # Find intel_report line
        m = re.search(r"^(intel_report:\s*)(['\"]?)([^'\"\n]*)(\2)\s*$", text, flags=re.MULTILINE)
        if not m:
            continue
        current = m.group(3)
        if not current or (REPO_ROOT / current).exists():
            continue  # fine or empty

        slug = slug_from_path(current)
        if slug and slug in slug_index:
            new_path = slug_index[slug]
            new_line = f"{m.group(1)}{m.group(2)}{new_path}{m.group(4)}"
            text = text[:m.start()] + new_line + text[m.end():]
            remapped += 1
            notes.append(f"{yml.name}: remap {current} -> {new_path}")
        else:
            # Orphan — clear to empty string
            new_line = f"{m.group(1)}''"
            text = text[:m.start()] + new_line + text[m.end():]
            cleared += 1
            notes.append(f"{yml.name}: clear orphan {current}")

        yml.write_text(text, encoding="utf-8")

    for n in notes:
        print(n)
    print()
    print(f"Remapped to kept copy: {remapped}")
    print(f"Cleared (orphan):      {cleared}")


if __name__ == "__main__":
    main()
