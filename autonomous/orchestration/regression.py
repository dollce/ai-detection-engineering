"""Regression testing for detection rules — CI-safe, no ES dependency."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from orchestration.validation_results import (
    ValidationUnavailable, load_events, read_f1, read_json, require_no_errors, score,
)

# Project root relative to this file: autonomous/orchestration/ -> ../../
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_RESULTS_DIR = _PROJECT_ROOT / "tests" / "results"
_REGRESSION_DIR = _RESULTS_DIR / "regression"
_TP_DIR = _PROJECT_ROOT / "tests" / "true_positives"
_TN_DIR = _PROJECT_ROOT / "tests" / "true_negatives"
_DETECTIONS_DIR = _PROJECT_ROOT / "detections"

# Regression thresholds
_FAIL_DELTA = -0.10
_WARN_DELTA = -0.05


@dataclass
class RegressionResult:
    technique_id: str
    rule_name: str
    previous_f1: float | None
    current_f1: float | None
    delta: float | None
    status: str  # "PASS", "WARN", "FAIL", "NOT_RUN"
    message: str
    local_validated: bool = False  # True when current_f1 came from local keyword validator
    rule_path: str = ""


# ---------------------------------------------------------------------------
# Baseline loading
# ---------------------------------------------------------------------------

def _result_path_candidates(technique_id: str) -> list[Path]:
    """Return candidate result file paths for a technique ID."""
    normalized = technique_id.lower().replace(".", "_")
    return [
        _RESULTS_DIR / f"{technique_id}.json",
        _RESULTS_DIR / f"{normalized}.json",
    ]


def load_baseline(technique_id: str) -> float | None:
    """Load the baseline F1 score from the stored test result.

    Checks ``tests/results/{technique_id}.json`` first, then the lower-case
    dot-replaced variant as a fallback.  Returns ``None`` when no baseline
    exists.
    """
    for path in _result_path_candidates(technique_id):
        if path.exists():
            data = read_json(path)
            require_no_errors(data)
            return read_f1(data)
    return None


def _rule_key(rule_path: str) -> str:
    path = Path(rule_path)
    if not path.is_absolute():
        path = _PROJECT_ROOT / path
    try:
        return path.resolve().relative_to(_PROJECT_ROOT.resolve()).as_posix()
    except ValueError as exc:
        raise ValidationUnavailable("Rule path must be inside the repository") from exc


def _snapshot_path(technique_id: str, rule_path: str = "") -> Path:
    if rule_path:
        key = _rule_key(rule_path)
        digest = hashlib.sha256(key.encode()).hexdigest()[:16]
        name = f"{Path(key).stem}-{digest}"
    else:
        name = technique_id.lower().replace(".", "_")
    return _REGRESSION_DIR / f"{name}_regression.json"


def load_local_baseline(technique_id: str, rule_path: str = "") -> float | None:
    """Read a successful local snapshot using the same path as its writer.

    Per-rule snapshots prevent variants of one technique from sharing a baseline.
    SIEM F1 and failed/incomplete runs cannot seed a keyword-smoke baseline.
    """
    path = _snapshot_path(technique_id, rule_path)
    if not path.exists():
        return None
    data = read_json(path)
    if not isinstance(data, dict):
        raise ValidationUnavailable("Baseline must be an object")
    require_no_errors(data)
    if data.get("status") not in {"PASS", "WARN"} or data.get("method") != "local_keyword":
        raise ValidationUnavailable("Baseline is not a successful local keyword validation")
    if rule_path and data.get("rule_path") != _rule_key(rule_path):
        raise ValidationUnavailable("Baseline belongs to a different rule")
    return score(data.get("local_f1"), "Baseline F1")


# ---------------------------------------------------------------------------
# Local validation (keyword-based, CI-safe)
# ---------------------------------------------------------------------------

def _extract_detection_keywords(rule_data: dict[str, Any]) -> list[str]:
    """Pull string literals out of the Sigma detection block for keyword matching.

    This is intentionally simple — we flatten all string values from the
    detection mapping to build a set of expected keywords.  The goal is to
    detect obvious regressions (wrong field names, removed conditions) rather
    than to replicate the full Sigma evaluation engine.
    """
    detection = rule_data.get("detection", {})
    keywords: list[str] = []

    def _collect(obj: Any) -> None:
        if isinstance(obj, str):
            stripped = obj.strip()
            if stripped and len(stripped) >= 2:
                keywords.append(stripped)
        elif isinstance(obj, list):
            for item in obj:
                _collect(item)
        elif isinstance(obj, dict):
            for v in obj.values():
                _collect(v)

    for key, value in detection.items():
        if key == "condition":
            continue
        _collect(value)

    return keywords


def _event_matches_keywords(event: dict[str, Any], keywords: list[str]) -> bool:
    """Return True if the event JSON contains at least one detection keyword.

    We serialise the event to a flat string and do case-insensitive substring
    matching.  This is a best-effort heuristic suitable for CI smoke-testing.
    """
    if not keywords:
        return False
    event_text = json.dumps(event).lower()
    return any(kw.lower() in event_text for kw in keywords)


def _load_events(path: Path) -> list[dict[str, Any]]:
    return load_events(path)


def validate_local(rule_path: str, tp_path: str, tn_path: str) -> float:
    """Simplified local validator — keyword matching against TP/TN test events.

    This is NOT the full ES-based validator.  It checks whether key fields
    from the detection condition appear in the events and returns an F1 score.
    Both positive and negative fixtures are required. Missing or malformed
    inputs raise ValidationUnavailable; they never produce a fabricated score.

    Parameters
    ----------
    rule_path:
        Absolute or project-relative path to the Sigma YAML rule.
    tp_path:
        Path to the true-positive test events JSON file.
    tn_path:
        Path to the true-negative test events JSON file.

    Returns
    -------
    float
        F1 score in [0.0, 1.0]. This heuristic is not SIEM validation.
    """
    rule_file = Path(rule_path)
    tp_file = Path(tp_path)
    tn_file = Path(tn_path)

    try:
        rule_data = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValidationUnavailable(f"Cannot read rule {rule_file}: {exc}") from exc
    if not isinstance(rule_data, dict) or not isinstance(rule_data.get("detection"), dict):
        raise ValidationUnavailable("Rule must contain a detection mapping")
    detection = rule_data["detection"]
    if not isinstance(detection.get("condition"), str) or not detection["condition"].strip():
        raise ValidationUnavailable("Rule must contain a nonempty condition")
    if rule_data.get("detection_type") in {"eql", "threshold"} or any(
        key in detection for key in ("query", "sequence", "threshold")
    ) or "|" in detection["condition"]:
        raise ValidationUnavailable("EQL/threshold/correlation requires SIEM validation")

    keywords = _extract_detection_keywords(rule_data)
    if not keywords:
        raise ValidationUnavailable("No usable detection keywords; local check cannot run")

    # --- True Positives ---
    tp_events = _load_events(tp_file)

    # --- True Negatives ---
    tn_events = _load_events(tn_file)

    tp_count = sum(1 for e in tp_events if _event_matches_keywords(e, keywords))
    fn_count = len(tp_events) - tp_count
    fp_count = sum(1 for e in tn_events if _event_matches_keywords(e, keywords))
    tn_count = len(tn_events) - fp_count

    # Precision / recall / F1
    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0.0
    recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0

    if (precision + recall) == 0.0:
        return 0.0
    f1 = 2 * precision * recall / (precision + recall)
    return round(f1, 4)


# ---------------------------------------------------------------------------
# Rule discovery helpers
# ---------------------------------------------------------------------------

def _find_rule_for_technique(technique_id: str) -> Path | None:
    """Search detections/ for a Sigma rule matching the technique ID."""
    normalized = technique_id.lower().replace(".", "_")
    # e.g. t1055_001.yml
    for yml_file in _DETECTIONS_DIR.rglob("*.yml"):
        if yml_file.parent.name == "compiled":
            continue
        stem = yml_file.stem.lower()
        if stem == normalized or stem.startswith(normalized):
            return yml_file
    return None


def _find_tp_for_technique(technique_id: str) -> Path | None:
    normalized = technique_id.lower().replace(".", "_")
    candidate = _TP_DIR / f"{normalized}_tp.json"
    return candidate if candidate.exists() else None


def _find_tn_for_technique(technique_id: str) -> Path | None:
    normalized = technique_id.lower().replace(".", "_")
    candidate = _TN_DIR / f"{normalized}_tn.json"
    return candidate if candidate.exists() else None


def _rule_name_from_path(rule_path: Path | None, technique_id: str) -> str:
    if rule_path is None:
        return technique_id
    try:
        data = yaml.safe_load(rule_path.read_text(encoding="utf-8")) or {}
        return data.get("title", technique_id) if isinstance(data, dict) else technique_id
    except (yaml.YAMLError, OSError):
        return technique_id


def find_test_file(rule_path: Path, directory: Path, suffix: str) -> Path:
    """Resolve one fixture for this rule, never a sibling technique variant."""
    stems = [rule_path.stem]
    for ending in ("_eql", "_threshold"):
        if rule_path.stem.endswith(ending):
            stems.append(rule_path.stem[:-len(ending)])
    for stem in stems:
        candidate = directory / f"{stem}_{suffix}.json"
        if candidate.is_file():
            return candidate
    candidates = sorted(directory.glob(f"{rule_path.stem}_*_{suffix}.json"))
    if len(candidates) == 1:
        return candidates[0]
    reason = "ambiguous" if candidates else "missing"
    raise ValidationUnavailable(f"{rule_path.name}: {reason} {suffix.upper()} fixture")


# ---------------------------------------------------------------------------
# Core regression check
# ---------------------------------------------------------------------------

def check_regression(technique_id: str, rule_path: str,
                     baseline_root: Path | None = None) -> RegressionResult:
    """Compare a local smoke score with a comparable, independently supplied baseline.

    A PR can use a trusted base checkout. Both revisions are evaluated on the
    same current fixtures so that SIEM scores and keyword scores are never mixed.
    Missing baselines, unsupported engines and unusable fixtures block the gate.
    """
    current_f1 = None
    baseline = None
    rule_name = technique_id
    try:
        key = _rule_key(rule_path)
        rule_file = _PROJECT_ROOT / key
        rule_name = _rule_name_from_path(rule_file, technique_id)
        if rule_file.stem.endswith(("_eql", "_threshold")):
            raise ValidationUnavailable("EQL/threshold rules require SIEM validation")
        tp_file = find_test_file(rule_file, _TP_DIR, "tp")
        tn_file = find_test_file(rule_file, _TN_DIR, "tn")
        current_f1 = score(validate_local(str(rule_file), str(tp_file), str(tn_file)))
        if current_f1 == 0:
            return RegressionResult(
                technique_id, rule_name, None, current_f1, None, "FAIL",
                "No true positives detected; F1=0 cannot pass", True, key,
            )
        if baseline_root is not None:
            baseline_rule = baseline_root / key
            baseline = score(validate_local(str(baseline_rule), str(tp_file), str(tn_file)))
        else:
            baseline = load_local_baseline(technique_id, key)
        if baseline is None:
            raise ValidationUnavailable(
                "Missing comparable local baseline; supply a trusted --baseline-root "
                "or a reviewed successful per-rule snapshot"
            )
    except (OSError, ValueError, yaml.YAMLError) as exc:
        return RegressionResult(
            technique_id, rule_name, baseline, current_f1, None, "NOT_RUN",
            str(exc), current_f1 is not None, rule_path,
        )

    delta = round(current_f1 - baseline, 4)
    if delta < _FAIL_DELTA:
        status = "FAIL"
        message = f"F1 dropped {abs(delta):.2f}, exceeding {abs(_FAIL_DELTA):.2f}"
    elif delta < _WARN_DELTA:
        status = "WARN"
        message = f"F1 dropped {abs(delta):.2f}, exceeding warning threshold"
    else:
        status = "PASS"
        message = "Local keyword smoke score is within the regression threshold"
    return RegressionResult(
        technique_id, rule_name, baseline, current_f1, delta, status,
        message, True, key,
    )


# ---------------------------------------------------------------------------
# Batch processing of changed files
# ---------------------------------------------------------------------------

_TECHNIQUE_RE = re.compile(r"(t\d{4}(?:[._]\d{3})?)", re.IGNORECASE)


def _technique_id_from_filename(filename: str) -> str | None:
    """Extract a MITRE technique ID from a file path string.

    Handles patterns like ``t1055_001.yml`` and ``t1055.001.yml``.
    Returns the canonical upper-case dotted form (e.g. ``"T1055.001"``).
    """
    stem = Path(filename).stem
    match = _TECHNIQUE_RE.search(stem)
    if not match:
        return None
    raw = match.group(1).upper()
    # Normalise separator: T1055_001 -> T1055.001
    return raw.replace("_", ".", 1) if "_" in raw else raw


def check_changed_files(file_list: str | list[str],
                        baseline_root: Path | None = None) -> list[RegressionResult]:
    """Evaluate every distinct rule path, including variants of one technique."""
    paths = file_list.split() if isinstance(file_list, str) else file_list
    results = []
    seen = set()
    for file_path in paths:
        if not isinstance(file_path, str):
            results.append(RegressionResult(
                "unknown", "Invalid file entry", None, None, None, "NOT_RUN",
                "Rule paths must be strings",
            ))
            continue
        path = Path(file_path)
        if path.suffix not in {".yml", ".yaml"} or {"compiled", "packs"} & set(path.parts):
            continue
        try:
            key = _rule_key(file_path)
        except ValidationUnavailable as exc:
            results.append(RegressionResult(
                "unknown", file_path, None, None, None, "NOT_RUN", str(exc),
            ))
            continue
        if key in seen:
            continue
        seen.add(key)
        technique_id = _technique_id_from_filename(file_path) or "unknown"
        results.append(check_regression(technique_id, key, baseline_root))
    return results


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

# ASCII-safe status markers — render cleanly in GitHub Markdown and all terminals
_STATUS_EMOJI = {s: f"[ {s} ]" for s in ("PASS", "WARN", "FAIL", "NOT_RUN")}


def gate_status(results: list[RegressionResult]) -> str:
    if any(r.status == "FAIL" for r in results):
        return "FAIL"
    if not results or any(r.status not in {"PASS", "WARN"} for r in results):
        return "NOT_RUN"
    return "WARN" if any(r.status == "WARN" for r in results) else "PASS"


def generate_report(results: list[RegressionResult], output_dir: Path | None = None) -> str:
    """Generate a markdown regression report and write it to disk.

    Returns the markdown string.
    """
    lines: list[str] = [
        "## Detection Regression Test Results",
        "",
        "Local keyword smoke test only; this is not SIEM validation or deployment approval.",
        "",
        "| Rule | Previous F1 | Current F1 | Delta | Status |",
        "|------|------------|------------|-------|--------|",
    ]

    for r in results:
        emoji = _STATUS_EMOJI.get(r.status, "")
        delta_str = f"{r.delta:+.2f}" if r.delta is not None else "N/A"
        previous = f"{r.previous_f1:.2f}" if r.previous_f1 is not None else "N/A"
        current = f"{r.current_f1:.2f}" if r.current_f1 is not None else "N/A"
        lines.append(
            f"| {r.rule_path or r.technique_id} | {previous} | {current} | "
            f"{delta_str} | {emoji} {r.status} |"
        )

    lines.append("")

    lines.append(f"**Overall: {gate_status(results)}** — {len(results)} rule(s) accounted for")
    if not results:
        lines.append("No rules were evaluated. Empty input cannot pass a required check.")
    lines.append("")

    # Detail section
    if results:
        lines += ["<details><summary>Details</summary>", ""]
        for r in results:
            emoji = _STATUS_EMOJI.get(r.status, "")
            lines.append(f"- **{r.rule_path or r.technique_id}** ({r.rule_name}): {emoji} {r.message}")
        lines += ["", "</details>", ""]

    report = "\n".join(lines)

    # Write to disk
    report_path = (output_dir or _REGRESSION_DIR) / "regression-report.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")
    report_path.with_suffix(".json").write_text(json.dumps({
        "status": gate_status(results), "method": "local_keyword",
        "results": [asdict(r) for r in results],
    }, indent=2, allow_nan=False), encoding="utf-8")

    return report


# ---------------------------------------------------------------------------
# Snapshot persistence
# ---------------------------------------------------------------------------

def save_snapshot(
    results: list[RegressionResult],
    commit_sha: str = "",
    pr_number: int = 0,
) -> None:
    """Explicitly persist successful local baselines; never overwrite with a failed run."""
    _REGRESSION_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(tz=timezone.utc).isoformat()

    for r in results:
        if r.status not in {"PASS", "WARN"} or not r.local_validated or not r.rule_path:
            continue
        current_f1 = score(r.current_f1)
        if current_f1 == 0:
            continue
        snapshot_path = _snapshot_path(r.technique_id, r.rule_path)
        record: dict[str, Any] = {
            "technique_id": r.technique_id,
            "timestamp": timestamp,
            "f1_score": current_f1,
            "local_f1": current_f1,
            "rule_path": _rule_key(r.rule_path),
            "method": "local_keyword",
            "status": r.status,
            "commit_sha": commit_sha,
            "pr_number": pr_number,
        }
        snapshot_path.write_text(json.dumps(record, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run regression tests on changed detection rules (CI-safe, no ES dependency)."
    )
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--files", help="Space-separated rule paths (local use).")
    inputs.add_argument("--files-from", type=Path, help="NUL-delimited changed paths from git diff -z.")
    parser.add_argument("--baseline-root", type=Path, help="Trusted checkout of the PR base revision.")
    parser.add_argument("--output-dir", type=Path, default=_REGRESSION_DIR)
    args = parser.parse_args(argv)

    try:
        files = (args.files_from.read_text(encoding="utf-8").rstrip("\0").split("\0")
                 if args.files_from else args.files)
        results = check_changed_files(files, args.baseline_root)
    except (OSError, ValueError) as exc:
        results = [RegressionResult("unknown", "Input manifest", None, None, None,
                                    "NOT_RUN", str(exc))]
    report = generate_report(results, args.output_dir)
    print(report)
    # Reports and accepted baselines are separate: a CI run never rewrites its baseline.
    return 0 if gate_status(results) in {"PASS", "WARN"} else 1


if __name__ == "__main__":
    sys.exit(main())
