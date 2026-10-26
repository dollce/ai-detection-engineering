"""Offline audit of stored evidence. This does not rerun detections in a SIEM."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import sys

import yaml

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from orchestration.regression import find_test_file
from orchestration.validation_results import (
    ValidationUnavailable, load_events, read_f1, read_json, require_no_errors, score,
)


@dataclass
class Check:
    target: str
    check: str
    status: str
    message: str
    f1: float | None = None


def overall_status(checks: list[Check]) -> str:
    if any(check.status == "FAIL" for check in checks):
        return "FAIL"
    if not checks or any(check.status != "PASS" for check in checks):
        return "NOT_RUN"
    return "PASS"


def _yaml(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise ValidationUnavailable(f"Cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValidationUnavailable(f"{path}: expected a YAML mapping")
    return data


def _inside(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative.strip():
        raise ValidationUnavailable("Missing artifact path")
    path = (root / relative.replace("\\", "/")).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValidationUnavailable("Artifact path must be inside the repository")
    return path


def _nonempty(path: Path) -> None:
    if not path.is_file() or not path.read_text(encoding="utf-8").strip():
        raise ValidationUnavailable(f"Missing or empty artifact: {path}")


def audit(root: Path, technique_filter: str = "", min_f1: float = 0.75,
          include_evasion: bool = False) -> list[Check]:
    """Account for every rule and required input; never silently skip bad records."""
    root = root.resolve()
    min_f1 = score(min_f1, "Minimum F1")
    checks: list[Check] = []
    requests: dict[str, list[dict]] = {}
    for path in sorted((root / "autonomous/detection-requests").glob("*.yml")):
        try:
            request = _yaml(path)
            if request.get("sigma_rule"):
                key = _inside(root, request["sigma_rule"]).relative_to(root).as_posix()
                requests.setdefault(key, []).append(request)
        except (OSError, ValueError) as exc:
            checks.append(Check(str(path.relative_to(root)), "request", "NOT_RUN", str(exc)))

    rules = sorted(path for path in (root / "detections").rglob("*")
                   if path.suffix in {".yml", ".yaml"}
                   and not {"compiled", "packs"} & set(path.relative_to(root).parts))
    selected = 0
    for path in rules:
        key = path.relative_to(root).as_posix()
        matches = requests.get(key, [])
        request = matches[0] if len(matches) == 1 else {}
        technique = str(request.get("technique_id", ""))
        if technique_filter and technique.upper() != technique_filter.upper():
            continue
        selected += 1
        rule = {}
        try:
            rule = _yaml(path)
            for field in ("title", "id", "description", "logsource", "detection"):
                if not rule.get(field):
                    raise ValidationUnavailable(f"Missing required field: {field}")
            if not isinstance(rule["detection"], dict) or not rule["detection"].get("condition"):
                raise ValidationUnavailable("Missing detection condition")
            checks.append(Check(key, "syntax", "PASS", "Required rule fields present"))
        except (OSError, ValueError) as exc:
            checks.append(Check(key, "syntax", "NOT_RUN", str(exc)))

        for suffix, directory in (("tp", "true_positives"), ("tn", "true_negatives")):
            try:
                fixture = find_test_file(path, root / "tests" / directory, suffix)
                events = load_events(fixture)
                checks.append(Check(key, suffix, "PASS", f"{len(events)} event(s): {fixture.name}"))
            except (OSError, ValueError) as exc:
                checks.append(Check(key, suffix, "NOT_RUN", str(exc)))

        rule_type = request.get("rule_type", rule.get("detection_type", "sigma"))
        try:
            if len(matches) != 1:
                raise ValidationUnavailable(f"Expected one detection request; found {len(matches)}")
            if rule_type not in {"sigma", "eql", "threshold"}:
                raise ValidationUnavailable(f"Unsupported rule type: {rule_type}")
            compiled = path.parent / "compiled"
            _nonempty(_inside(root, request.get("compiled_spl") or
                               str((compiled / f"{path.stem}.spl").relative_to(root))))
            if rule_type == "sigma":
                _nonempty(_inside(root, request.get("compiled_lucene") or
                                   str((compiled / f"{path.stem}.lucene").relative_to(root))))
            else:
                artifact = read_json(_inside(root, request.get("compiled_artifact", "")))
                if not isinstance(artifact, dict) or artifact.get("type") != rule_type or not artifact.get("query"):
                    raise ValidationUnavailable(f"Invalid {rule_type} compiled artifact")
                if rule_type == "threshold" and not artifact.get("threshold"):
                    raise ValidationUnavailable("Missing threshold configuration")
            checks.append(Check(key, "compiled", "PASS", "Required artifacts present (freshness not evaluated)"))
        except (OSError, ValueError) as exc:
            checks.append(Check(key, "compiled", "NOT_RUN", str(exc)))

        try:
            if not technique or len(matches) != 1:
                raise ValidationUnavailable("Cannot identify a unique result for this rule")
            result_path = _inside(root, f"tests/results/{technique.lower().replace('.', '_')}.json")
            stored = read_json(result_path)
            f1 = read_f1(stored)
            try:
                require_no_errors(stored)
            except ValidationUnavailable as exc:
                checks.append(Check(key, "stored_result", "FAIL", str(exc)))
                continue
            if rule_type in {"eql", "threshold"} and stored.get("validation_method") != f"elasticsearch_{rule_type}":
                raise ValidationUnavailable(f"No {rule_type} SIEM validation evidence")
            status = "PASS" if f1 >= min_f1 else "FAIL"
            checks.append(Check(key, "stored_result", status,
                                f"Stored F1={f1:.3f}; minimum={min_f1:.2f}. No fresh execution.", f1))
        except (OSError, ValueError) as exc:
            checks.append(Check(key, "stored_result", "NOT_RUN", str(exc)))

    if selected == 0:
        checks.append(Check(technique_filter or "catalog", "discovery", "NOT_RUN", "No rules selected"))

    packs = root / "detections/packs"
    pack_dirs = sorted(p for p in packs.iterdir() if p.is_dir()) if packs.is_dir() else []
    if not pack_dirs:
        checks.append(Check("packs", "manifest", "NOT_RUN", "No pack manifests found"))
    else:
        for pack in pack_dirs:
            try:
                manifest = _yaml(pack / "pack.yml")
                for field in ("name", "version", "rules", "quality"):
                    if not manifest.get(field):
                        raise ValidationUnavailable(f"Missing required pack field: {field}")
                if not isinstance(manifest["rules"], list):
                    raise ValidationUnavailable("Pack rules must be a list")
                for entry in manifest["rules"]:
                    if not isinstance(entry, dict):
                        raise ValidationUnavailable("Invalid pack rule entry")
                    _nonempty(_inside(root, entry.get("path", "")))
                checks.append(Check(pack.name, "manifest", "PASS", "Pack references exist"))
            except (OSError, ValueError) as exc:
                checks.append(Check(pack.name, "manifest", "NOT_RUN", str(exc)))
    if include_evasion:
        checks.append(Check("evasion", "execution", "NOT_RUN",
                            "This offline audit cannot execute evasion tests; use the SIEM validation path"))
    return checks


def write_report(checks: list[Check], output_dir: Path) -> str:
    output_dir.mkdir(parents=True, exist_ok=True)
    counts = {status: sum(c.status == status for c in checks) for status in ("PASS", "FAIL", "NOT_RUN")}
    results = [c for c in checks if c.check == "stored_result"]
    scores = [c.f1 for c in results if c.f1 is not None]
    summary = {
        "status": overall_status(checks), "method": "stored_evidence_audit",
        "counts": counts, "stored_results_expected": len(results), "stored_results_read": len(scores),
        "average_stored_f1": sum(scores) / len(scores) if scores else None,
        "checks": [asdict(c) for c in checks],
    }
    (output_dir / "validation-audit.json").write_text(json.dumps(summary, indent=2, allow_nan=False), encoding="utf-8")
    lines = ["## Stored Validation Evidence Audit", "",
             "Offline artifact and stored-result checks only. No SIEM queries or evasion tests were executed.", "",
             f"**Overall: {summary['status']}** — {counts}",
             f"Stored results read: {len(scores)}/{len(results)}. Missing/error results are excluded from the average, not from the gate.", "",
             "| Target | Check | Status | Detail |", "|---|---|---|---|"]
    for check in checks:
        if check.status != "PASS":
            detail = check.message.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {check.target} | {check.check} | {check.status} | {detail} |")
    report = "\n".join(lines) + "\n"
    (output_dir / "validation-audit.md").write_text(report, encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--technique", default="")
    parser.add_argument("--min-f1", type=float, default=0.75)
    parser.add_argument("--include-evasion", action="store_true")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        checks = audit(args.root, args.technique, args.min_f1, args.include_evasion)
    except (OSError, ValueError) as exc:
        checks = [Check("audit", "execution", "NOT_RUN", str(exc))]
    print(write_report(checks, args.output_dir))
    return 0 if overall_status(checks) == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
