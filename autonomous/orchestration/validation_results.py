"""Strict readers shared by offline validation gates.

An absent, malformed, or non-finite result is not a successful validation.
These readers do not execute a SIEM query or confer deployment eligibility.
"""

import json
import math
from pathlib import Path


class ValidationUnavailable(ValueError):
    """A required input or validation result cannot be used."""


def score(value, name="F1") -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationUnavailable(f"{name} must be a number")
    if not math.isfinite(value) or not 0 <= value <= 1:
        raise ValidationUnavailable(f"{name} must be finite and between 0 and 1")
    return float(value)


def read_f1(record: dict) -> float:
    """Accept the historical flat, metrics, and results schemas explicitly."""
    if not isinstance(record, dict):
        raise ValidationUnavailable("Validation result must be an object")
    values = []
    for container in (record, record.get("metrics", {}), record.get("results", {})):
        if not isinstance(container, dict):
            raise ValidationUnavailable("metrics/results must be objects")
        for key in ("f1_score", "f1"):
            if key in container:
                values.append(score(container[key]))
    if not values:
        raise ValidationUnavailable("Missing F1 score")
    if any(value != values[0] for value in values):
        raise ValidationUnavailable("Conflicting F1 scores")
    return values[0]


def require_no_errors(record: dict) -> None:
    if not isinstance(record, dict):
        raise ValidationUnavailable("Validation result must be an object")
    for container in (record, record.get("metrics", {}),
                      record.get("results", {}),
                      record.get("validation_details", {})):
        if not isinstance(container, dict):
            raise ValidationUnavailable("Validation details must be an object")
        errors = container.get("errors", [])
        if not isinstance(errors, list):
            raise ValidationUnavailable("Validation errors must be a list")
        if errors:
            raise ValidationUnavailable("Validation reported errors: " + "; ".join(map(str, errors)))
        if container.get("error"):
            raise ValidationUnavailable(f"Validation reported error: {container['error']}")
        if "status" in container:
            status = str(container["status"]).upper()
            if status not in {"PASS", "WARN", "SUCCESS", "SUCCEEDED", "COMPLETED", "VALIDATED"}:
                raise ValidationUnavailable(f"Validation status is not successful: {status}")
    if record.get("quality_tier") == "needs_rework":
        raise ValidationUnavailable("Validation needs rework")


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValidationUnavailable(f"Cannot read {path}: {exc}") from exc


def load_events(path: Path) -> list[dict]:
    """Read real event objects, including the repository's fixture wrappers."""
    raw = read_json(path)
    if isinstance(raw, dict):
        for key in ("attack_events", "benign_events", "events"):
            if key in raw:
                raw = raw[key]
                break
        else:
            # A fixture wrapper contains a complete event under `event`.
            # An ECS event's `event` field contains code/category, not a log.
            nested = raw.get("event")
            if isinstance(nested, dict) and any(
                key in nested for key in ("@timestamp", "event", "process", "host", "winlog")
            ):
                raw = nested
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list) or not raw:
        raise ValidationUnavailable(f"{path}: expected a nonempty event list")
    for event in raw:
        if not isinstance(event, dict) or not event or not (any(
            key in event for key in ("@timestamp", "event", "process", "host", "winlog", "user",
                                     "file", "registry", "source", "destination", "message",
                                     "cloud", "network")
        ) or any("." in key for key in event)):
            raise ValidationUnavailable(f"{path}: invalid event object")
    return raw
