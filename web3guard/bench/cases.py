"""Labeled calibration cases for the confirmation and live layers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CalibrationCase:
    name: str
    target: str
    category: str
    language: str
    expect_confirmed: bool
    poc: str = ""


def _load(manifest: Path | str) -> list[CalibrationCase]:
    path = Path(manifest)
    data = json.loads(path.read_text(encoding="utf-8"))
    cases: list[CalibrationCase] = []
    for raw in data.get("cases", []):
        cases.append(CalibrationCase(
            name=str(raw["name"]),
            target=str(raw["target"]),
            category=str(raw.get("category", "")),
            language=str(raw.get("language", "")),
            expect_confirmed=bool(raw.get("expect_confirmed", False)),
            poc=str(raw.get("poc", "")),
        ))
    return cases


def load_cases(manifest: Path | str) -> list[CalibrationCase]:
    return _load(manifest)


def load_live_cases(manifest: Path | str) -> list[CalibrationCase]:
    return _load(manifest)
