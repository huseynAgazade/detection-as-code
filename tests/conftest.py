"""Fixtures for the pipeline tests.

The tests work on detections built in memory rather than on files in the
repository, so a test asserts one behaviour of one check instead of breaking
every time a real rule is edited. `make_detection` returns a minimal rule that
passes every check, and each test breaks exactly the thing it is about.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipelines.lib.catalog import Detection

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "schemas" / "detection.schema.json"


@pytest.fixture(scope="session")
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def base_variables() -> dict:
    from pipelines.lib.yamlio import load_yaml

    return load_yaml(REPO_ROOT / "environments" / "_base" / "variables.yaml")


def _valid_rule() -> dict:
    return {
        "metadata": {
            "id": "ID-AD-900",
            "name": "Test Rule For Validation",
            "description": (
                "A rule used by the test suite. It describes a behaviour in enough words "
                "to satisfy the description length gate, and it exists purely so that each "
                "test can break exactly one thing about an otherwise valid document."
            ),
            "author": "test",
            "created": "2026-01-01",
            "modified": "2026-01-02",
            "version": "1.0.0",
            "status": "stable",
            "severity": "medium",
            "confidence": "medium",
            "mitre": [
                {
                    "tactic": "Credential Access",
                    "tactic_id": "TA0006",
                    "technique": "Brute Force: Password Spraying",
                    "technique_id": "T1110.003",
                }
            ],
            "data_sources": ["Windows Security Event Log"],
            "platforms": ["splunk"],
            "risk": {
                "objects": [{"field": "src", "type": "system", "score": 50}],
                "message": "Suspicious authentication activity observed from $src$.",
            },
            "false_positives": ["A documented benign cause with enough detail to check."],
            "triage": ["A first investigation step with enough detail to follow."],
            "references": ["https://attack.mitre.org/techniques/T1110/003/"],
        },
        "detection": {
            "splunk": {
                "schedule": {"cron": "*/5 * * * *", "earliest": "-20m", "latest": "-5m"},
                "query": (
                    "index=windows EventCode=4625\n"
                    "| stats count AS failures BY src\n"
                    "| where failures > 10\n"
                    "| table src, failures\n"
                ),
                "throttle": {"fields": ["src"], "period": "6h"},
            }
        },
    }


@pytest.fixture
def make_detection():
    """Build a Detection, optionally mutating the valid baseline first."""

    def _make(mutate=None, relative: str = "identity/active_directory/test_rule.yaml") -> Detection:
        data = _valid_rule()
        if mutate is not None:
            mutate(data)
        path = Path("detections") / relative
        return Detection(path=path, relative=Path(relative), data=data)

    return _make
