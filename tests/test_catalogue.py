"""End-to-end checks against the real catalogue.

These are the tests that fail when a rule is added carelessly rather than when
the pipeline code is changed. They run the same entry points CI runs, so a green
local test run means a green pipeline.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pipelines.build.__main__ import main as build_main
from pipelines.lib.catalog import CATEGORY_PREFIXES, load_detections, prefix_for
from pipelines.validate.__main__ import main as validate_main

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def catalogue():
    detections, errors = load_detections(REPO_ROOT / "detections")
    assert errors == [], errors
    return detections


def test_the_catalogue_is_not_empty(catalogue):
    assert catalogue


def test_validation_passes_on_the_real_catalogue(monkeypatch):
    monkeypatch.chdir(REPO_ROOT)
    assert validate_main([]) == 0


def test_validation_passes_in_strict_mode(monkeypatch):
    """Strict mode is what the scheduled run uses; if warnings accumulate here,
    the catalogue is drifting."""
    monkeypatch.chdir(REPO_ROOT)
    assert validate_main(["--strict"]) == 0


def test_every_environment_builds(monkeypatch, tmp_path):
    monkeypatch.chdir(REPO_ROOT)
    assert build_main(["--output", str(tmp_path)]) == 0
    assert list(tmp_path.glob("*/manifest.json"))


def test_every_category_directory_has_an_id_prefix(catalogue):
    for detection in catalogue:
        prefix, _ = prefix_for(detection.category_parts)
        assert prefix is not None, (
            f"{detection.relative} lives in '{detection.category}', which is not in "
            f"CATEGORY_PREFIXES ({sorted('/'.join(k) for k in CATEGORY_PREFIXES)})"
        )


def test_rule_ids_are_unique(catalogue):
    ids = [d.rule_id for d in catalogue]
    assert len(ids) == len(set(ids))


def test_every_rule_documents_how_it_is_wrong(catalogue):
    """A detection with no documented false positives has not been thought
    through, whatever else is true of it."""
    for detection in catalogue:
        assert detection.metadata.get("false_positives"), detection.relative
