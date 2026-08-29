"""Quality gates: the deterministic checks that sit between schema and judgement."""

from __future__ import annotations

from pipelines.lib.findings import Report
from pipelines.validate import quality_gates


def test_clean_rule_raises_nothing(make_detection):
    report = Report()
    quality_gates.validate([make_detection()], report)
    assert report.findings == []


def test_wildcard_index_is_an_error(make_detection):
    detection = make_detection(
        lambda d: d["detection"]["splunk"].update(
            query="index=* EventCode=4625\n| stats count BY src\n| table src\n"
        )
    )
    report = Report()
    quality_gates.check_query_scope(detection, report)
    assert any(f.check == "query-scope" for f in report.errors)


def test_join_is_flagged_as_a_cost_warning(make_detection):
    detection = make_detection(
        lambda d: d["detection"]["splunk"].update(
            query=(
                "index=windows EventCode=4625\n"
                "| join src [ search index=windows EventCode=4624 ]\n"
                "| table src\n"
            )
        )
    )
    report = Report()
    quality_gates.check_query_scope(detection, report)
    assert any(f.check == "query-cost" for f in report.warnings)


def test_missing_throttle_warns(make_detection):
    detection = make_detection(lambda d: d["detection"]["splunk"].pop("throttle"))
    report = Report()
    quality_gates.check_alert_hygiene(detection, report)
    assert any("no throttle" in f.message for f in report.warnings)


def test_throttle_on_a_field_the_query_does_not_emit_warns(make_detection):
    detection = make_detection(
        lambda d: d["detection"]["splunk"]["throttle"].update(fields=["not_a_field"])
    )
    report = Report()
    quality_gates.check_alert_hygiene(detection, report)
    assert any("not_a_field" in f.message for f in report.warnings)


def test_stable_rule_without_analyst_context_fails(make_detection):
    detection = make_detection(lambda d: d["metadata"].pop("triage"))
    report = Report()
    quality_gates.check_analyst_context(detection, report)
    assert any("metadata.triage" in f.message for f in report.errors)


def test_draft_rule_without_analyst_context_only_warns(make_detection):
    def mutate(data):
        data["metadata"]["status"] = "draft"
        data["metadata"].pop("triage")

    report = Report()
    quality_gates.check_analyst_context(make_detection(mutate), report)
    assert report.errors == []
    assert any("metadata.triage" in f.message for f in report.warnings)


def test_description_that_repeats_the_name_is_rejected(make_detection):
    detection = make_detection(
        lambda d: d["metadata"].update(description=d["metadata"]["name"])
    )
    report = Report()
    quality_gates.check_description(detection, report)
    assert any(f.check == "description" for f in report.errors)


def test_modified_before_created_is_rejected(make_detection):
    detection = make_detection(lambda d: d["metadata"].update(modified="2025-12-01"))
    report = Report()
    quality_gates.check_versioning(detection, report)
    assert any(f.check == "versioning" for f in report.errors)
