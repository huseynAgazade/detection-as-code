"""Structural validation: the checks that keep the catalogue coherent."""

from __future__ import annotations

from jsonschema import Draft202012Validator

from pipelines.lib.findings import Report
from pipelines.validate import structure


def checks(report: Report) -> set[str]:
    return {finding.check for finding in report.findings}


def test_valid_rule_passes_every_structural_check(make_detection, schema, base_variables):
    detection = make_detection()
    report = Report()
    validator = Draft202012Validator(schema)

    assert structure.check_schema(detection, validator, report)
    structure.check_location(detection, report)
    structure.check_id_prefix(detection, report)
    structure.check_platforms(detection, report)
    structure.check_mitre(detection, report)
    structure.check_lifecycle(detection, report)
    structure.check_risk_fields(detection, report)
    structure.check_placeholders(detection, base_variables, report)

    assert report.errors == []


def test_schema_rejects_an_unknown_metadata_field(make_detection, schema):
    detection = make_detection(lambda d: d["metadata"].update(sevrity="high"))
    report = Report()
    assert not structure.check_schema(detection, Draft202012Validator(schema), report)
    assert "schema" in checks(report)


def test_id_prefix_must_match_the_category(make_detection):
    detection = make_detection(lambda d: d["metadata"].update(id="NET-AD-900"))
    report = Report()
    structure.check_id_prefix(detection, report)
    assert "id-prefix" in {f.check for f in report.errors}


def test_platform_declared_without_a_block_is_an_error(make_detection):
    detection = make_detection(lambda d: d["metadata"]["platforms"].append("sentinel"))
    report = Report()
    structure.check_platforms(detection, report)
    assert any("no detection.sentinel block" in f.message for f in report.errors)


def test_block_present_without_being_declared_is_an_error(make_detection):
    def mutate(data):
        data["detection"]["elastic"] = {
            "schedule": {"interval": "5m", "lookback": "15m"},
            "query": "FROM logs-* | WHERE event.code == 4625 | LIMIT 10",
        }

    report = Report()
    structure.check_platforms(make_detection(mutate), report)
    assert any("never be built" in f.message for f in report.errors)


def test_tactic_name_must_match_its_id(make_detection):
    detection = make_detection(lambda d: d["metadata"]["mitre"][0].update(tactic="Persistence"))
    report = Report()
    structure.check_mitre(detection, report)
    assert any("does not match TA0006" in f.message for f in report.errors)


def test_superseded_tactic_name_warns_rather_than_fails(make_detection):
    def mutate(data):
        data["metadata"]["mitre"][0].update(
            tactic="Stealth",
            tactic_id="TA0005",
            technique="Indicator Removal: Clear Windows Event Logs",
            technique_id="T1070.001",
        )

    report = Report()
    structure.check_mitre(make_detection(mutate), report)
    assert report.errors == []
    assert any("superseded" in f.message for f in report.warnings)


def test_duplicate_attack_pair_is_rejected(make_detection):
    def mutate(data):
        data["metadata"]["mitre"].append(dict(data["metadata"]["mitre"][0]))

    report = Report()
    structure.check_mitre(make_detection(mutate), report)
    assert any("duplicates" in f.message for f in report.errors)


def test_experimental_rule_without_a_soak_start_is_rejected(make_detection):
    detection = make_detection(lambda d: d["metadata"].update(status="experimental"))
    report = Report()
    structure.check_lifecycle(detection, report)
    assert any("soak_started" in f.message for f in report.errors)


def test_risk_field_missing_from_the_query_warns(make_detection):
    detection = make_detection(
        lambda d: d["metadata"]["risk"]["objects"].append(
            {"field": "nonexistent_field", "type": "user", "score": 10}
        )
    )
    report = Report()
    structure.check_risk_fields(detection, report)
    assert any("nonexistent_field" in f.message for f in report.warnings)


def test_unknown_placeholder_fails_before_the_build_does(make_detection, base_variables):
    detection = make_detection(
        lambda d: d["detection"]["splunk"].update(
            query="index={{ indx.windows }} EventCode=4625 | table src\n"
        )
    )
    report = Report()
    structure.check_placeholders(detection, base_variables, report)
    assert any("indx" in f.message for f in report.errors)


def test_unknown_nested_variable_is_caught(make_detection, base_variables):
    """The root existing says nothing about the leaf: a threshold the rule needs
    but nobody added is the typo people actually make."""
    detection = make_detection(
        lambda d: d["detection"]["splunk"].update(
            query="index=windows | where n > {{ thresholds.never_defined }}\n| table src\n"
        )
    )
    report = Report()
    structure.check_placeholders(detection, base_variables, report)
    assert any("thresholds.never_defined" in f.message for f in report.errors)


def test_known_nested_variable_passes(make_detection, base_variables):
    detection = make_detection(
        lambda d: d["detection"]["splunk"].update(
            query="index={{ index.windows }} | where n > {{ thresholds.dns_query_burst }}\n| table src\n"
        )
    )
    report = Report()
    structure.check_placeholders(detection, base_variables, report)
    assert [f.message for f in report.errors] == []


def test_a_guarded_placeholder_is_not_reported(base_variables, make_detection):
    """`| default(...)` means the author handled absence, so it cannot fail the
    build and must not be reported as if it would."""
    detection = make_detection(
        lambda d: d["detection"]["splunk"].update(
            query='index=windows | head {{ thresholds.never_defined | default(10) }}\n| table src\n'
        )
    )
    report = Report()
    structure.check_placeholders(detection, base_variables, report)
    assert report.errors == []


def test_duplicate_rule_ids_are_rejected(make_detection):
    first = make_detection(relative="identity/active_directory/one.yaml")
    second = make_detection(relative="identity/active_directory/two.yaml")
    report = Report()
    ids = structure.check_unique_ids([first, second], report)
    assert ids == {"ID-AD-900"}
    assert any("already used by" in f.message for f in report.errors)


def test_loose_detection_file_is_rejected(make_detection):
    detection = make_detection(relative="loose_rule.yaml")
    report = Report()
    structure.check_location(detection, report)
    assert any("category directory" in f.message for f in report.errors)


def test_filename_should_match_the_rule_name(make_detection):
    report = Report()
    structure.check_filename(make_detection(), report)
    assert any(f.check == "filename" for f in report.warnings)
    assert structure.slugify("Kerberoasting via RC4 Request") == "kerberoasting_via_rc4_request"
