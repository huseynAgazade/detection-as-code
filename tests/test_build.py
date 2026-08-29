"""The build stage: rendering a portable rule into a deployable one."""

from __future__ import annotations

import pytest
import yaml

from pipelines.build import renderer
from pipelines.build.__main__ import skip_reason
from pipelines.lib.yamlio import DuplicateKeyError, dump_yaml, load_yaml


def render(text: str, context: dict) -> str:
    return renderer.render_text(renderer.make_environment(), text, context, "test")


def test_variables_are_substituted():
    out = render("index={{ index.windows }}\n", {"index": {"windows": "wineventlog"}})
    assert out == "index=wineventlog\n"


def test_unknown_variable_fails_the_build():
    with pytest.raises(renderer.RenderError) as excinfo:
        render("index={{ index.missing }}\n", {"index": {"windows": "w"}})
    assert "missing" in str(excinfo.value)


def test_undefined_exclusion_renders_empty_when_guarded():
    out = render('    {{ exclusions.splunk.absent | default("") }}\n', {"exclusions": {"splunk": {}}})
    assert out.strip() == ""


def test_multiline_exclusion_keeps_the_placeholder_indentation():
    context = {
        "exclusions": {
            "splunk": {"tuning": 'NOT src="192.0.2.1"\nNOT src="192.0.2.2"'}
        }
    }
    out = render('    {{ exclusions.splunk.tuning | default("") }}\n', context)
    assert out == '    NOT src="192.0.2.1"\n    NOT src="192.0.2.2"\n'


def test_rendered_multiline_exclusion_stays_valid_yaml():
    template = 'query: |\n  index=windows\n  {{ exclusions.splunk.tuning | default("") }}\n'
    context = {"exclusions": {"splunk": {"tuning": 'NOT a="1"\nNOT b="2"'}}}
    parsed = yaml.safe_load(render(template, context))
    assert parsed["query"].splitlines() == ["index=windows", 'NOT a="1"', 'NOT b="2"']


def test_unused_exclusion_leaves_no_whitespace_line():
    """A whitespace-only line would force YAML to abandon block style and emit
    the whole query as an escaped one-liner."""
    template = 'index=windows\n    {{ exclusions.splunk.absent | default("") }}\n| table src\n'
    out = render(template, {"exclusions": {"splunk": {}}})
    assert out == "index=windows\n| table src\n"


def test_author_written_blank_lines_survive():
    out = render("index=windows\n\n| table src\n", {})
    assert out == "index=windows\n\n| table src\n"


def test_rendered_query_stays_a_block_scalar_when_an_exclusion_is_unused():
    template = 'index=windows\n    {{ exclusions.splunk.absent | default("") }}\n| table src\n'
    rendered = render(template, {"exclusions": {"splunk": {}}})
    assert "query: |" in dump_yaml({"query": rendered})


def test_deep_merge_overrides_leaves_without_dropping_siblings():
    merged = renderer.deep_merge(
        {"thresholds": {"a": 1, "b": 2}, "index": {"windows": "w"}},
        {"thresholds": {"b": 99}},
    )
    assert merged == {"thresholds": {"a": 1, "b": 99}, "index": {"windows": "w"}}


def test_rule_scoped_exclusions_override_shared_ones():
    context = renderer.build_context(
        variables={},
        exclusions={
            "exclusions": {"splunk": {"tuning": "shared"}},
            "rules": {"ID-AD-001": {"splunk": {"tuning": "rule specific"}}},
        },
        rule_id="ID-AD-001",
    )
    assert context["exclusions"]["splunk"]["tuning"] == "rule specific"


def test_rule_threshold_override_applies_to_that_rule_only():
    variables = {
        "thresholds": {"burst": 50},
        "rules": {"ID-AD-001": {"thresholds": {"burst": 5}}},
    }
    assert renderer.build_context(variables, {}, "ID-AD-001")["thresholds"]["burst"] == 5
    assert renderer.build_context(variables, {}, "ID-AD-002")["thresholds"]["burst"] == 50


def test_draft_rules_are_not_built(make_detection):
    detection = make_detection(lambda d: d["metadata"].update(status="draft"))
    assert skip_reason(detection, {}) == "status is 'draft'"


def test_environment_can_disable_a_rule(make_detection):
    variables = {"rules": {"ID-AD-900": {"enabled": False, "reason": "no such log source"}}}
    assert skip_reason(make_detection(), variables) == "no such log source"


def test_duplicate_yaml_keys_are_rejected(tmp_path):
    path = tmp_path / "rule.yaml"
    path.write_text("metadata:\n  id: A\n  id: B\n", encoding="utf-8")
    with pytest.raises(DuplicateKeyError):
        load_yaml(path)


def test_multiline_strings_round_trip_as_block_scalars():
    text = dump_yaml({"query": "line one\nline two\n"})
    assert "query: |" in text
    assert yaml.safe_load(text)["query"] == "line one\nline two\n"
