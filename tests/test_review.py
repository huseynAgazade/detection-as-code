"""The review stage: how a set of dimension scores becomes a merge decision.

The model call itself is not tested here - it is a network call with a
non-deterministic result. What is tested is everything around it, which is where
a scoring bug would actually hide: the weighting, the thresholds, and the
guarantee that an unreviewed rule never reports as a passing one.
"""

from __future__ import annotations

from pipelines.review import rubric
from pipelines.review.engine import ReviewResult, Usage, review_detection


def test_rubric_weights_total_one_hundred():
    assert sum(d.weight for d in rubric.DIMENSIONS) == 100


def test_score_is_the_weighted_mean_of_the_dimensions():
    assert rubric.weighted_score({d.key: 80 for d in rubric.DIMENSIONS}) == 80.0


def test_weighting_favours_the_heaviest_dimension():
    heavy = dict.fromkeys(rubric.DIMENSION_KEYS, 100) | {"logic_soundness": 0}
    light = dict.fromkeys(rubric.DIMENSION_KEYS, 100) | {"evasion_resistance": 0}
    assert rubric.weighted_score(heavy) < rubric.weighted_score(light)


def test_a_missing_dimension_scores_zero_rather_than_being_ignored():
    partial = {d.key: 100 for d in rubric.DIMENSIONS if d.key != "performance"}
    assert rubric.weighted_score(partial) == 88.0


def test_verdict_thresholds():
    assert rubric.verdict_for(95, False) == "pass"
    assert rubric.verdict_for(80, False) == "review"
    assert rubric.verdict_for(50, False) == "block"


def test_a_blocking_issue_blocks_regardless_of_score():
    assert rubric.verdict_for(99, True) == "block"


def test_response_schema_requires_every_dimension():
    schema = rubric.response_schema()
    assert schema["properties"]["dimensions"]["minItems"] == len(rubric.DIMENSIONS)
    assert set(schema["properties"]["dimensions"]["items"]["properties"]["key"]["enum"]) == set(
        rubric.DIMENSION_KEYS
    )


class _RefusingClient:
    class messages:  # noqa: N801 - mirrors the SDK's attribute layout
        @staticmethod
        def create(**_kwargs):
            class _Details:
                category = "cyber"

            class _Response:
                content = []
                usage = None
                stop_reason = "refusal"
                stop_details = _Details()

            return _Response()


class _FailingClient:
    class messages:  # noqa: N801
        @staticmethod
        def create(**_kwargs):
            raise RuntimeError("connection reset")


def test_a_refusal_is_reported_as_unassessed_not_as_a_pass(make_detection):
    result, _ = review_detection(_RefusingClient(), make_detection())
    assert result.verdict == "error"
    assert result.score == 0.0
    assert "declined" in result.error
    assert not result.ok


def test_an_api_failure_does_not_raise(make_detection):
    result, usage = review_detection(_FailingClient(), make_detection())
    assert result.verdict == "error"
    assert "connection reset" in result.error
    assert usage.input_tokens == 0


def test_cost_estimate_uses_the_priced_model():
    usage = Usage(input_tokens=1_000_000, output_tokens=100_000)
    assert usage.estimated_cost("claude-opus-5") == 7.5
    assert usage.estimated_cost("some-unpriced-model") is None


def test_review_result_serialises_for_the_json_report():
    payload = ReviewResult(rule_id="ID-AD-001", path="p", name="n", status="stable").to_dict()
    assert payload["quality_score"] == 0.0
    assert payload["verdict"] == "error"
