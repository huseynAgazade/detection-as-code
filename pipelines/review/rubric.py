"""The rubric the AI review stage scores against.

A number is only useful if everyone reading it means the same thing by it, so
the rubric is defined here rather than embedded in a prompt string: the
dimensions, their weights, the calibration anchors, and the thresholds that turn
a score into a merge decision. Changing any of them is a reviewed change to this
file, visible in the diff, and the score in an old report can be interpreted
against the rubric that produced it.

The weights encode a position worth stating plainly. A detection that does not
actually detect the thing it describes is worthless, so logic carries the most
weight. After that, the two properties that decide whether a correct rule
survives contact with production are how it behaves on benign traffic and
whether an analyst can act on what it returns - together those outweigh logic.
Performance and evasion resistance matter, but a rule that is slow or bypassable
still has value, whereas one that pages the SOC forty times a night does not.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Dimension:
    key: str
    title: str
    weight: int
    question: str
    guidance: str


DIMENSIONS: tuple[Dimension, ...] = (
    Dimension(
        key="logic_soundness",
        title="Detection logic",
        weight=25,
        question=(
            "Does the query actually detect the behaviour the description claims, on the "
            "data sources it names?"
        ),
        guidance=(
            "Read the query as written, not as intended. Check field names against the "
            "named data sources, check that filters and thresholds combine the way the "
            "description implies, and check aggregation boundaries - a stats or summarize "
            "over the wrong key silently changes what the rule means. Call out logic that "
            "cannot fire at all, and logic that fires on something other than what is "
            "described."
        ),
    ),
    Dimension(
        key="false_positive_resilience",
        title="False-positive resilience",
        weight=22,
        question=(
            "On a normal week of real enterprise traffic, would this produce a workable "
            "number of alerts, and are the benign causes anticipated?"
        ),
        guidance=(
            "Judge the shape of benign traffic that would match. Consider whether the "
            "thresholds are defensible or arbitrary, whether aggregation and throttling "
            "collapse a burst into one alert, and whether the documented false positives "
            "match what would really be seen. A rule with no tuning surface at all is a "
            "weakness even when the logic is correct."
        ),
    ),
    Dimension(
        key="triage_readiness",
        title="Triage readiness",
        weight=18,
        question=(
            "Can an analyst who has never seen this alert decide what happened and what to "
            "do, from what the rule returns and documents?"
        ),
        guidance=(
            "Check that the output fields carry the evidence the triage steps ask for, that "
            "the risk objects and alert message reference fields the query emits, and that "
            "the description explains the behaviour rather than restating the title. Missing "
            "context is a real defect, not a documentation nit: it is paid for on every "
            "single alert."
        ),
    ),
    Dimension(
        key="metadata_accuracy",
        title="Metadata and ATT&CK accuracy",
        weight=15,
        question=(
            "Do the ATT&CK mapping, severity, confidence, and data sources honestly describe "
            "what the logic does?"
        ),
        guidance=(
            "The mapping should reflect the behaviour the query matches, not the worst case "
            "it might be part of. Severity should match the impact of a true positive and "
            "confidence the likelihood that a hit is one. Flag inflated severity, mappings "
            "stretched to claim coverage, and data sources the query does not read."
        ),
    ),
    Dimension(
        key="performance",
        title="Performance and cost",
        weight=12,
        question=(
            "Will this run at the scheduled cadence on production data volumes without "
            "becoming the thing that gets disabled?"
        ),
        guidance=(
            "Look at how early the search narrows, whether the schedule and lookback line up "
            "with each other, whether the window leaves room for ingestion lag, and whether "
            "expensive operations sit before or after the filtering. Consider cardinality: "
            "grouping by a high-cardinality field changes cost by orders of magnitude."
        ),
    ),
    Dimension(
        key="evasion_resistance",
        title="Evasion resistance",
        weight=8,
        question=(
            "How much effort does it take for an informed attacker to stay under this rule "
            "while still achieving the objective?"
        ),
        guidance=(
            "Consider trivial bypasses: exact string matches on a renameable artefact, a "
            "threshold defeated by pacing, a single tool's signature standing in for a "
            "technique. Weigh this against the alternative - a rule that is easy to evade may "
            "still be worth having, so do not score it as if evasion were the only concern."
        ),
    ),
)

assert sum(d.weight for d in DIMENSIONS) == 100, "rubric weights must total 100"

DIMENSION_KEYS: tuple[str, ...] = tuple(d.key for d in DIMENSIONS)

# Calibration anchors. Without these, scores drift upward across runs and the
# number stops carrying information.
CALIBRATION = """\
90-100  Production-ready. You would merge this as it stands. Any remark you have
        is a preference, not a defect.
75-89   Sound. It does what it claims and would work, but there are specific,
        nameable improvements a reviewer should ask for.
60-74   Workable but flawed. A real weakness that will cost someone time: a gap
        in the logic, missing tuning, or context an analyst will have to
        reconstruct themselves.
40-59   Not ready. The rule misses a substantial part of what it claims to
        cover, or would generate an unworkable alert volume.
0-39    Broken. It cannot fire, fires on the wrong thing, or is so noisy that
        deploying it would degrade the SOC's ability to work other alerts.
"""

# Score thresholds that turn the rubric into a merge decision.
BLOCK_BELOW = 70   # below this, the review stage fails the pipeline
WARN_BELOW = 85    # below this, the review passes but asks for a human look


def weighted_score(scores: dict[str, float]) -> float:
    """Combine per-dimension scores into the overall quality score.

    Deliberately computed here rather than asked of the model: arithmetic is not
    a judgement call, and a score the model derives itself cannot be audited
    against the dimensions it reported.
    """
    total = 0.0
    for dimension in DIMENSIONS:
        total += float(scores.get(dimension.key, 0)) * dimension.weight
    return round(total / 100, 1)


def verdict_for(score: float, has_blocking_issue: bool) -> str:
    """block | review | pass."""
    if has_blocking_issue or score < BLOCK_BELOW:
        return "block"
    if score < WARN_BELOW:
        return "review"
    return "pass"


def response_schema() -> dict:
    """JSON schema the model's response is constrained to.

    Every dimension is required, so a review cannot quietly skip the dimension it
    found hardest to judge.
    """
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["summary", "detects_what_it_claims", "dimensions", "blocking_issues", "recommendations"],
        "properties": {
            "summary": {
                "type": "string",
                "description": "Two or three sentences: what the rule does well and the most important thing wrong with it.",
            },
            "detects_what_it_claims": {
                "type": "boolean",
                "description": "False if the query cannot detect the behaviour described, for any reason.",
            },
            "dimensions": {
                "type": "array",
                "minItems": len(DIMENSIONS),
                "maxItems": len(DIMENSIONS),
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["key", "score", "assessment"],
                    "properties": {
                        "key": {"enum": list(DIMENSION_KEYS)},
                        "score": {"type": "integer", "minimum": 0, "maximum": 100},
                        "assessment": {
                            "type": "string",
                            "description": "One or two sentences justifying the score, citing the specific field or query line.",
                        },
                    },
                },
            },
            "blocking_issues": {
                "type": "array",
                "description": "Defects that must be fixed before merge. Empty is the expected case; reserve this for real blockers.",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["title", "detail"],
                    "properties": {
                        "title": {"type": "string"},
                        "detail": {"type": "string"},
                    },
                },
            },
            "recommendations": {
                "type": "array",
                "description": "Concrete changes, most valuable first. Each one names what to change, not just what is wrong.",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["priority", "change", "rationale"],
                    "properties": {
                        "priority": {"enum": ["high", "medium", "low"]},
                        "change": {"type": "string"},
                        "rationale": {"type": "string"},
                    },
                },
            },
        },
    }
