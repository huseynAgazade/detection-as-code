"""The model call behind the review stage.

Design decisions worth knowing before changing anything here:

  * The response is constrained by a JSON schema, so parsing cannot fail on
    prose and a review cannot silently omit a dimension.
  * The overall score is computed in Python from the per-dimension scores. The
    model judges; the arithmetic is ours, and therefore auditable.
  * The system prompt is identical for every rule in a run and is marked for
    caching, so reviewing forty rules pays for the rubric once.
  * A refusal is reported as a review error, never as a passing score. Security
    content occasionally trips a safety classifier, and a rule must not reach
    production because a review failed open.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from ..lib.catalog import Detection
from ..lib.yamlio import dump_yaml
from . import rubric

DEFAULT_MODEL = os.environ.get("DETECTION_REVIEW_MODEL", "claude-opus-5")

# Indicative list prices per million tokens, used only to print an estimate at
# the end of a run. Update alongside the model default.
PRICING_PER_MTOK: dict[str, tuple[float, float]] = {
    "claude-opus-5": (5.00, 25.00),
    "claude-sonnet-5": (2.00, 10.00),
    "claude-haiku-4-5": (1.00, 5.00),
}

SYSTEM_PROMPT = f"""\
You are a senior detection engineer reviewing a colleague's detection rule before \
it is merged into a production detection-as-code repository. You have run a SOC, \
you have been paged by bad rules at 3am, and you have had to explain to a customer \
why a detection did not fire. Review accordingly.

You are reviewing one rule. It is a YAML document describing a detection: metadata, \
ATT&CK mapping, analyst context, and one query per analytics platform. The queries \
contain {{{{ jinja }}}} placeholders that are substituted per environment at build \
time - treat a placeholder as a well-formed value of the obvious kind, and review \
the logic around it. Placeholders guarded with `| default("")` are optional tuning \
that may render to nothing.

A separate deterministic validator has already checked schema conformance, naming \
conventions, ATT&CK ID consistency, and obvious query-scope problems. Do not spend \
your review restating what a linter can find. Your value is judgement: whether this \
rule would work, and whether the SOC could live with it.

Score each of these dimensions from 0 to 100:

{chr(10).join(f"  {d.key} ({d.weight}%) - {d.title}: {d.question}{chr(10)}      {d.guidance}" for d in rubric.DIMENSIONS)}

Use these anchors, and use the full range. Most competent, unremarkable rules \
land in the 70s and 80s; reserve 90+ for rules you would merge without comment.

{rubric.CALIBRATION}
Rules for your review:

  * Judge the rule as written. If a field name looks wrong for the stated data \
source, say so - do not assume the author meant something reasonable.
  * Every assessment must cite something specific: a field, a threshold, a query \
line, a metadata value. An assessment that would read the same for any rule is \
not a review.
  * A blocking issue is a defect that makes the rule unsafe or useless to deploy. \
An empty list is the normal outcome for a competent rule. Do not manufacture one \
to appear rigorous, and do not withhold one to be agreeable.
  * Do not reward length, prose quality, or the presence of optional fields for \
their own sake. Ask what each one buys the analyst.
  * If you are unsure whether something is a defect, say what would settle it \
rather than scoring around the uncertainty.
"""


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0

    def add(self, other: "Usage") -> None:
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens

    def estimated_cost(self, model: str) -> float | None:
        prices = PRICING_PER_MTOK.get(model)
        if prices is None:
            return None
        input_price, output_price = prices
        return round(
            (self.input_tokens / 1_000_000) * input_price
            + (self.output_tokens / 1_000_000) * output_price,
            4,
        )


@dataclass
class ReviewResult:
    rule_id: str
    path: str
    name: str
    status: str
    score: float = 0.0
    verdict: str = "error"
    summary: str = ""
    detects_what_it_claims: bool = True
    dimensions: dict[str, dict[str, Any]] = field(default_factory=dict)
    blocking_issues: list[dict[str, str]] = field(default_factory=list)
    recommendations: list[dict[str, str]] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.verdict != "block"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "path": self.path,
            "name": self.name,
            "status": self.status,
            "quality_score": self.score,
            "verdict": self.verdict,
            "summary": self.summary,
            "detects_what_it_claims": self.detects_what_it_claims,
            "dimensions": self.dimensions,
            "blocking_issues": self.blocking_issues,
            "recommendations": self.recommendations,
            "error": self.error,
        }


def build_user_prompt(detection: Detection) -> str:
    """The rule, plus only the context needed to review it fairly."""
    return (
        f"Review this detection rule.\n\n"
        f"Repository path: detections/{detection.relative}\n"
        f"Category: {detection.category}\n"
        f"Declared platforms: {', '.join(detection.platforms) or 'none'}\n"
        f"Lifecycle status: {detection.status}\n\n"
        f"```yaml\n{dump_yaml(detection.data)}```\n"
    )


def _extract_json(response: Any) -> dict[str, Any]:
    text = next((block.text for block in response.content if block.type == "text"), None)
    if text is None:
        raise ValueError("model returned no text block")
    return json.loads(text)


def review_detection(client: Any, detection: Detection, model: str = DEFAULT_MODEL) -> tuple[ReviewResult, Usage]:
    """Review one rule. Never raises: a failure is reported as a result whose
    verdict is `error`, so one bad call does not abort a run over forty rules."""
    result = ReviewResult(
        rule_id=detection.rule_id or "<unknown>",
        path=str(detection.path),
        name=detection.name,
        status=detection.status,
    )
    usage = Usage()

    try:
        response = client.messages.create(
            model=model,
            max_tokens=8000,
            system=[
                {
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": build_user_prompt(detection)}],
            output_config={"format": {"type": "json_schema", "schema": rubric.response_schema()}},
        )
    except Exception as exc:  # noqa: BLE001 - surfaced in the report
        result.error = f"{type(exc).__name__}: {exc}"
        return result, usage

    raw_usage = getattr(response, "usage", None)
    if raw_usage is not None:
        usage = Usage(
            input_tokens=getattr(raw_usage, "input_tokens", 0) or 0,
            output_tokens=getattr(raw_usage, "output_tokens", 0) or 0,
            cache_read_tokens=getattr(raw_usage, "cache_read_input_tokens", 0) or 0,
        )

    if getattr(response, "stop_reason", None) == "refusal":
        details = getattr(response, "stop_details", None)
        category = getattr(details, "category", None) or "unspecified"
        result.error = (
            f"the model declined to complete this review (category: {category}); "
            f"the rule has NOT been assessed and must be reviewed by a person"
        )
        return result, usage

    try:
        payload = _extract_json(response)
    except Exception as exc:  # noqa: BLE001
        result.error = f"could not read the review response: {exc}"
        return result, usage

    dimensions = {
        entry["key"]: {"score": entry["score"], "assessment": entry["assessment"]}
        for entry in payload.get("dimensions", [])
    }
    missing = set(rubric.DIMENSION_KEYS) - set(dimensions)
    if missing:
        result.error = f"review omitted dimension(s): {', '.join(sorted(missing))}"
        return result, usage

    result.dimensions = dimensions
    result.summary = payload.get("summary", "")
    result.detects_what_it_claims = bool(payload.get("detects_what_it_claims", True))
    result.blocking_issues = payload.get("blocking_issues", [])
    result.recommendations = payload.get("recommendations", [])
    result.score = rubric.weighted_score({k: v["score"] for k, v in dimensions.items()})
    result.verdict = rubric.verdict_for(
        result.score,
        has_blocking_issue=bool(result.blocking_issues) or not result.detects_what_it_claims,
    )
    return result, usage
