"""Deterministic quality gates.

These sit between the schema, which only knows about shape, and the AI review,
which makes judgement calls. Everything here is a rule that is objectively true
or false about a detection file and cheap to check: an unbounded search, an
alert with no de-duplication, a rule with no documented false positives.

Keeping them here rather than in the AI stage matters for two reasons. They run
on every commit for free, with no API key and no network. And a finding that can
be stated as a rule should be stated as a rule, so the model spends its
attention on the parts that genuinely need judgement.
"""

from __future__ import annotations

import re

from ..lib.catalog import Detection
from ..lib.findings import Report

# Patterns that make a scheduled search read everything it can reach. Each entry
# is (compiled pattern, platform it applies to, explanation).
_UNBOUNDED_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"\bindex\s*=\s*\*", re.IGNORECASE),
        "splunk",
        "searches every index; name the indexes the rule needs through {{ index.* }}",
    ),
    (
        re.compile(r"\bsourcetype\s*=\s*\*", re.IGNORECASE),
        "splunk",
        "searches every sourcetype, which scales with unrelated onboarding work",
    ),
    (
        re.compile(r"\bsearch\s+\*", re.IGNORECASE),
        "splunk",
        "starts from a bare wildcard search",
    ),
    (
        re.compile(r"^\s*union\s+\*", re.IGNORECASE | re.MULTILINE),
        "sentinel",
        "unions every table in the workspace",
    ),
]

# Commands that are fine occasionally and expensive as a habit, flagged so the
# choice is visible in review rather than discovered in a performance incident.
_COSTLY_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (
        re.compile(r"\|\s*join\b", re.IGNORECASE),
        "splunk",
        "uses `join`, which is subquery-bounded and silently truncates; `stats` or "
        "`lookup` is usually both correct and faster",
    ),
    (
        re.compile(r"\|\s*transaction\b", re.IGNORECASE),
        "splunk",
        "uses `transaction`, which is memory-bound and drops events past its limits; "
        "`stats` by a correlation field is the scalable form",
    ),
    (
        re.compile(r"\bappend(?:cols|pipe)?\b", re.IGNORECASE),
        "splunk",
        "uses an `append` family command, which is capped by subsearch limits",
    ),
]

_MAX_QUERY_LINES = 80


def _queries(detection: Detection) -> list[tuple[str, str]]:
    blocks = detection.data.get("detection", {}) or {}
    out: list[tuple[str, str]] = []
    for platform, block in blocks.items():
        if isinstance(block, dict) and isinstance(block.get("query"), str):
            out.append((platform, block["query"]))
    return out


def check_query_scope(detection: Detection, report: Report) -> None:
    """A scheduled search that is not bounded by source and time will eventually
    cost more than the detection is worth, and will be the first thing turned off
    when the platform is under load."""
    for platform, query in _queries(detection):
        for pattern, applies_to, explanation in _UNBOUNDED_PATTERNS:
            if applies_to == platform and pattern.search(query):
                report.error(
                    "query-scope",
                    f"detection.{platform} {explanation}",
                    detection.path,
                )
        for pattern, applies_to, explanation in _COSTLY_PATTERNS:
            if applies_to == platform and pattern.search(query):
                report.warn("query-cost", f"detection.{platform} {explanation}", detection.path)


def check_query_shape(detection: Detection, report: Report) -> None:
    """Long or trailing-whitespace-laden queries are a maintenance problem, and a
    query with no explicit output stage hands the analyst raw events."""
    for platform, query in _queries(detection):
        lines = query.splitlines()
        if len(lines) > _MAX_QUERY_LINES:
            report.warn(
                "query-shape",
                f"detection.{platform} query is {len(lines)} lines; consider moving shared "
                f"logic into a macro, saved search, or function so the rule stays reviewable",
                detection.path,
            )
        if any(line.rstrip() != line for line in lines):
            report.warn(
                "query-shape",
                f"detection.{platform} query has trailing whitespace, which shows up as a "
                f"spurious diff on the next edit",
                detection.path,
            )
        if platform == "splunk" and not re.search(r"\|\s*(table|fields|stats|tstats)\b", query, re.IGNORECASE):
            report.warn(
                "query-shape",
                "detection.splunk query never projects an explicit field set; the analyst "
                "receives raw events and has to work out what matters",
                detection.path,
            )


def check_alert_hygiene(detection: Detection, report: Report) -> None:
    """Throttling and severity are what stop a correct rule from becoming an
    unworkable one the week it meets real traffic."""
    blocks = detection.data.get("detection", {}) or {}
    for platform, block in blocks.items():
        if not isinstance(block, dict):
            continue
        if "throttle" not in block:
            report.warn(
                "alert-hygiene",
                f"detection.{platform} has no throttle; a single noisy source will open one "
                f"alert per scheduled run",
                detection.path,
            )
            continue
        fields = block["throttle"].get("fields", [])
        queries = block.get("query", "")
        for field in fields:
            if field not in queries:
                report.warn(
                    "alert-hygiene",
                    f"detection.{platform} throttles on '{field}', which the query does not "
                    f"appear to emit; de-duplication will not group as intended",
                    detection.path,
                )

    severity = detection.metadata.get("severity")
    confidence = detection.metadata.get("confidence")
    if severity == "critical" and confidence == "low":
        report.warn(
            "alert-hygiene",
            "severity 'critical' with confidence 'low' will page someone for a finding the "
            "rule itself does not trust; reconsider one of the two",
            detection.path,
        )


def check_analyst_context(detection: Detection, report: Report) -> None:
    """The fields that decide whether an alert can actually be worked.

    These are warnings rather than errors so a genuine work-in-progress can still
    be committed, but a rule reaching `stable` without them is a rule whose
    triage cost lands entirely on the analyst.
    """
    metadata = detection.metadata
    stable = detection.status == "stable"

    expectations: list[tuple[str, str]] = [
        ("false_positives", "no documented false positives; the first analyst to work this "
                            "alert will rediscover them at 3am"),
        ("triage", "no triage steps; the rule states what fired but not what to do about it"),
        ("references", "no references; there is nothing to check the logic against when it "
                       "is revisited in a year"),
        ("risk", "no risk block, so the alert has no summary line and no risk objects"),
    ]

    for key, explanation in expectations:
        if not metadata.get(key):
            if stable:
                report.error("analyst-context", f"metadata.{key} is missing: {explanation}", detection.path)
            else:
                report.warn("analyst-context", f"metadata.{key} is missing: {explanation}", detection.path)


def check_description(detection: Detection, report: Report) -> None:
    """The description is the alert body. It is read far more often than the query."""
    metadata = detection.metadata
    description = str(metadata.get("description", ""))
    name = str(metadata.get("name", ""))

    if description.strip().lower() == name.strip().lower():
        report.error(
            "description",
            "description just repeats the rule name; it should explain what the behaviour "
            "is, why it matters, and what the results contain",
            detection.path,
        )
    if len(description.split()) < 25:
        report.warn(
            "description",
            f"description is {len(description.split())} words; that is rarely enough to "
            f"orient someone who has never seen this alert before",
            detection.path,
        )


def check_versioning(detection: Detection, report: Report) -> None:
    """`modified` is what tells a reviewer whether the rule has been looked at
    since the last time the environment changed around it."""
    metadata = detection.metadata
    created = str(metadata.get("created", ""))
    modified = str(metadata.get("modified", ""))
    if created and modified and modified < created:
        report.error(
            "versioning",
            f"modified ({modified}) is earlier than created ({created})",
            detection.path,
        )


def validate(detections: list[Detection], report: Report) -> None:
    for detection in detections:
        if not detection.metadata:
            continue  # already reported by the schema stage
        check_query_scope(detection, report)
        check_query_shape(detection, report)
        check_alert_hygiene(detection, report)
        check_analyst_context(detection, report)
        check_description(detection, report)
        check_versioning(detection, report)
