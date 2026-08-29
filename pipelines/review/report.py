"""Rendering for review results: terminal, Markdown, and JSON.

The Markdown form is what lands on the pull request, so it leads with the
decision and the numbers and keeps the reasoning one click away. A reviewer
should be able to read the first table and know whether to look further.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from . import rubric
from .engine import ReviewResult, Usage

_VERDICT_LABEL = {
    "pass": ("PASS", "Meets the bar"),
    "review": ("REVIEW", "Merge only with a human look"),
    "block": ("BLOCK", "Do not merge as it stands"),
    "error": ("ERROR", "Not assessed"),
}


def to_json(results: Iterable[ReviewResult], usage: Usage, model: str) -> str:
    results = list(results)
    scored = [r for r in results if r.error is None]
    return json.dumps(
        {
            "model": model,
            "rubric": {
                "dimensions": {d.key: d.weight for d in rubric.DIMENSIONS},
                "block_below": rubric.BLOCK_BELOW,
                "warn_below": rubric.WARN_BELOW,
            },
            "summary": {
                "reviewed": len(results),
                "mean_score": round(sum(r.score for r in scored) / len(scored), 1) if scored else None,
                "blocked": sum(1 for r in results if r.verdict == "block"),
                "errors": sum(1 for r in results if r.error is not None),
            },
            "usage": {
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "cache_read_tokens": usage.cache_read_tokens,
                "estimated_cost_usd": usage.estimated_cost(model),
            },
            "results": [r.to_dict() for r in results],
        },
        indent=2,
    )


def to_markdown(results: Iterable[ReviewResult], usage: Usage, model: str) -> str:
    results = sorted(results, key=lambda r: (r.error is not None, r.score))
    scored = [r for r in results if r.error is None]
    mean = round(sum(r.score for r in scored) / len(scored), 1) if scored else None

    lines: list[str] = []
    lines.append("## Detection quality review")
    lines.append("")
    if mean is not None:
        lines.append(
            f"**{len(scored)} rule(s) reviewed - mean quality score {mean}/100.** "
            f"Merge threshold is {rubric.BLOCK_BELOW}; below {rubric.WARN_BELOW} asks for a human look."
        )
    else:
        lines.append("No rule was successfully reviewed.")
    lines.append("")

    lines.append("| Rule | Name | Score | Verdict |")
    lines.append("|------|------|-------|---------|")
    for result in results:
        label = _VERDICT_LABEL[result.verdict][0]
        score = "-" if result.error else f"{result.score:.1f}"
        lines.append(f"| `{result.rule_id}` | {result.name} | {score} | **{label}** |")
    lines.append("")

    for result in results:
        label, meaning = _VERDICT_LABEL[result.verdict]
        lines.append(f"### `{result.rule_id}` - {result.name}")
        lines.append("")
        if result.error:
            lines.append(f"> **Not assessed.** {result.error}")
            lines.append("")
            continue

        lines.append(f"**{result.score:.1f}/100 - {label}.** {meaning}.")
        lines.append("")
        lines.append(result.summary)
        lines.append("")

        if not result.detects_what_it_claims:
            lines.append(
                "> The reviewer judged that this query does not detect the behaviour its "
                "description claims. Treat that as the first thing to resolve."
            )
            lines.append("")

        lines.append("<details><summary>Scores by dimension</summary>")
        lines.append("")
        lines.append("| Dimension | Weight | Score | Assessment |")
        lines.append("|-----------|--------|-------|------------|")
        for dimension in rubric.DIMENSIONS:
            entry = result.dimensions.get(dimension.key, {})
            assessment = str(entry.get("assessment", "")).replace("|", "\\|")
            lines.append(
                f"| {dimension.title} | {dimension.weight}% | "
                f"{entry.get('score', '-')} | {assessment} |"
            )
        lines.append("")
        lines.append("</details>")
        lines.append("")

        if result.blocking_issues:
            lines.append("**Blocking issues**")
            lines.append("")
            for issue in result.blocking_issues:
                lines.append(f"- **{issue.get('title', 'Issue')}** - {issue.get('detail', '')}")
            lines.append("")

        if result.recommendations:
            lines.append("**Recommendations**")
            lines.append("")
            for rec in result.recommendations:
                priority = rec.get("priority", "medium")
                lines.append(f"- `{priority}` {rec.get('change', '')} — {rec.get('rationale', '')}")
            lines.append("")

    cost = usage.estimated_cost(model)
    footer = (
        f"<sub>Reviewed with `{model}`. "
        f"{usage.input_tokens:,} input / {usage.output_tokens:,} output tokens"
    )
    if usage.cache_read_tokens:
        footer += f", {usage.cache_read_tokens:,} read from cache"
    if cost is not None:
        footer += f" — approximately ${cost:.4f} at list prices"
    footer += ".</sub>"
    lines.append("---")
    lines.append(footer)

    return "\n".join(lines) + "\n"


def to_terminal(results: Iterable[ReviewResult], usage: Usage, model: str) -> str:
    results = sorted(results, key=lambda r: (r.error is not None, r.score))
    lines: list[str] = []
    width = max((len(r.rule_id) for r in results), default=10)

    for result in results:
        label = _VERDICT_LABEL[result.verdict][0]
        if result.error:
            lines.append(f"  {result.rule_id:<{width}}    --    {label:<6}  {result.error}")
            continue
        bar_length = int(result.score / 5)
        bar = "#" * bar_length + "." * (20 - bar_length)
        lines.append(f"  {result.rule_id:<{width}}  {result.score:5.1f}  {label:<6}  [{bar}]")
        for issue in result.blocking_issues:
            lines.append(f"  {'':<{width}}         blocker: {issue.get('title', '')}")

    scored = [r for r in results if r.error is None]
    if scored:
        mean = sum(r.score for r in scored) / len(scored)
        lines.append("")
        lines.append(f"  mean quality score: {mean:.1f}/100 over {len(scored)} rule(s)")
    cost = usage.estimated_cost(model)
    if cost is not None:
        lines.append(f"  estimated cost:     ${cost:.4f} ({model})")
    return "\n".join(lines)
