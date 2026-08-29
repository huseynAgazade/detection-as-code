"""Coverage report for the catalogue.

    python -m pipelines.tools.coverage --output docs/coverage.md

Detection engineering runs on the question "what are we blind to?", and that
question is unanswerable from a directory listing. This renders the catalogue as
ATT&CK coverage, platform coverage, and the log sources everything depends on -
generated from the rules themselves so it cannot drift from them.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from pathlib import Path

from ..lib.catalog import load_detections
from ..lib.mitre import TACTICS


def render(detections_dir: Path) -> str:
    detections, errors = load_detections(detections_dir)

    by_tactic: dict[str, list[str]] = defaultdict(list)
    techniques: set[str] = set()
    platforms: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    data_sources: Counter[str] = Counter()

    for detection in detections:
        statuses[detection.status] += 1
        severities[str(detection.metadata.get("severity", "unknown"))] += 1
        for platform in detection.platforms:
            platforms[platform] += 1
        for source in detection.metadata.get("data_sources", []) or []:
            data_sources[str(source)] += 1
        for mapping in detection.metadata.get("mitre", []) or []:
            if not isinstance(mapping, dict):
                continue
            by_tactic[str(mapping.get("tactic_id"))].append(detection.rule_id)
            techniques.add(str(mapping.get("technique_id")))

    lines: list[str] = []
    lines.append("# Detection coverage")
    lines.append("")
    lines.append(
        "Generated from the rule catalogue by `python -m pipelines.tools.coverage`. "
        "Do not edit by hand."
    )
    lines.append("")
    lines.append(
        f"**{len(detections)} rules** covering **{len(techniques)} ATT&CK techniques** "
        f"across **{len(by_tactic)} tactics**."
    )
    lines.append("")

    lines.append("## ATT&CK tactic coverage")
    lines.append("")
    lines.append("| Tactic | ID | Rules | Covered by |")
    lines.append("|--------|----|-------|------------|")
    for tactic_id, tactic_name in TACTICS.items():
        rules = sorted(set(by_tactic.get(tactic_id, [])))
        covered = ", ".join(f"`{r}`" for r in rules) if rules else "_no coverage_"
        lines.append(f"| {tactic_name} | {tactic_id} | {len(rules)} | {covered} |")
    lines.append("")

    def table(title: str, counter: Counter[str], label: str) -> None:
        lines.append(f"## {title}")
        lines.append("")
        lines.append(f"| {label} | Rules |")
        lines.append(f"|{'-' * (len(label) + 2)}|-------|")
        for key, count in counter.most_common():
            lines.append(f"| {key} | {count} |")
        lines.append("")

    table("Platform coverage", platforms, "Platform")
    table("Lifecycle status", statuses, "Status")
    table("Severity distribution", severities, "Severity")
    table("Log source dependencies", data_sources, "Data source")

    if errors:
        lines.append("## Files that could not be read")
        lines.append("")
        for message in errors:
            lines.append(f"- {message}")
        lines.append("")

    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m pipelines.tools.coverage",
        description="Render ATT&CK and platform coverage for the catalogue.",
    )
    parser.add_argument("--detections", type=Path, default=Path("detections"))
    parser.add_argument("--output", type=Path, help="Write to a file instead of stdout.")
    args = parser.parse_args(argv)

    content = render(args.detections)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content, encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(content, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
