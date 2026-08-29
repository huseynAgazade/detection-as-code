"""Which experimental rules are due for a promotion decision.

    python -m pipelines.tools.soak_report
    python -m pipelines.tools.soak_report --fail-on-overdue

A rule enters production as `experimental` and is supposed to be promoted or
retired once its soak window closes. In practice nobody remembers, and the
catalogue fills with rules that have been "on trial" for a year while quietly
generating alerts nobody trusts. This turns the window into something the
pipeline enforces: once a soak is overdue, the weekly health job fails until a
person decides.
"""

from __future__ import annotations

import argparse
from datetime import date, datetime
from pathlib import Path

from ..lib.catalog import load_detections

DEFAULT_SOAK_DAYS = 14


def _parse_date(value: object) -> date | None:
    if isinstance(value, date):
        return value
    try:
        return datetime.strptime(str(value), "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m pipelines.tools.soak_report",
        description="Report experimental rules whose soak window has closed.",
    )
    parser.add_argument("--detections", type=Path, default=Path("detections"))
    parser.add_argument(
        "--fail-on-overdue",
        action="store_true",
        help="Exit non-zero when a soak window has closed without a decision.",
    )
    args = parser.parse_args(argv)

    detections, _ = load_detections(args.detections)
    experimental = [d for d in detections if d.status == "experimental"]

    if not experimental:
        print("No rules are in a soak window.")
        return 0

    today = date.today()
    overdue: list[str] = []

    print(f"{len(experimental)} rule(s) in a soak window:\n")
    for detection in sorted(experimental, key=lambda d: d.rule_id):
        lifecycle = detection.metadata.get("lifecycle") or {}
        started = _parse_date(lifecycle.get("soak_started"))
        days = int(lifecycle.get("soak_days") or DEFAULT_SOAK_DAYS)
        owner = lifecycle.get("owner", "unassigned")

        if started is None:
            print(f"  {detection.rule_id}  no soak_started recorded  (owner: {owner})")
            overdue.append(detection.rule_id)
            continue

        elapsed = (today - started).days
        remaining = days - elapsed
        state = "DUE" if remaining <= 0 else f"{remaining}d left"
        print(
            f"  {detection.rule_id}  {state:<10} started {started} "
            f"({elapsed}/{days} days, owner: {owner})"
        )
        if remaining <= 0:
            overdue.append(detection.rule_id)

    if overdue:
        print(
            f"\n{len(overdue)} rule(s) need a promotion decision: "
            f"{', '.join(sorted(overdue))}.\n"
            f"Promote to status 'stable', extend lifecycle.soak_days with a reason, "
            f"or retire the rule."
        )
        if args.fail_on_overdue:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
