"""Stage 2 of the pipeline: AI review of detection quality.

    python -m pipelines.review --all
    python -m pipelines.review --changed-from origin/main
    python -m pipelines.review --rule ID-AD-001 --markdown review.md

The structure stage answers "is this a well-formed detection?". This stage
answers the question a linter cannot: "is this a good one?" - and turns the
answer into a number the pipeline can gate on.

Two behaviours are deliberate. Without credentials the stage skips rather than
fails, so a fork or an offline contributor is not blocked by a key they cannot
have; the workflow makes the review required on the branches that matter. And a
review that errors is never counted as a pass - an unreviewed rule is reported
as unreviewed.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..lib.catalog import Detection, load_detections
from . import report as report_module
from . import rubric
from .engine import DEFAULT_MODEL, ReviewResult, Usage, review_detection


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m pipelines.review",
        description="Score detection rules against the review rubric.",
    )
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--all", action="store_true", help="Review every rule in the catalogue.")
    selection.add_argument(
        "--changed-from",
        metavar="REF",
        help="Review only rules changed against a git ref (for example origin/main).",
    )
    selection.add_argument("--rule", action="append", default=[], metavar="ID", help="Review specific rule IDs.")

    parser.add_argument("--detections", type=Path, default=Path("detections"))
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--concurrency", type=int, default=4, help="Rules reviewed in parallel.")
    parser.add_argument("--json", type=Path, metavar="PATH", help="Write the full result as JSON.")
    parser.add_argument("--markdown", type=Path, metavar="PATH", help="Write a Markdown report.")
    parser.add_argument(
        "--min-score",
        type=float,
        default=rubric.BLOCK_BELOW,
        help=f"Fail below this score (default: {rubric.BLOCK_BELOW}).",
    )
    parser.add_argument(
        "--require-credentials",
        action="store_true",
        help="Fail instead of skipping when no API credentials are available.",
    )
    parser.add_argument(
        "--no-gate",
        action="store_true",
        help="Report scores without failing the pipeline. Useful when adopting the stage.",
    )
    return parser


def changed_detection_paths(ref: str, detections_dir: Path) -> list[Path]:
    """Detection files that differ from `ref`, so a pull request pays only for
    what it touched."""
    try:
        output = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=d", f"{ref}...HEAD", "--", str(detections_dir)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"Could not determine changed files against '{ref}': {exc}", file=sys.stderr)
        return []
    return [Path(line) for line in output.splitlines() if line.strip().endswith((".yaml", ".yml"))]


def select(detections: list[Detection], args: argparse.Namespace) -> list[Detection]:
    if args.rule:
        wanted = {r.upper() for r in args.rule}
        return [d for d in detections if d.rule_id.upper() in wanted]
    if args.changed_from:
        changed = {p.resolve() for p in changed_detection_paths(args.changed_from, args.detections)}
        return [d for d in detections if d.path.resolve() in changed]
    return detections


def has_credentials() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    detections, parse_errors = load_detections(args.detections)
    for message in parse_errors:
        print(f"  skipped: {message}", file=sys.stderr)

    selected = select(detections, args)
    if not selected:
        print("No detection rules selected for review.")
        return 0

    if not has_credentials():
        message = (
            f"No Anthropic credentials found, so {len(selected)} rule(s) were not reviewed.\n"
            f"Set ANTHROPIC_API_KEY, or run `ant auth login`, to enable this stage."
        )
        if args.require_credentials:
            print(f"ERROR: {message}", file=sys.stderr)
            return 1
        print(f"SKIPPED: {message}")
        return 0

    try:
        import anthropic
    except ImportError:
        print("ERROR: the `anthropic` package is required for this stage (pip install anthropic).", file=sys.stderr)
        return 1

    client = anthropic.Anthropic()
    print(f"Reviewing {len(selected)} rule(s) with {args.model}...\n")

    total_usage = Usage()
    results: list[ReviewResult] = []

    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
        futures = [pool.submit(review_detection, client, d, args.model) for d in selected]
        for future in futures:
            result, usage = future.result()
            total_usage.add(usage)
            results.append(result)

    print(report_module.to_terminal(results, total_usage, args.model))

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(report_module.to_json(results, total_usage, args.model), encoding="utf-8")
        print(f"\n  JSON report:     {args.json}")

    markdown = report_module.to_markdown(results, total_usage, args.model)
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(markdown, encoding="utf-8")
        print(f"  Markdown report: {args.markdown}")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(markdown)

    failed = [r for r in results if r.error is not None]
    blocked = [r for r in results if r.error is None and (r.verdict == "block" or r.score < args.min_score)]

    print("")
    if failed:
        print(f"{len(failed)} rule(s) could not be reviewed:")
        for result in failed:
            print(f"  - {result.rule_id}: {result.error}")
    if blocked:
        print(f"{len(blocked)} rule(s) below the quality bar of {args.min_score}:")
        for result in blocked:
            print(f"  - {result.rule_id}: {result.score:.1f}")

    if args.no_gate:
        print("\nGate disabled (--no-gate): reporting only.")
        return 0
    if failed or blocked:
        print("\nReview stage failed.")
        return 1
    print("\nReview stage passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
