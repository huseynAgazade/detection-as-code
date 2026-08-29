"""Stage 1 of the pipeline: structure, quality gates, and sensitive values.

    python -m pipelines.validate

Every check is offline and deterministic, so this is also the pre-commit hook and
the thing to run locally before opening a pull request. Warnings do not fail the
build by default; --strict promotes them, which is what the scheduled run uses to
stop the catalogue drifting.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..lib.catalog import load_detections
from ..lib.findings import Report
from ..lib.yamlio import load_yaml
from . import quality_gates, sensitive, structure


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m pipelines.validate",
        description="Validate the detection catalogue: structure, quality gates, sensitive values.",
    )
    parser.add_argument("--detections", type=Path, default=Path("detections"))
    parser.add_argument("--environments", type=Path, default=Path("environments"))
    parser.add_argument("--schema", type=Path, default=Path("schemas/detection.schema.json"))
    parser.add_argument(
        "--skip",
        choices=["structure", "quality", "sensitive"],
        action="append",
        default=[],
        help="Skip a check group. Use sparingly and never in CI.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = Report()

    detections, parse_errors = load_detections(args.detections)
    for message in parse_errors:
        path, _, detail = message.partition(": ")
        report.error("parse", detail, Path(path))

    print(f"Detection catalogue: {len(detections)} rule(s) under {args.detections}/")

    if "structure" not in args.skip:
        print("  -> structure    (schema, conventions, internal consistency)")
        schema = structure.load_schema(args.schema)
        base_variables = load_yaml(args.environments / "_base" / "variables.yaml")
        structure.validate(detections, schema, base_variables, args.environments, report)

    if "quality" not in args.skip:
        print("  -> quality      (query scope, alert hygiene, analyst context)")
        quality_gates.validate(detections, report)

    if "sensitive" not in args.skip:
        print("  -> sensitive    (credentials, public addresses, internal references)")
        sensitive.scan_paths([args.detections, args.environments], report)

    report.render(sys.stdout)
    report.annotate_github()

    errors, warnings = len(report.errors), len(report.warnings)
    print(f"\n{errors} error(s), {warnings} warning(s)")

    if errors:
        print("\nValidation failed.")
        return 1
    if warnings and args.strict:
        print("\nValidation failed: --strict treats warnings as errors.")
        return 1

    print("\nValidation passed." + ("" if not warnings else " Warnings above are worth reading."))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
