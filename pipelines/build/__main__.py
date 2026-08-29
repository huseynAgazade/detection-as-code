"""Stage 3 of the pipeline: render deployable rules per environment.

    python -m pipelines.build --output dist/
    python -m pipelines.build --environment production

Output layout:

    dist/<environment>/<platform>/<RULE-ID>.yaml
    dist/<environment>/manifest.json

The manifest is the record of what an environment is supposed to be running: the
rule IDs, their versions, and why anything in the catalogue was left out. A
deployment job compares it against what the platform actually has, which is how
a rule that was disabled six months ago and never removed gets noticed.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from ..lib.catalog import BUILDABLE_STATUSES, Detection, load_detections
from ..lib.yamlio import dump_yaml, load_yaml
from .renderer import RenderError, build_context, deep_merge, make_environment, render_block


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m pipelines.build",
        description="Render deployable detection packages for each environment.",
    )
    parser.add_argument("--detections", type=Path, default=Path("detections"))
    parser.add_argument("--environments", type=Path, default=Path("environments"))
    parser.add_argument("--output", type=Path, default=Path("dist"))
    parser.add_argument(
        "--environment",
        action="append",
        default=[],
        metavar="NAME",
        help="Build only these environments (default: all except _base).",
    )
    return parser


def load_environment(environments_dir: Path, name: str) -> tuple[dict, dict]:
    """An environment is its own files merged onto the base ones."""
    base_vars = load_yaml(environments_dir / "_base" / "variables.yaml")
    base_excl = load_yaml(environments_dir / "_base" / "exclusions.yaml")
    env_vars = load_yaml(environments_dir / name / "variables.yaml")
    env_excl = load_yaml(environments_dir / name / "exclusions.yaml")
    return deep_merge(base_vars, env_vars), deep_merge(base_excl, env_excl)


def skip_reason(detection: Detection, variables: dict) -> str | None:
    """Why this rule is not built for this environment, or None if it is."""
    if detection.status not in BUILDABLE_STATUSES:
        return f"status is '{detection.status}'"
    override = (variables.get("rules") or {}).get(detection.rule_id) or {}
    if isinstance(override, dict) and override.get("enabled") is False:
        return override.get("reason") or "disabled for this environment"
    return None


def build_environment(
    name: str,
    detections: list[Detection],
    environments_dir: Path,
    output_dir: Path,
) -> tuple[dict, list[str]]:
    variables, exclusions = load_environment(environments_dir, name)
    jinja_env = make_environment()
    errors: list[str] = []

    enabled_platforms = {
        platform
        for platform, config in (variables.get("platforms") or {}).items()
        if isinstance(config, dict) and config.get("enabled")
    }

    manifest = {
        "environment": name,
        "generated": date.today().isoformat(),
        "enabled_platforms": sorted(enabled_platforms),
        "rules": [],
        "skipped": [],
    }

    env_output = output_dir / name
    for detection in detections:
        reason = skip_reason(detection, variables)
        if reason:
            manifest["skipped"].append({"rule_id": detection.rule_id, "reason": reason})
            continue

        targets = sorted(set(detection.platforms) & enabled_platforms)
        if not targets:
            manifest["skipped"].append(
                {
                    "rule_id": detection.rule_id,
                    "reason": f"no overlap between rule platforms ({', '.join(detection.platforms)}) "
                              f"and those enabled here ({', '.join(sorted(enabled_platforms)) or 'none'})",
                }
            )
            continue

        context = build_context(variables, exclusions, detection.rule_id)

        for platform in targets:
            block = detection.data["detection"][platform]
            try:
                rendered_block = render_block(
                    jinja_env, block, context, f"{detection.rule_id}/{platform}"
                )
            except RenderError as exc:
                errors.append(f"{detection.relative}: {exc}")
                continue

            document = {
                "metadata": {
                    **detection.metadata,
                    "environment": name,
                    "platform": platform,
                    "built": date.today().isoformat(),
                },
                "detection": rendered_block,
            }
            document["metadata"].pop("platforms", None)

            target_dir = env_output / platform
            target_dir.mkdir(parents=True, exist_ok=True)
            (target_dir / f"{detection.rule_id}.yaml").write_text(
                dump_yaml(document), encoding="utf-8"
            )

            manifest["rules"].append(
                {
                    "rule_id": detection.rule_id,
                    "name": detection.name,
                    "version": detection.metadata.get("version"),
                    "status": detection.status,
                    "severity": detection.metadata.get("severity"),
                    "platform": platform,
                    "source": str(detection.relative),
                }
            )

    if manifest["rules"] or manifest["skipped"]:
        env_output.mkdir(parents=True, exist_ok=True)
        (env_output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return manifest, errors


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    detections, parse_errors = load_detections(args.detections)
    if parse_errors:
        for message in parse_errors:
            print(f"ERROR: {message}", file=sys.stderr)
        return 1

    names = args.environment or sorted(
        p.name for p in args.environments.iterdir() if p.is_dir() and not p.name.startswith("_")
    )
    if not names:
        print(f"No environments found under {args.environments}/", file=sys.stderr)
        return 1

    all_errors: list[str] = []
    for name in names:
        manifest, errors = build_environment(name, detections, args.environments, args.output)
        all_errors.extend(errors)
        built = len(manifest["rules"])
        skipped = len(manifest["skipped"])
        platforms = ", ".join(manifest["enabled_platforms"]) or "none"
        print(f"{name:<14} {built:>3} rule/platform artefact(s), {skipped} skipped  [{platforms}]")
        for entry in manifest["skipped"]:
            print(f"                 - {entry['rule_id']}: {entry['reason']}")

    if all_errors:
        print(f"\nBuild failed with {len(all_errors)} error(s):", file=sys.stderr)
        for message in all_errors:
            print(f"  {message}", file=sys.stderr)
        return 1

    print(f"\nWrote {args.output}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
