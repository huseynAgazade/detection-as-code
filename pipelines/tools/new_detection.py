"""Scaffold a new detection, with its ID already allocated.

    python -m pipelines.tools.new_detection --next-id identity
    python -m pipelines.tools.new_detection \
        --category identity/active_directory \
        --subject AD \
        --name "Kerberos Pre-Authentication Disabled"

Allocating IDs by hand is how two rules end up sharing one, usually on the day
two people write detections in the same category. This reads the catalogue,
takes the next free number for the category, and writes a file that already
passes structure validation, so the author starts from the query rather than
from the boilerplate.
"""

from __future__ import annotations

import argparse
import re
from datetime import date
from pathlib import Path

from ..lib.catalog import CATEGORY_PREFIXES, load_detections, prefix_for
from ..validate.structure import slugify

TEMPLATE_PATH = Path("templates/detection.template.yaml")


def next_id(detections_dir: Path, category: str, subject: str) -> str:
    """Lowest unused number for <prefix>-<subject>-NNN across the catalogue."""
    parts = tuple(category.strip("/").split("/"))
    prefix, _ = prefix_for(parts)
    if prefix is None:
        known = ", ".join(sorted("/".join(k) for k in CATEGORY_PREFIXES))
        raise SystemExit(
            f"'{category}' has no ID prefix. Known categories: {known}.\n"
            f"Add it to CATEGORY_PREFIXES in pipelines/lib/catalog.py first, so the "
            f"convention stays in one place."
        )

    detections, _ = load_detections(detections_dir)
    pattern = re.compile(rf"^{re.escape(prefix)}-{re.escape(subject.upper())}-(\d{{3}})$")
    used = {
        int(match.group(1))
        for match in (pattern.match(d.rule_id) for d in detections)
        if match
    }
    number = next(n for n in range(1, 1000) if n not in used)
    return f"{prefix}-{subject.upper()}-{number:03d}"


def scaffold(detections_dir: Path, category: str, subject: str, name: str, author: str) -> Path:
    if not TEMPLATE_PATH.is_file():
        raise SystemExit(f"Template not found at {TEMPLATE_PATH}")

    rule_id = next_id(detections_dir, category, subject)
    today = date.today().isoformat()
    target_dir = detections_dir / category
    target = target_dir / f"{slugify(name)}.yaml"

    if target.exists():
        raise SystemExit(f"{target} already exists.")

    content = TEMPLATE_PATH.read_text(encoding="utf-8")
    content = content.replace('id: "XX-XXX-000"', f'id: "{rule_id}"')
    content = content.replace(
        'name: "Short, specific, human-readable rule name"', f'name: "{name}"'
    )
    content = content.replace('author: "your.handle"', f'author: "{author}"')
    content = content.replace('created: "2026-01-01"', f'created: "{today}"')
    content = content.replace('modified: "2026-01-01"', f'modified: "{today}"')
    content = content.replace('soak_started: "2026-01-01"', f'soak_started: "{today}"')
    content = content.replace('owner: "your.handle"', f'owner: "{author}"')

    target_dir.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m pipelines.tools.new_detection",
        description="Allocate a rule ID and scaffold a detection file.",
    )
    parser.add_argument("--detections", type=Path, default=Path("detections"))
    parser.add_argument("--next-id", metavar="CATEGORY", help="Print the next free ID and exit.")
    parser.add_argument("--category", help="Category path under detections/, e.g. identity/active_directory")
    parser.add_argument("--subject", help="Three-or-fewer-letter subject code, e.g. AD, DNS, WAF")
    parser.add_argument("--name", help="Rule name; also becomes the filename")
    parser.add_argument("--author", default="huseyn.aghazada")
    args = parser.parse_args(argv)

    if args.next_id:
        subject = args.subject or "GEN"
        print(next_id(args.detections, args.next_id, subject))
        return 0

    missing = [flag for flag, value in (("--category", args.category), ("--name", args.name)) if not value]
    if missing:
        parser.error(f"missing required argument(s): {', '.join(missing)}")

    subject = args.subject or args.category.split("/")[-1][:3].upper()
    target = scaffold(args.detections, args.category, subject, args.name, args.author)
    print(f"Created {target}")
    print("Next: write the query, then run `make validate`.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
