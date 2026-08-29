"""Structural validation: does this repository still hold together?

Three layers, in order of how expensive they are to get wrong:

  1. Schema conformance, against schemas/detection.schema.json. This is the
     contract every downstream job relies on.
  2. Repository conventions - where a file lives, what its ID may be, that no
     two rules claim the same ID. These are what keep the catalogue navigable
     once it has several hundred rules in it.
  3. Internal consistency - the parts of a rule that must agree with each other
     and that no schema can express: platforms against detection blocks, ATT&CK
     names against ATT&CK IDs, risk objects against the fields the query emits.

Everything here is deterministic and offline. Judgement calls about whether a
rule is any *good* belong to the AI review stage, not to this one.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from ..lib import mitre
from ..lib.catalog import (
    BUILDABLE_STATUSES,
    SUPPORTED_PLATFORMS,
    Detection,
    prefix_for,
)
from ..lib.findings import Report
from ..lib.yamlio import load_yaml

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_FIELD_PLACEHOLDER_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_.]*)\$")
_JINJA_RE = re.compile(r"\{\{(.+?)\}\}", re.DOTALL)


def load_schema(schema_path: str | Path) -> dict[str, Any]:
    with Path(schema_path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def slugify(text: str) -> str:
    return _SLUG_RE.sub("_", text.lower()).strip("_")


# --------------------------------------------------------------------------
# 1. Schema conformance
# --------------------------------------------------------------------------

def check_schema(detection: Detection, validator: Draft202012Validator, report: Report) -> bool:
    """Validate one detection against the JSON schema.

    Returns whether it passed, because the consistency checks below assume a
    rule that already has the right shape - running them on a malformed file
    produces a cascade of confusing follow-on errors.
    """
    errors = sorted(validator.iter_errors(detection.data), key=lambda e: list(e.absolute_path))
    for error in errors:
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        report.error("schema", f"{location}: {error.message}", detection.path)
    return not errors


# --------------------------------------------------------------------------
# 2. Repository conventions
# --------------------------------------------------------------------------

def check_location(detection: Detection, report: Report) -> None:
    """A detection lives in a category folder, never loose in detections/."""
    if len(detection.relative.parts) < 2:
        report.error(
            "location",
            "detection files belong in a category directory (for example "
            "identity/active_directory/), not directly under detections/",
            detection.path,
        )


def check_id_prefix(detection: Detection, report: Report) -> None:
    """The ID prefix has to match the folder, so an ID alone tells you where the
    rule lives and a mis-filed rule is caught at review time."""
    rule_id = detection.rule_id
    if not rule_id:
        return

    expected, category = prefix_for(detection.category_parts)
    if expected is None:
        report.warn(
            "id-prefix",
            f"category '{detection.category}' has no entry in CATEGORY_PREFIXES, so the "
            f"prefix of '{rule_id}' cannot be checked; add it to pipelines/lib/catalog.py",
            detection.path,
        )
        return

    actual = rule_id.split("-")[0]
    if actual != expected:
        report.error(
            "id-prefix",
            f"rule ID '{rule_id}' uses prefix '{actual}' but lives under "
            f"{'/'.join(category)}/, which is allocated '{expected}' "
            f"(expected an ID of the form {expected}-XXX-000)",
            detection.path,
        )


def check_filename(detection: Detection, report: Report) -> None:
    """The filename should be the rule name, so the tree is greppable by name and
    a rename is visible in the diff rather than hidden inside the file."""
    if not detection.name:
        return
    expected = slugify(detection.name)
    actual = detection.path.stem
    if actual != expected:
        report.warn(
            "filename",
            f"filename '{actual}.yaml' does not match the rule name; "
            f"expected '{expected}.yaml'",
            detection.path,
        )


def check_unique_ids(detections: list[Detection], report: Report) -> set[str]:
    """No two rules may claim the same ID. Returns the set of IDs in use."""
    seen: dict[str, Detection] = {}
    for detection in detections:
        rule_id = detection.rule_id
        if not rule_id:
            continue
        if rule_id in seen:
            report.error(
                "unique-id",
                f"rule ID '{rule_id}' is already used by {seen[rule_id].relative}",
                detection.path,
            )
        else:
            seen[rule_id] = detection
    return set(seen)


# --------------------------------------------------------------------------
# 3. Internal consistency
# --------------------------------------------------------------------------

def check_platforms(detection: Detection, report: Report) -> None:
    """metadata.platforms and the detection blocks must describe the same set.

    A platform declared but not implemented builds nothing and silently leaves a
    coverage gap; a block present but undeclared never reaches the build stage at
    all. Both look like the rule is deployed when it is not.
    """
    declared = set(detection.platforms)
    implemented = set(detection.data.get("detection", {}) or {})

    for platform in sorted(declared - implemented):
        report.error(
            "platforms",
            f"'{platform}' is listed in metadata.platforms but there is no "
            f"detection.{platform} block",
            detection.path,
        )
    for platform in sorted(implemented - declared):
        report.error(
            "platforms",
            f"a detection.{platform} block exists but '{platform}' is not listed in "
            f"metadata.platforms, so it will never be built",
            detection.path,
        )


def check_mitre(detection: Detection, report: Report) -> None:
    """Tactic IDs must be real, tactic names must match their IDs, and no pair
    may be listed twice."""
    mappings = detection.metadata.get("mitre") or []
    seen: dict[tuple[str, str], int] = {}

    for index, mapping in enumerate(mappings):
        if not isinstance(mapping, dict):
            continue
        where = f"mitre[{index}]"
        tactic_id = str(mapping.get("tactic_id", ""))
        tactic_name = str(mapping.get("tactic", ""))
        technique_id = str(mapping.get("technique_id", ""))
        technique = str(mapping.get("technique", ""))

        canonical = mitre.canonical_tactic(tactic_id)
        if canonical is None:
            report.error("mitre", f"{where}: unknown tactic_id '{tactic_id}'", detection.path)
        elif tactic_name.strip().lower() != canonical.lower():
            if mitre.is_alias(tactic_id, tactic_name):
                report.warn(
                    "mitre",
                    f"{where}: '{tactic_name}' is a superseded name for {tactic_id}; "
                    f"the current name is '{canonical}'",
                    detection.path,
                )
            else:
                report.error(
                    "mitre",
                    f"{where}: tactic '{tactic_name}' does not match {tactic_id} "
                    f"(which is '{canonical}')",
                    detection.path,
                )

        if re.fullmatch(r"T[0-9]{4}(\.[0-9]{3})?", technique.strip()):
            report.error(
                "mitre",
                f"{where}: 'technique' holds an ID; put the human-readable name there "
                f"and the ID in 'technique_id'",
                detection.path,
            )

        key = (tactic_id, technique_id)
        if key in seen:
            report.error(
                "mitre",
                f"{where}: duplicates mitre[{seen[key]}] ({tactic_id}/{technique_id}); "
                f"map each tactic and technique pair once",
                detection.path,
            )
        else:
            seen[key] = index


def check_lifecycle(detection: Detection, report: Report) -> None:
    """Status and lifecycle have to tell the same story.

    An experimental rule with no soak start can never be reviewed for promotion:
    it just runs indefinitely in a state nobody owns.
    """
    status = detection.status
    lifecycle = detection.metadata.get("lifecycle") or {}

    if status == "experimental":
        if not lifecycle.get("soak_started"):
            report.error(
                "lifecycle",
                "status is 'experimental' but lifecycle.soak_started is missing, so the "
                "soak window has no end and the rule will never be reviewed for promotion",
                detection.path,
            )
        if not lifecycle.get("owner"):
            report.warn(
                "lifecycle",
                "status is 'experimental' but no lifecycle.owner is set; an unowned soak "
                "is one nobody closes",
                detection.path,
            )

    if status == "deprecated" and not detection.metadata.get("status_reason"):
        report.warn(
            "lifecycle",
            "status is 'deprecated' but status_reason is missing; record what replaced it "
            "or why it was retired",
            detection.path,
        )

    if status not in BUILDABLE_STATUSES and lifecycle.get("promoted"):
        report.warn(
            "lifecycle",
            f"lifecycle.promoted is set but status is '{status}', so the rule is not built",
            detection.path,
        )


def check_risk_fields(detection: Detection, report: Report) -> None:
    """Risk objects and the $placeholders$ in the alert message must name fields
    the query actually emits, or the alert renders with empty values."""
    risk = detection.metadata.get("risk")
    if not isinstance(risk, dict):
        return

    blocks = detection.data.get("detection", {}) or {}
    queries = " ".join(
        str(block.get("query", "")) for block in blocks.values() if isinstance(block, dict)
    )
    if not queries:
        return

    referenced = {obj["field"] for obj in risk.get("objects", []) if isinstance(obj, dict) and "field" in obj}
    referenced |= set(_FIELD_PLACEHOLDER_RE.findall(str(risk.get("message", ""))))

    for name in sorted(referenced):
        # Substring match on purpose: field names are shaped differently per
        # query language (src vs source.ip vs SourceIp), so this catches the
        # common case of a renamed or invented field without pretending to parse
        # three query languages.
        if name not in queries:
            report.warn(
                "risk-fields",
                f"metadata.risk refers to field '{name}', which does not appear in any "
                f"query; the alert will render it empty",
                detection.path,
            )


def check_placeholders(detection: Detection, variables: dict[str, Any], report: Report) -> None:
    """Every {{ jinja }} placeholder must resolve against the base variables.

    The build stage runs with StrictUndefined, so an unresolvable placeholder is
    a build failure. Catching it here names the rule and the variable instead of
    failing later with a stack trace.
    """
    blocks = detection.data.get("detection", {}) or {}
    for platform, block in blocks.items():
        if not isinstance(block, dict):
            continue
        text = json.dumps(block)
        for raw in _JINJA_RE.findall(text):
            expression = raw.strip()
            root = expression.split("|")[0].strip().split(".")[0].split("[")[0].strip()
            if root in ("exclusions", "rules"):
                continue  # environment-scoped, and always guarded by default("")

            missing = _unresolvable_path(expression, variables)
            if missing is not None:
                report.error(
                    "placeholder",
                    f"detection.{platform} uses '{{{{ {expression} }}}}' but '{missing}' is not "
                    f"defined in environments/_base/variables.yaml, so the build will fail",
                    detection.path,
                )


def _unresolvable_path(expression: str, variables: dict[str, Any]) -> str | None:
    """Walk a dotted placeholder path through the base variables.

    Returns the longest prefix that does not resolve, or None when the whole
    path does. Checking only the root name is not enough: `thresholds` existing
    says nothing about `thresholds.a_threshold_that_was_never_added`, and that
    is the typo people actually make - adding a rule and forgetting the value it
    depends on. The build would catch it, but by then the error names a Jinja
    expression rather than a rule.
    """
    head, _, filters = expression.partition("|")
    if "default(" in filters.replace(" ", ""):
        return None  # explicitly guarded; absence is handled, not a build failure

    path = head.strip()
    if not path or "(" in path or "[" in path:
        return None  # a call or a subscript; out of scope for a static check

    node: Any = variables
    walked: list[str] = []
    for segment in path.split("."):
        walked.append(segment)
        if not isinstance(node, dict) or segment not in node:
            return ".".join(walked)
        node = node[segment]
    return None


# --------------------------------------------------------------------------
# Environment configuration
# --------------------------------------------------------------------------

def check_environments(environments_dir: Path, rule_ids: set[str], report: Report) -> None:
    """Environment overlays are code too, and they fail quietly when they are
    wrong: an override keyed on a rule ID that no longer exists simply stops
    applying, and nobody finds out until the rule fires in production."""
    if not environments_dir.is_dir():
        report.error("environments", f"{environments_dir} does not exist")
        return

    base = environments_dir / "_base"
    if not (base / "variables.yaml").is_file():
        report.error("environments", "environments/_base/variables.yaml is missing", base)

    for env_dir in sorted(p for p in environments_dir.iterdir() if p.is_dir()):
        for filename in ("variables.yaml", "exclusions.yaml"):
            path = env_dir / filename
            if not path.is_file():
                report.error("environments", f"{env_dir.name} is missing {filename}", env_dir)
                continue
            try:
                data = load_yaml(path)
            except Exception as exc:  # noqa: BLE001
                report.error("environments", f"could not parse: {exc}", path)
                continue

            if filename == "variables.yaml":
                _check_variables(env_dir, path, data, rule_ids, report)
            else:
                _check_exclusions(path, data, rule_ids, report)


def _check_variables(env_dir: Path, path: Path, data: dict, rule_ids: set[str], report: Report) -> None:
    declared_id = (data.get("environment") or {}).get("id")
    if declared_id and declared_id != env_dir.name:
        report.error(
            "environments",
            f"environment.id is '{declared_id}' but the directory is '{env_dir.name}'; "
            f"the two are used interchangeably downstream",
            path,
        )

    for rule_id, override in (data.get("rules") or {}).items():
        if rule_id not in rule_ids:
            report.warn(
                "environments",
                f"rules.{rule_id} overrides a rule ID that does not exist in the catalogue, "
                f"so the override does nothing",
                path,
            )
        if isinstance(override, dict) and override.get("enabled") is False and not override.get("reason"):
            report.warn(
                "environments",
                f"rules.{rule_id} is disabled without a reason; record why so the next "
                f"person knows whether it can be re-enabled",
                path,
            )


def _check_exclusions(path: Path, data: dict, rule_ids: set[str], report: Report) -> None:
    valid = set(SUPPORTED_PLATFORMS)

    def check_map(mapping: Any, label: str) -> None:
        if not isinstance(mapping, dict):
            report.error("environments", f"{label} must be a mapping", path)
            return
        for platform, names in mapping.items():
            if platform not in valid:
                report.error("environments", f"{label}.{platform} is not a known platform", path)
                continue
            if not isinstance(names, dict):
                report.error(
                    "environments",
                    f"{label}.{platform} must map exclusion names to query text",
                    path,
                )
                continue
            for name, text in names.items():
                if not isinstance(text, str) or not text.strip():
                    report.error(
                        "environments",
                        f"exclusion '{name}' in {label}.{platform} is empty; remove it "
                        f"rather than leaving a placeholder that renders nothing",
                        path,
                    )

    check_map(data.get("exclusions") or {}, "exclusions")
    for rule_id, per_rule in (data.get("rules") or {}).items():
        if rule_id not in rule_ids:
            report.warn(
                "environments",
                f"rules.{rule_id} defines exclusions for a rule ID that does not exist",
                path,
            )
        check_map(per_rule or {}, f"rules.{rule_id}")


# --------------------------------------------------------------------------
# Entry point used by the CLI
# --------------------------------------------------------------------------

def validate(
    detections: list[Detection],
    schema: dict[str, Any],
    base_variables: dict[str, Any],
    environments_dir: Path,
    report: Report,
) -> set[str]:
    """Run every structural check. Returns the set of rule IDs in the catalogue."""
    validator = Draft202012Validator(schema)

    for detection in detections:
        if not check_schema(detection, validator, report):
            continue
        check_location(detection, report)
        check_id_prefix(detection, report)
        check_filename(detection, report)
        check_platforms(detection, report)
        check_mitre(detection, report)
        check_lifecycle(detection, report)
        check_risk_fields(detection, report)
        check_placeholders(detection, base_variables, report)

    rule_ids = check_unique_ids(detections, report)
    check_environments(environments_dir, rule_ids, report)
    return rule_ids
