"""Discovery of the detection catalogue and the conventions that hold it together.

Both the validator and the build stage need the same answers to "which files are
detections", "which category does this one belong to", and "what ID prefix does
that category use". They live here so the two can never disagree.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .yamlio import load_yaml

# Directory under detections/ -> rule ID prefix. Keyed by the path segments below
# detections/ and matched most-specific-first, so a nested category can take its
# own prefix if it ever needs one.
CATEGORY_PREFIXES: dict[tuple[str, ...], str] = {
    ("identity",): "ID",
    ("endpoint",): "EDR",
    ("network",): "NET",
    ("os",): "OS",
    ("cloud",): "CLD",
    ("web",): "WEB",
    ("email",): "EML",
    ("saas",): "SAA",
    ("operational",): "OPS",
}

# Statuses that the build stage will render. A draft is not deployed anywhere,
# and a deprecated rule is kept for history only.
BUILDABLE_STATUSES = frozenset({"experimental", "stable"})

SUPPORTED_PLATFORMS = ("splunk", "sentinel", "elastic")

_SKIP_DIRS = frozenset({".git", "__pycache__", "_deprecated", "templates"})


@dataclass(frozen=True)
class Detection:
    """One parsed detection file, with the context needed to talk about it."""

    path: Path
    relative: Path
    data: dict[str, Any]

    @property
    def metadata(self) -> dict[str, Any]:
        meta = self.data.get("metadata")
        return meta if isinstance(meta, dict) else {}

    @property
    def rule_id(self) -> str:
        return str(self.metadata.get("id", ""))

    @property
    def name(self) -> str:
        return str(self.metadata.get("name", ""))

    @property
    def status(self) -> str:
        return str(self.metadata.get("status", ""))

    @property
    def platforms(self) -> list[str]:
        value = self.metadata.get("platforms")
        return list(value) if isinstance(value, list) else []

    @property
    def category_parts(self) -> tuple[str, ...]:
        return self.relative.parts[:-1]

    @property
    def category(self) -> str:
        return "/".join(self.category_parts)

    def __str__(self) -> str:  # pragma: no cover - display only
        return str(self.relative)


def prefix_for(category_parts: tuple[str, ...]) -> tuple[str | None, tuple[str, ...] | None]:
    """Return (expected ID prefix, the category path it came from) for a
    detection's folder, or (None, None) when the folder is not in the map."""
    for depth in (2, 1):
        key = tuple(category_parts[:depth])
        if key in CATEGORY_PREFIXES:
            return CATEGORY_PREFIXES[key], key
    return None, None


def iter_detection_paths(root: str | Path) -> Iterator[Path]:
    """Yield every path under `root` that should be treated as a detection file."""
    root = Path(root)
    for path in sorted(root.rglob("*.yaml")):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        yield path


def load_detections(root: str | Path) -> tuple[list[Detection], list[str]]:
    """Load the whole catalogue.

    Returns the detections that parsed, and a list of parse errors for the ones
    that did not. A parse failure is reported rather than raised so a single
    broken file does not hide the state of the other hundred.
    """
    root = Path(root)
    detections: list[Detection] = []
    errors: list[str] = []

    for path in iter_detection_paths(root):
        try:
            data = load_yaml(path)
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            errors.append(f"{path}: could not parse YAML: {exc}")
            continue

        if not isinstance(data, dict) or not data:
            errors.append(f"{path}: file is empty or its root is not a mapping")
            continue

        detections.append(
            Detection(path=path, relative=path.relative_to(root), data=data)
        )

    return detections, errors
