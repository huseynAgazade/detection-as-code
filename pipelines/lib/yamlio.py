"""YAML loading with the failure modes this repository cannot afford.

PyYAML resolves a duplicate mapping key by keeping the last one, silently. In a
detection file that is dangerous: a second `metadata:` block, or a rule listed
twice under an environment's `rules:`, discards the earlier definition with no
warning at all. The rule then behaves differently from what the file appears to
say, and nothing in the pipeline notices.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class DuplicateKeyError(Exception):
    """Raised when a YAML mapping defines the same key twice."""


class StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of merging them."""


def _no_duplicate_keys(loader: StrictLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise DuplicateKeyError(
                f"duplicate key {key!r} at line {key_node.start_mark.line + 1} "
                f"(the earlier definition would be silently discarded)"
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    lambda loader, node: _no_duplicate_keys(loader, node),
)


def load_yaml(path: str | Path) -> Any:
    """Parse a YAML file. Returns {} for an empty file so callers can treat a
    missing optional file and an empty one the same way."""
    path = Path(path)
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        content = yaml.load(handle, Loader=StrictLoader)
    return {} if content is None else content


class _BlockDumper(yaml.SafeDumper):
    """Dumper that writes multi-line strings as literal block scalars."""


def _represent_str(dumper: yaml.SafeDumper, data: str):
    # A rendered query is the thing a human reads when they compare what is
    # deployed against what is in the repository. As a quoted scalar full of
    # \n escapes that comparison is unreadable, so multi-line strings keep
    # their line structure.
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


_BlockDumper.add_representer(str, _represent_str)


def dump_yaml(data: Any) -> str:
    """Serialise for build output: block style, keys in the order we set them,
    and no line wrapping (wrapping a query string would change what it means)."""
    return yaml.dump(
        data,
        Dumper=_BlockDumper,
        sort_keys=False,
        default_flow_style=False,
        width=10_000,
        allow_unicode=True,
    )
