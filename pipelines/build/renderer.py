"""Turning one portable rule into one deployable rule.

A detection in this repository is written once and is deliberately incomplete:
index names, table names, thresholds, and tuning are placeholders. The build
stage resolves them against an environment and writes something a deployment job
could hand to a platform API without further thought.

Two properties are load-bearing:

  * Undefined placeholders are an error, not an empty string. Jinja runs with
    StrictUndefined, so a typo in a variable name fails the build instead of
    quietly rendering `index= ` and producing a rule that matches everything or
    nothing.

  * A multi-line exclusion keeps the indentation of the placeholder it replaced.
    Jinja substitutes text with no awareness of YAML, so without this only the
    first line of a multi-line value lands at the right column and the rendered
    document is invalid. The rewrite below attaches an explicit indent filter to
    any placeholder that sits alone on its line, which is how they are authored.
"""

from __future__ import annotations

import copy
import re
from typing import Any

import jinja2

_OWN_LINE_EXCLUSION = re.compile(
    r"^(?P<indent>[ \t]*)\{\{\s*(?P<expr>exclusions\.[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*"
    r"(?:\s*\|\s*[A-Za-z_][A-Za-z0-9_]*(?:\([^{}]*\))?)*)\s*\}\}[ \t]*$",
    re.MULTILINE,
)


class RenderError(Exception):
    """A rule could not be rendered for an environment."""


def deep_merge(base: dict, override: dict) -> dict:
    """Merge `override` onto `base`, recursing into nested mappings.

    Environments inherit rather than restate, so an environment that changes one
    threshold does not have to copy the other eight and drift from them.
    """
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(result.get(key), dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def make_environment() -> jinja2.Environment:
    return jinja2.Environment(
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,  # rendering query languages, not HTML
    )


def preserve_indentation(text: str) -> str:
    """Attach `| indent(n, first=false)` to every own-line exclusion placeholder,
    where n is the column the placeholder itself sits at."""

    def rewrite(match: re.Match[str]) -> str:
        indent = match.group("indent")
        expression = match.group("expr")
        column = len(indent.expandtabs())
        return f"{indent}{{{{ {expression} | indent({column}, first=false) }}}}"

    return _OWN_LINE_EXCLUSION.sub(rewrite, text)


def tidy(text: str) -> str:
    """Remove the traces an unused placeholder leaves behind.

    An own-line exclusion that an environment has not defined renders to its own
    indentation and nothing else, leaving a whitespace-only line in the middle of
    the query. That is not cosmetic: YAML cannot write a literal block scalar
    when any line has trailing whitespace, so a single unused exclusion turns the
    whole rendered query into an unreadable quoted string full of escapes - which
    is exactly the artefact a reviewer has to read when comparing what is
    deployed against what is in the repository.

    A whitespace-only line is therefore dropped, while a genuinely empty line the
    author wrote is kept: the two are distinguishable, because only the first has
    characters in it.
    """
    lines = [line.rstrip() for line in text.split("\n")]
    kept = [
        line
        for original, line in zip(text.split("\n"), lines, strict=True)
        if line or not original.strip("\n")
    ]
    return "\n".join(kept)


def render_text(env: jinja2.Environment, text: str, context: dict[str, Any], where: str) -> str:
    try:
        rendered = env.from_string(preserve_indentation(text)).render(**context)
    except jinja2.UndefinedError as exc:
        raise RenderError(f"{where}: {exc.message}") from exc
    except jinja2.TemplateSyntaxError as exc:
        raise RenderError(f"{where}: template syntax error on line {exc.lineno}: {exc.message}") from exc
    return tidy(rendered)


def render_block(env: jinja2.Environment, block: Any, context: dict[str, Any], where: str) -> Any:
    """Render every string in a nested structure, leaving other types alone."""
    if isinstance(block, str):
        return render_text(env, block, context, where)
    if isinstance(block, dict):
        return {key: render_block(env, value, context, f"{where}.{key}") for key, value in block.items()}
    if isinstance(block, list):
        return [render_block(env, item, context, f"{where}[{index}]") for index, item in enumerate(block)]
    return block


def build_context(variables: dict, exclusions: dict, rule_id: str) -> dict[str, Any]:
    """The variables one rule sees when it is rendered.

    Rule-scoped exclusions are merged on top of the shared ones, so a rule can
    add a name of its own or override a shared name for itself only, without
    that change leaking into every other rule in the environment.
    """
    shared = (exclusions.get("exclusions") or {})
    rule_scoped = ((exclusions.get("rules") or {}).get(rule_id) or {})

    context = dict(variables)
    context["exclusions"] = deep_merge(shared, rule_scoped)

    overrides = ((variables.get("rules") or {}).get(rule_id) or {})
    if isinstance(overrides, dict) and isinstance(overrides.get("thresholds"), dict):
        context["thresholds"] = deep_merge(variables.get("thresholds", {}), overrides["thresholds"])
    return context
