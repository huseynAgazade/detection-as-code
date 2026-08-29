"""Sensitive-value scan.

A detection repository is one of the easier places to leak an environment by
accident. Tuning is the usual culprit: an exclusion added at 2am names a real
server, a reference links an internal ticket, an example is pasted with a real
address still in it. None of that is caught by a schema, and every bit of it is
permanent once the repository is public or shared with a third party.

So this runs on every commit, and it fails the build rather than warning. The
allowlist exists for the cases where a value genuinely has to be there, and it
is a reviewed file like any other - the point is that the exception is written
down and someone approved it.

Documentation ranges (RFC 5737, RFC 3849) and reserved example domains
(RFC 2606) are always accepted: they exist precisely so examples do not need
real values.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

from ..lib.findings import Report

ALLOWLIST_PATH = Path(__file__).with_name("allowlist.txt")

# Reserved for documentation and examples; safe by construction.
_DOC_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),     # RFC 5737 TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # RFC 5737 TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # RFC 5737 TEST-NET-3
]

_EXAMPLE_DOMAINS = (
    "example.com", "example.org", "example.net", "example.internal",
    "example.local", "localhost", "invalid", "test",
)

_INTERNAL_TLDS = (".local", ".internal", ".corp", ".lan", ".intranet", ".home", ".domain")


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern[str]
    explanation: str
    fatal: bool = True


PATTERNS: list[Pattern] = [
    Pattern(
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        "a private key block",
    ),
    Pattern(
        "cloud-access-key",
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b"),
        "something shaped like a cloud access key ID",
    ),
    Pattern(
        "bearer-token",
        re.compile(r"\b(?:Bearer|Authorization:)\s+[A-Za-z0-9\-._~+/]{20,}"),
        "an authorization header carrying a token",
    ),
    Pattern(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "a JSON web token",
    ),
    Pattern(
        "assigned-secret",
        re.compile(
            r"(?i)\b(?:api[_-]?key|apikey|secret|passwd|password|token|client[_-]?secret)"
            r"\s*[:=]\s*[\"']?(?!\{\{)(?!\s*$)(?!(?:REDACTED|CHANGEME|PLACEHOLDER|xxx+|<))[^\s\"',{}]{8,}"
        ),
        "a credential assigned inline",
    ),
    Pattern(
        "email-address",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "an email address",
    ),
    Pattern(
        "internal-hostname",
        re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:local|internal|corp|lan|intranet)\b",
                   re.IGNORECASE),
        "an internal hostname",
        fatal=False,
    ),
    Pattern(
        "internal-link",
        re.compile(r"https?://[^\s\"']*(?:jira|confluence|servicenow|sharepoint|gitlab|wiki)[^\s\"']*",
                   re.IGNORECASE),
        "a link to what looks like an internal system",
        fatal=False,
    ),
]

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def load_allowlist(path: Path = ALLOWLIST_PATH) -> list[str]:
    """Read the reviewed exceptions. One literal value per line; `#` comments."""
    if not path.exists():
        return []
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.split("#", 1)[0].strip()
        if value:
            entries.append(value)
    return entries


def _is_allowed(match: str, allowlist: list[str]) -> bool:
    lowered = match.lower()
    return any(entry.lower() in lowered for entry in allowlist)


def _ip_is_sensitive(candidate: str) -> bool:
    """True only for a routable public address. Anything private, reserved, or
    set aside for documentation is fine in a rule or an example."""
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return False  # a version string or a threshold, not an address
    if any(address in network for network in _DOC_NETWORKS):
        return False
    return address.is_global


def _email_is_sensitive(candidate: str) -> bool:
    domain = candidate.rsplit("@", 1)[-1].lower()
    if domain in _EXAMPLE_DOMAINS or domain.endswith(tuple(f".{d}" for d in _EXAMPLE_DOMAINS)):
        return False
    return not domain.endswith(_INTERNAL_TLDS)


def _hostname_is_sensitive(candidate: str) -> bool:
    """An internal-looking hostname built on a reserved example domain is an
    illustration, not a leak."""
    lowered = candidate.lower()
    return not any(
        lowered == domain or lowered.endswith(f".{domain}") for domain in _EXAMPLE_DOMAINS
    )


def scan_text(text: str, path: Path, allowlist: list[str], report: Report) -> None:
    for number, line in enumerate(text.splitlines(), start=1):
        for pattern in PATTERNS:
            for match in pattern.regex.findall(line):
                value = match if isinstance(match, str) else match[0]
                if _is_allowed(value, allowlist):
                    continue
                if pattern.name == "email-address" and not _email_is_sensitive(value):
                    continue
                if pattern.name == "internal-hostname" and not _hostname_is_sensitive(value):
                    continue
                emit = report.error if pattern.fatal else report.warn
                emit(
                    f"sensitive:{pattern.name}",
                    f"{pattern.explanation} appears here ({_redact(value)}); replace it with a "
                    f"variable, a documentation-range value, or add a reviewed entry to "
                    f"{ALLOWLIST_PATH.name}",
                    path,
                    number,
                )

        for candidate in _IPV4_RE.findall(line):
            if _is_allowed(candidate, allowlist) or not _ip_is_sensitive(candidate):
                continue
            report.error(
                "sensitive:public-ip",
                f"a routable public IP address appears here ({_redact(candidate)}); use a "
                f"documentation range (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), a "
                f"variable, or an environment exclusion",
                path,
                number,
            )


def _redact(value: str) -> str:
    """Show enough to find the line, not enough to republish the secret."""
    if len(value) <= 8:
        return value
    return f"{value[:4]}...{value[-2:]}"


def scan_paths(paths: list[Path], report: Report, allowlist: list[str] | None = None) -> None:
    allowlist = load_allowlist() if allowlist is None else allowlist
    for root in paths:
        if not root.exists():
            continue
        files = [root] if root.is_file() else sorted(
            p for p in root.rglob("*") if p.is_file() and p.suffix in {".yaml", ".yml", ".json", ".md"}
        )
        for path in files:
            if path.resolve() == ALLOWLIST_PATH.resolve():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            scan_text(text, path, allowlist, report)
