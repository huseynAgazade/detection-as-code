"""ATT&CK tactic reference used to check that a rule's mapping is internally
consistent.

This is deliberately a checked-in table rather than a live lookup: CI must give
the same answer offline as it does online, and a mapping that silently changes
meaning between two runs is worse than one that is a release behind. Update the
table when ATT&CK publishes a new version, and add the previous name to
TACTIC_ALIASES so existing content keeps validating while it is remapped.
"""

from __future__ import annotations

TACTICS: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

# Superseded or alternative tactic names, accepted with a warning so a rename in
# ATT&CK does not fail the pipeline on the day it lands.
TACTIC_ALIASES: dict[str, set[str]] = {
    "TA0005": {"stealth", "defence evasion"},
}

TACTIC_IDS_BY_NAME: dict[str, str] = {name.lower(): tid for tid, name in TACTICS.items()}
for _tid, _aliases in TACTIC_ALIASES.items():
    for _alias in _aliases:
        TACTIC_IDS_BY_NAME.setdefault(_alias, _tid)


def canonical_tactic(tactic_id: str) -> str | None:
    """Canonical name for a tactic ID, or None if the ID is unknown."""
    return TACTICS.get(tactic_id)


def is_alias(tactic_id: str, name: str) -> bool:
    """True when `name` is an accepted-but-superseded name for `tactic_id`."""
    return name.strip().lower() in TACTIC_ALIASES.get(tactic_id, set())
