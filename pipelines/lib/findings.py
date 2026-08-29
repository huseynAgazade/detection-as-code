"""A single shape for everything the validators report.

Each check returns Findings rather than printing, so the CLI decides how to
render them (terminal, GitHub annotations, JSON) and the exit code is derived
from one place instead of from scattered `sys.exit` calls.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Level(StrEnum):
    """Severity of a finding. A StrEnum so a level interpolates as its own name
    in a message or a GitHub workflow command without an explicit `.value`."""

    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class Finding:
    level: Level
    check: str
    message: str
    path: Path | None = None
    line: int | None = None

    @property
    def location(self) -> str:
        if self.path is None:
            return "<repository>"
        return f"{self.path}:{self.line}" if self.line else str(self.path)


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)

    def error(self, check: str, message: str, path: Path | None = None, line: int | None = None) -> None:
        self.findings.append(Finding(Level.ERROR, check, message, path, line))

    def warn(self, check: str, message: str, path: Path | None = None, line: int | None = None) -> None:
        self.findings.append(Finding(Level.WARNING, check, message, path, line))

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.level is Level.ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.level is Level.WARNING]

    def render(self, stream) -> None:
        """Print findings grouped by file, most severe first."""
        if not self.findings:
            return

        symbols = {Level.ERROR: "ERROR  ", Level.WARNING: "WARNING"}
        by_location: dict[str, list[Finding]] = {}
        for finding in self.findings:
            by_location.setdefault(finding.location, []).append(finding)

        for location in sorted(by_location):
            print(f"\n  {location}", file=stream)
            for finding in sorted(by_location[location], key=lambda f: f.level.value):
                print(f"    {symbols[finding.level]} [{finding.check}] {finding.message}", file=stream)

    def annotate_github(self) -> None:
        """Emit GitHub Actions workflow commands so findings appear inline on the
        pull request diff. A no-op outside Actions."""
        if not os.environ.get("GITHUB_ACTIONS"):
            return
        for finding in self.findings:
            parts = [f"title=detection-validate ({finding.check})"]
            if finding.path is not None:
                parts.append(f"file={finding.path}")
            if finding.line:
                parts.append(f"line={finding.line}")
            message = finding.message.replace("\n", "%0A")
            print(f"::{finding.level.value} {','.join(parts)}::{message}")
