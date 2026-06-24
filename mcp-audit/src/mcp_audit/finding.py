"""Finding model — the structured output of every check.

Designed to be both LLM-readable (`message` + `remediation` are full
prose) and machine-readable (`to_dict()` for JSON).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    """How urgently a finding should be acted on.

    - HIGH:   exploitable vuln, broken contract, or production-shape bug.
              Block release.
    - MEDIUM: latent risk under realistic conditions. Fix soon.
    - LOW:    style / hygiene. Improves but doesn't block.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Finding:
    """One audit finding. `check` is the identifier of the check module
    (e.g. `starlette_badhost`); useful for filtering and suppressions."""

    check: str
    severity: Severity
    path: Path
    message: str
    remediation: str
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["path"] = str(self.path)
        d["severity"] = self.severity.value
        return d

    def format_text(self, root: Path | None = None) -> str:
        """One-line + remediation text block, suitable for terminal output."""
        try:
            rel = self.path.relative_to(root) if root else self.path
        except ValueError:
            rel = self.path
        location = f"{rel}:{self.line}" if self.line is not None else str(rel)
        sev = self.severity.value.upper()
        return (
            f"[{sev:6s}] {self.check} @ {location}\n"
            f"           {self.message}\n"
            f"           -> {self.remediation}"
        )
