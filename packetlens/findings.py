"""Finding model shared by expert analyzers, the correlation engine and reports."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
PERSPECTIVES = ("client", "server", "network", "routing", "application", "security")


@dataclass
class Finding:
    id: str
    severity: str
    category: str
    protocol: str
    title: str
    summary: str
    packets: list = field(default_factory=list)
    entities: list = field(default_factory=list)       # hosts / routers / streams involved
    ts: Optional[float] = None
    count: int = 1
    details: dict = field(default_factory=dict)
    causes: list = field(default_factory=list)
    perspectives: dict = field(default_factory=dict)
    remediation: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    filter: str = ""
    uid: str = ""

    def to_dict(self) -> dict:
        return {
            "uid": self.uid, "id": self.id, "severity": self.severity, "category": self.category,
            "protocol": self.protocol, "title": self.title, "summary": self.summary,
            "packets": self.packets[:50], "entities": self.entities[:20], "ts": self.ts,
            "count": self.count, "details": self.details, "causes": self.causes,
            "perspectives": self.perspectives, "remediation": self.remediation,
            "recommendations": self.recommendations, "filter": self.filter,
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.ts or 0))
