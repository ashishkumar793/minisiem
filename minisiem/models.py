"""Data classes shared by the whole project: Event (input) and Alert (output)."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def severity_rank(severity: str) -> int:
    """Return a number so severities can be compared (CRITICAL is highest)."""
    return SEVERITIES.index(severity)


@dataclass
class Event:
    """One normalised log entry. All parsers convert their lines into this."""
    timestamp: datetime          # naive datetime in UTC
    source: str                  # "ssh", "web" or "windows"
    host: str
    action: str                  # login_failed, login_success, http_request, ...
    ip: Optional[str] = None
    user: Optional[str] = None
    raw: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class Alert:
    """A detection result produced by a rule."""
    rule: str
    severity: str
    timestamp: datetime
    summary: str
    ip: Optional[str] = None
    user: Optional[str] = None
    tag: str = ""                # sub-category, e.g. "sqli" for web attacks
    mitre: str = ""              # MITRE ATT&CK technique id
    evidence: list = field(default_factory=list)
    count: int = 1
    last_seen: Optional[datetime] = None

    def __post_init__(self):
        if self.last_seen is None:
            self.last_seen = self.timestamp

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "time": self.timestamp.isoformat(sep=" "),
            "last_seen": self.last_seen.isoformat(sep=" "),
            "summary": self.summary,
            "ip": self.ip,
            "user": self.user,
            "tag": self.tag,
            "mitre": self.mitre,
            "count": self.count,
            "evidence": self.evidence,
        }
