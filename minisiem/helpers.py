"""Small helpers that build Events quickly for the tests."""
from datetime import datetime, timedelta

from minisiem.models import Event

BASE = datetime(2026, 10, 10, 12, 0, 0)


def make_event(offset_seconds=0, action="login_failed", ip="203.0.113.5", user="root",
               source="ssh", **extra):
    ts = BASE + timedelta(seconds=offset_seconds)
    return Event(ts, source, "server", action, ip=ip, user=user,
                 raw=f"{ts.isoformat()} {action} {user} {ip}", extra=extra)


def failures(count, spacing=10, **kwargs):
    return [make_event(i * spacing, **kwargs) for i in range(count)]
