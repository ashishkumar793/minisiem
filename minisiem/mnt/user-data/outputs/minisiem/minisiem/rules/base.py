"""Base class and helper functions shared by all detection rules."""
from collections import defaultdict
from datetime import timedelta

from ..models import Alert


def group_by(items, keyfunc):
    groups = defaultdict(list)
    for item in items:
        groups[keyfunc(item)].append(item)
    return groups


def find_bursts(items, window, is_hit):
    """Find groups of time-sorted items that happen close together.

    `items` must be sorted by timestamp. A burst starts at items[i], covers every
    item within `window` of it, and must satisfy `is_hit(burst_items)`. A burst keeps
    growing while the next item is within `window` of the previous one.
    """
    bursts = []
    i, n = 0, len(items)
    while i < n:
        j = i
        while j + 1 < n and items[j + 1].timestamp - items[i].timestamp <= window:
            j += 1
        if is_hit(items[i:j + 1]):
            k = j
            while k + 1 < n and items[k + 1].timestamp - items[k].timestamp <= window:
                k += 1
            bursts.append(items[i:k + 1])
            i = k + 1
        else:
            i += 1
    return bursts


class Rule:
    """Every rule has a name, default severity, MITRE id, parameters and evaluate()."""
    name = "base"
    description = ""
    severity = "MEDIUM"
    mitre = ""
    defaults = {}

    def __init__(self, params=None, context=None):
        merged = {**self.defaults, **(params or {})}
        merged.pop("enabled", None)
        self.params = merged
        self.context = context or {}
        self.severity = merged.pop("severity", self.severity)

    def window(self, key="window_minutes"):
        return timedelta(minutes=self.params[key])

    def evaluate(self, events):
        """Take a time-sorted list of Events and return a list of Alerts."""
        raise NotImplementedError

    def alert(self, timestamp, summary, ip=None, user=None, evidence=(), tag="", severity=None):
        return Alert(
            rule=self.name, severity=severity or self.severity, timestamp=timestamp,
            summary=summary, ip=ip, user=user, tag=tag, mitre=self.mitre,
            evidence=[e.raw[:200] for e in list(evidence)[:5]],
        )
