"""The detection engine: runs every rule over the events and cleans up the alerts."""
from datetime import timedelta

from .intel import Blocklist, GeoDB, load_optional
from .models import severity_rank
from .rules import build_rules


def deduplicate(alerts, window):
    """Merge repeated alerts (same rule, ip, user, tag) that happen within `window`."""
    merged, latest = [], {}
    for alert in sorted(alerts, key=lambda a: a.timestamp):
        key = (alert.rule, alert.ip, alert.user, alert.tag)
        previous = latest.get(key)
        if previous is not None and alert.timestamp - previous.last_seen <= window:
            previous.count += alert.count
            previous.last_seen = alert.timestamp
            for line in alert.evidence:
                if len(previous.evidence) < 5 and line not in previous.evidence:
                    previous.evidence.append(line)
        else:
            latest[key] = alert
            merged.append(alert)
    return merged


class Engine:
    def __init__(self, config):
        self.config = config
        context = {
            "blocklist": load_optional(config.blocklist_path, Blocklist.from_file),
            "geo": load_optional(config.geo_path, GeoDB.from_file),
        }
        self.rules = build_rules(config.rule_params, context)
        self.dedupe_window = timedelta(minutes=config.dedupe_minutes)

    def run(self, events):
        """Return alerts sorted by severity (highest first), then by time."""
        ordered = sorted(events, key=lambda e: e.timestamp)
        alerts = []
        for rule in self.rules:
            alerts.extend(rule.evaluate(ordered))
        alerts = deduplicate(alerts, self.dedupe_window)
        return sorted(alerts, key=lambda a: (-severity_rank(a.severity), a.timestamp))
