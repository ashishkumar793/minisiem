"""Rule that uses the local IP blocklist."""
from .base import Rule, group_by


class BlocklistedIPRule(Rule):
    name = "blocklisted_ip"
    description = "Activity from an IP address on the blocklist"
    severity = "HIGH"
    mitre = "T1071"

    def evaluate(self, events):
        blocklist = self.context.get("blocklist")
        if blocklist is None:
            return []
        hits = [e for e in events if e.ip and blocklist.contains(e.ip)]
        return [self.alert(
            items[0].timestamp, f"Blocklisted IP {ip} was active ({len(items)} events)",
            ip=ip, evidence=items)
            for ip, items in group_by(hits, lambda e: e.ip).items()]
