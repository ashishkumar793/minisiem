"""Rules about web server traffic: scanners, attack strings and hacking tools."""
import re
from urllib.parse import unquote

from .base import Rule, find_bursts, group_by

ATTACK_PATTERNS = {
    "sqli": [r"(?i)\bunion\b.{0,20}\bselect\b", r"(?i)'\s*or\s*'?\d", r"(?i)\bor\b\s+1\s*=\s*1",
             r"(?i);\s*drop\s+table", r"(?i)sleep\(\d+\)"],
    "xss": [r"(?i)<script", r"(?i)javascript:", r"(?i)onerror\s*="],
    "path_traversal": [r"\.\./", r"/etc/passwd", r"(?i)boot\.ini"],
    "command_injection": [r"(?i)(;|\|\||&&|\|)\s*(cat|ls|wget|curl|nc|bash|whoami|id)\b",
                          r"\$\([^)]*\)", r"`[^`]+`"],
}


def _web_requests(events):
    return [e for e in events if e.action == "http_request" and e.ip]


class WebScanRule(Rule):
    name = "web_scan"
    description = "Many 403/404 responses to one IP (directory or vulnerability scanning)"
    severity = "MEDIUM"
    mitre = "T1595"
    defaults = {"threshold": 15, "window_minutes": 2}

    def evaluate(self, events):
        alerts = []
        errors = [e for e in _web_requests(events) if e.extra.get("status") in (403, 404)]
        for ip, items in group_by(errors, lambda e: e.ip).items():
            bursts = find_bursts(items, self.window(), lambda s: len(s) >= self.params["threshold"])
            for burst in bursts:
                alerts.append(self.alert(
                    burst[0].timestamp, f"{ip} caused {len(burst)} not-found/forbidden responses",
                    ip=ip, evidence=burst))
        return alerts


class WebAttackRule(Rule):
    name = "web_attack"
    description = "Attack strings in URLs: SQL injection, XSS, traversal, command injection"
    severity = "HIGH"
    mitre = "T1190"
    defaults = {"categories": list(ATTACK_PATTERNS)}

    def __init__(self, params=None, context=None):
        super().__init__(params, context)
        self.compiled = {c: [re.compile(p) for p in ATTACK_PATTERNS[c]]
                         for c in self.params["categories"] if c in ATTACK_PATTERNS}

    def classify(self, path):
        """Return the list of attack categories found in a URL path."""
        decoded = unquote(unquote(path))  # decode twice to catch double-encoding tricks
        return [cat for cat, patterns in self.compiled.items()
                if any(p.search(decoded) for p in patterns)]

    def evaluate(self, events):
        alerts = []
        for e in _web_requests(events):
            for category in self.classify(e.extra.get("path", "")):
                alerts.append(self.alert(
                    e.timestamp, f"{category} pattern in request from {e.ip}: {e.extra['path'][:80]}",
                    ip=e.ip, evidence=[e], tag=category))
        return alerts


class BadUserAgentRule(Rule):
    name = "bad_user_agent"
    description = "Request made by a known scanning or attack tool"
    severity = "MEDIUM"
    mitre = "T1595.002"
    defaults = {"agents": ["sqlmap", "nikto", "nmap", "masscan", "hydra", "dirbuster",
                           "gobuster", "wpscan", "zgrab"]}

    def evaluate(self, events):
        alerts = []
        seen = set()
        for e in _web_requests(events):
            ua = e.extra.get("user_agent", "").lower()
            for agent in self.params["agents"]:
                if agent in ua and (e.ip, agent) not in seen:
                    seen.add((e.ip, agent))
                    alerts.append(self.alert(
                        e.timestamp, f"{e.ip} used the tool signature '{agent}'",
                        ip=e.ip, evidence=[e], tag=agent))
        return alerts
