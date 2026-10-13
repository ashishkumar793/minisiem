"""Rules about logins: brute force, password spraying, compromise, odd hours, travel."""
from datetime import timedelta

from .base import Rule, find_bursts, group_by


def _failures(events):
    return [e for e in events if e.action == "login_failed" and e.ip]


class BruteForceRule(Rule):
    name = "brute_force"
    description = "Many failed logins from one IP address in a short time"
    severity = "HIGH"
    mitre = "T1110.001"
    defaults = {"threshold": 5, "window_minutes": 5}

    def evaluate(self, events):
        alerts = []
        for ip, items in group_by(_failures(events), lambda e: e.ip).items():
            bursts = find_bursts(items, self.window(), lambda s: len(s) >= self.params["threshold"])
            for burst in bursts:
                users = sorted({e.user for e in burst if e.user})
                alerts.append(self.alert(
                    burst[0].timestamp,
                    f"{len(burst)} failed logins from {ip} (users tried: {', '.join(users[:5])})",
                    ip=ip, evidence=burst))
        return alerts


class PasswordSprayRule(Rule):
    name = "password_spray"
    description = "One IP address failing against many different usernames"
    severity = "HIGH"
    mitre = "T1110.003"
    defaults = {"threshold": 5, "window_minutes": 10}

    def evaluate(self, events):
        alerts = []
        for ip, items in group_by(_failures(events), lambda e: e.ip).items():
            bursts = find_bursts(
                items, self.window(),
                lambda s: len({e.user for e in s if e.user}) >= self.params["threshold"])
            for burst in bursts:
                distinct = {e.user for e in burst if e.user}
                alerts.append(self.alert(
                    burst[0].timestamp,
                    f"{ip} tried {len(distinct)} different usernames ({len(burst)} attempts)",
                    ip=ip, evidence=burst))
        return alerts


class SuccessAfterFailuresRule(Rule):
    name = "success_after_failures"
    description = "A successful login right after many failures (possible compromise)"
    severity = "CRITICAL"
    mitre = "T1078"
    defaults = {"threshold": 5, "window_minutes": 10}

    def evaluate(self, events):
        alerts = []
        relevant = [e for e in events
                    if e.ip and e.action in ("login_failed", "login_success")]
        for ip, items in group_by(relevant, lambda e: e.ip).items():
            for idx, event in enumerate(items):
                if event.action != "login_success":
                    continue
                recent = [e for e in items[:idx]
                          if e.action == "login_failed"
                          and event.timestamp - e.timestamp <= self.window()]
                if len(recent) >= self.params["threshold"]:
                    alerts.append(self.alert(
                        event.timestamp,
                        f"{ip} logged in as '{event.user}' after {len(recent)} failed attempts",
                        ip=ip, user=event.user, evidence=recent[-3:] + [event]))
        return alerts


class OffHoursLoginRule(Rule):
    name = "off_hours_login"
    description = "Successful login outside normal working hours"
    severity = "MEDIUM"
    mitre = "T1078"
    defaults = {"start_hour": 8, "end_hour": 19, "ignore_users": []}

    def evaluate(self, events):
        alerts = []
        start, end = self.params["start_hour"], self.params["end_hour"]
        for e in events:
            if e.action != "login_success" or e.user in self.params["ignore_users"]:
                continue
            if not (start <= e.timestamp.hour < end):
                alerts.append(self.alert(
                    e.timestamp,
                    f"'{e.user}' logged in at {e.timestamp:%H:%M} from {e.ip}, "
                    f"outside {start:02d}:00-{end:02d}:00",
                    ip=e.ip, user=e.user, evidence=[e]))
        return alerts


class ImpossibleTravelRule(Rule):
    name = "impossible_travel"
    description = "Same user logged in from two countries too quickly"
    severity = "HIGH"
    mitre = "T1078"
    defaults = {"min_hours": 2}

    def evaluate(self, events):
        geo = self.context.get("geo")
        if geo is None:
            return []  # without a country table this rule cannot work
        alerts = []
        logins = [e for e in events if e.action == "login_success" and e.user and e.ip]
        for user, items in group_by(logins, lambda e: e.user).items():
            previous = None
            for e in items:
                country = geo.country(e.ip)
                if country is None:
                    continue
                if previous is not None:
                    prev_event, prev_country = previous
                    gap = e.timestamp - prev_event.timestamp
                    if prev_country != country and gap < timedelta(hours=self.params["min_hours"]):
                        minutes = int(gap.total_seconds() // 60)
                        alerts.append(self.alert(
                            e.timestamp,
                            f"'{user}' logged in from {prev_country} then {country} "
                            f"only {minutes} min later",
                            ip=e.ip, user=user, evidence=[prev_event, e]))
                previous = (e, country)
        return alerts
