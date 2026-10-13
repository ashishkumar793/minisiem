"""Rules for Windows account-management events."""
from .base import Rule


class AccountCreatedRule(Rule):
    name = "account_created"
    description = "A new user account was created (event 4720)"
    severity = "MEDIUM"
    mitre = "T1136"

    def evaluate(self, events):
        return [self.alert(
            e.timestamp, f"'{e.user}' created account '{e.extra.get('target')}' on {e.host}",
            ip=e.ip, user=e.user, evidence=[e], tag=str(e.extra.get("target")))
            for e in events if e.action == "account_created"]


class AccountLockoutRule(Rule):
    name = "account_lockout"
    description = "An account was locked out (event 4740)"
    severity = "LOW"
    mitre = "T1110"

    def evaluate(self, events):
        return [self.alert(
            e.timestamp, f"Account '{e.user}' was locked out on {e.host}",
            ip=e.ip, user=e.user, evidence=[e])
            for e in events if e.action == "account_locked"]
