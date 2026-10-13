"""Rule registry: maps rule names (used in the config file) to rule classes."""
from .auth_rules import (BruteForceRule, ImpossibleTravelRule, OffHoursLoginRule,
                         PasswordSprayRule, SuccessAfterFailuresRule)
from .intel_rules import BlocklistedIPRule
from .web_rules import BadUserAgentRule, WebAttackRule, WebScanRule
from .windows_rules import AccountCreatedRule, AccountLockoutRule

ALL_RULES = [BruteForceRule, PasswordSprayRule, SuccessAfterFailuresRule, OffHoursLoginRule,
             ImpossibleTravelRule, WebScanRule, WebAttackRule, BadUserAgentRule,
             BlocklistedIPRule, AccountCreatedRule, AccountLockoutRule]

REGISTRY = {rule.name: rule for rule in ALL_RULES}


def build_rules(rule_params, context=None):
    """Create rule objects from the config. Unknown names raise an error (catches typos)."""
    unknown = set(rule_params) - set(REGISTRY)
    if unknown:
        raise ValueError(f"Unknown rule(s) in config: {', '.join(sorted(unknown))}")
    rules = []
    for name, cls in REGISTRY.items():
        params = rule_params.get(name, {})
        if params.get("enabled", True):
            rules.append(cls(params, context))
    return rules
