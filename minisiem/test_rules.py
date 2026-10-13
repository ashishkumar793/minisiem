import unittest
from datetime import timedelta

from minisiem.intel import Blocklist, GeoDB
from minisiem.rules.auth_rules import (BruteForceRule, ImpossibleTravelRule, OffHoursLoginRule,
                                       PasswordSprayRule, SuccessAfterFailuresRule)
from minisiem.rules.base import find_bursts
from minisiem.rules.intel_rules import BlocklistedIPRule
from minisiem.rules.web_rules import BadUserAgentRule, WebAttackRule, WebScanRule
from minisiem.rules.windows_rules import AccountCreatedRule, AccountLockoutRule
from minisiem.rules import build_rules
from tests.helpers import BASE, failures, make_event


class BurstHelperTests(unittest.TestCase):
    def test_burst_found_and_gap_splits_bursts(self):
        events = failures(5, spacing=10) + failures(5, spacing=10)  # same timestamps twice
        events = sorted(events, key=lambda e: e.timestamp)
        window = timedelta(minutes=1)
        self.assertEqual(len(find_bursts(events, window, lambda s: len(s) >= 5)), 1)
        far = failures(5, spacing=10) + [make_event(7200 + i) for i in range(5)]
        self.assertEqual(len(find_bursts(far, window, lambda s: len(s) >= 5)), 2)


class AuthRuleTests(unittest.TestCase):
    def test_brute_force_triggers_at_threshold(self):
        rule = BruteForceRule({"threshold": 5, "window_minutes": 5})
        self.assertEqual(len(rule.evaluate(failures(5))), 1)
        self.assertEqual(rule.evaluate(failures(4)), [])

    def test_brute_force_ignores_slow_attempts(self):
        rule = BruteForceRule({"threshold": 5, "window_minutes": 5})
        self.assertEqual(rule.evaluate(failures(5, spacing=600)), [])

    def test_brute_force_separates_ips(self):
        events = failures(3, ip="1.1.1.1") + failures(3, ip="2.2.2.2")
        self.assertEqual(BruteForceRule({"threshold": 5}).evaluate(events), [])

    def test_password_spray_needs_distinct_users(self):
        same_user = failures(8)
        self.assertEqual(PasswordSprayRule().evaluate(same_user), [])
        many_users = [make_event(i * 10, user=f"user{i}") for i in range(6)]
        self.assertEqual(len(PasswordSprayRule().evaluate(many_users)), 1)

    def test_success_after_failures_is_critical(self):
        events = failures(6) + [make_event(100, action="login_success")]
        alerts = SuccessAfterFailuresRule().evaluate(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "CRITICAL")

    def test_success_without_failures_is_fine(self):
        self.assertEqual(SuccessAfterFailuresRule().evaluate([make_event(0, action="login_success")]), [])

    def test_off_hours(self):
        rule = OffHoursLoginRule({"start_hour": 8, "end_hour": 19, "ignore_users": ["svc"]})
        night = make_event(-9 * 3600, action="login_success")        # 03:00
        day = make_event(0, action="login_success")                  # 12:00
        service = make_event(-9 * 3600, action="login_success", user="svc")
        self.assertEqual(len(rule.evaluate([night, day, service])), 1)

    def test_impossible_travel(self):
        geo = GeoDB({"192.0.2.0/24": "IN", "198.51.100.0/24": "US"})
        rule = ImpossibleTravelRule({"min_hours": 2}, {"geo": geo})
        a = make_event(0, action="login_success", ip="192.0.2.10", user="alice")
        b = make_event(1800, action="login_success", ip="198.51.100.5", user="alice")
        c = make_event(30000, action="login_success", ip="192.0.2.10", user="alice")
        self.assertEqual(len(rule.evaluate([a, b])), 1)
        self.assertEqual(rule.evaluate([a, c]), [])   # same country
        self.assertEqual(rule.evaluate([b, c]), [])   # far enough apart

    def test_impossible_travel_without_geo_is_silent(self):
        self.assertEqual(ImpossibleTravelRule().evaluate([make_event(action="login_success")]), [])


def web(offset, path="/", status=200, ua="Mozilla", ip="203.0.113.9"):
    return make_event(offset, action="http_request", ip=ip, user=None, source="web",
                      path=path, status=status, user_agent=ua)


class WebRuleTests(unittest.TestCase):
    def test_web_scan(self):
        scan = [web(i, path=f"/x{i}", status=404) for i in range(20)]
        self.assertEqual(len(WebScanRule().evaluate(scan)), 1)
        ok = [web(i, status=200) for i in range(30)]
        self.assertEqual(WebScanRule().evaluate(ok), [])

    def test_attack_categories(self):
        rule = WebAttackRule()
        cases = {
            "/p?id=1%27%20OR%20%271%27=%271": "sqli",
            "/p?id=1%20UNION%20SELECT%20a,b%20FROM%20t": "sqli",
            "/s?q=%3Cscript%3Ealert(1)%3C/script%3E": "xss",
            "/d?f=../../etc/passwd": "path_traversal",
            "/d?f=%252e%252e/%252e%252e/x": None,   # double-encoded; decoded twice -> ../
            "/ping?host=1.1.1.1;cat%20/etc/shadow": "command_injection",
        }
        for path, expected in cases.items():
            found = rule.classify(path)
            if expected is None:
                self.assertIn("path_traversal", found, path)
            else:
                self.assertIn(expected, found, path)

    def test_normal_urls_are_not_flagged(self):
        rule = WebAttackRule()
        for path in ["/", "/products?id=42", "/blog/how-to-order-food", "/search?q=cats&sort=asc"]:
            self.assertEqual(rule.classify(path), [], path)

    def test_bad_user_agent_once_per_ip(self):
        events = [web(i, ua="sqlmap/1.7") for i in range(5)]
        self.assertEqual(len(BadUserAgentRule().evaluate(events)), 1)
        self.assertEqual(BadUserAgentRule().evaluate([web(0, ua="Mozilla/5.0")]), [])


class OtherRuleTests(unittest.TestCase):
    def test_blocklist_rule(self):
        context = {"blocklist": Blocklist(["203.0.113.0/28", "# comment", "garbage"])}
        rule = BlocklistedIPRule({}, context)
        self.assertEqual(len(rule.evaluate([make_event(ip="203.0.113.5")])), 1)
        self.assertEqual(rule.evaluate([make_event(ip="198.51.100.5")]), [])
        self.assertEqual(BlocklistedIPRule().evaluate([make_event()]), [])  # no list loaded

    def test_windows_rules(self):
        created = make_event(action="account_created", source="windows", target="temp")
        locked = make_event(action="account_locked", source="windows")
        self.assertEqual(len(AccountCreatedRule().evaluate([created, locked])), 1)
        self.assertEqual(len(AccountLockoutRule().evaluate([created, locked])), 1)

    def test_build_rules_validates_names_and_enabled_flag(self):
        with self.assertRaises(ValueError):
            build_rules({"brute_forse": {}})
        names = [r.name for r in build_rules({"brute_force": {"enabled": False}})]
        self.assertNotIn("brute_force", names)
        self.assertIn("password_spray", names)

    def test_severity_override(self):
        rule = AccountLockoutRule({"severity": "CRITICAL"})
        alert = rule.evaluate([make_event(action="account_locked", source="windows")])[0]
        self.assertEqual(alert.severity, "CRITICAL")


class IntelTests(unittest.TestCase):
    def test_geo_prefers_specific_range(self):
        geo = GeoDB({"10.0.0.0/8": "AA", "10.1.0.0/16": "BB"})
        self.assertEqual(geo.country("10.1.2.3"), "BB")
        self.assertEqual(geo.country("10.9.9.9"), "AA")
        self.assertIsNone(geo.country("8.8.8.8"))
        self.assertIsNone(geo.country("not-an-ip"))


if __name__ == "__main__":
    unittest.main()
