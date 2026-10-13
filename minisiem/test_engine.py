import json
import os
import tempfile
import unittest
from datetime import timedelta

from minisiem.cli import main
from minisiem.config import Config, load_config
from minisiem.engine import Engine, deduplicate
from minisiem.generator import generate_sample
from minisiem.models import Alert
from minisiem.parsers import ParseResult, default_parsers, parse_file
from tests.helpers import BASE

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "rules.json")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def alert(offset_minutes, rule="brute_force", ip="1.1.1.1"):
    return Alert(rule, "HIGH", BASE + timedelta(minutes=offset_minutes), "x", ip=ip, evidence=["e"])


class DedupeTests(unittest.TestCase):
    def test_close_alerts_merge(self):
        merged = deduplicate([alert(0), alert(5), alert(10)], timedelta(minutes=30))
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].count, 3)

    def test_far_apart_or_different_keys_stay_separate(self):
        self.assertEqual(len(deduplicate([alert(0), alert(120)], timedelta(minutes=30))), 2)
        self.assertEqual(len(deduplicate([alert(0), alert(1, ip="2.2.2.2")], timedelta(minutes=30))), 2)


class ConfigTests(unittest.TestCase):
    def test_defaults_without_file(self):
        config = load_config(None)
        self.assertEqual(config.dedupe_minutes, 30)

    def test_paths_are_relative_to_config_file(self):
        config = load_config(CONFIG_PATH)
        self.assertTrue(config.geo_path.endswith("geo.json"))
        self.assertTrue(os.path.exists(config.geo_path))

    def test_bad_rules_section(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c.json")
            with open(path, "w") as f:
                json.dump({"rules": []}, f)
            with self.assertRaises(ValueError):
                load_config(path)


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        generate_sample(cls.tmp.name, seed=7)
        config = load_config(CONFIG_PATH)
        parsers = default_parsers(config.default_year)
        result = ParseResult()
        for name in sorted(os.listdir(cls.tmp.name)):
            result.merge(parse_file(os.path.join(cls.tmp.name, name), parsers))
        cls.parsed = result
        cls.alerts = Engine(config).run(result.events)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_line_is_parsed(self):
        self.assertEqual(self.parsed.skipped, 0)
        self.assertEqual(set(self.parsed.by_source), {"ssh", "web", "windows"})

    def test_all_expected_detections_present(self):
        found = {a.rule for a in self.alerts}
        expected = {"brute_force", "password_spray", "success_after_failures", "off_hours_login",
                    "impossible_travel", "web_scan", "web_attack", "bad_user_agent",
                    "blocklisted_ip", "account_created", "account_lockout"}
        self.assertEqual(expected - found, set())

    def test_critical_alert_is_first(self):
        self.assertEqual(self.alerts[0].severity, "CRITICAL")
        self.assertEqual(self.alerts[0].ip, "203.0.113.45")

    def test_web_attack_categories(self):
        tags = {a.tag for a in self.alerts if a.rule == "web_attack"}
        self.assertEqual(tags, {"sqli", "xss", "path_traversal"})

    def test_generator_is_deterministic(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            generate_sample(a, seed=3)
            generate_sample(b, seed=3)
            for name in os.listdir(a):
                self.assertEqual(read(os.path.join(a, name)), read(os.path.join(b, name)))


class CLITests(unittest.TestCase):
    def test_generate_analyze_json_and_fail_on(self):
        with tempfile.TemporaryDirectory() as tmp:
            logs, report = os.path.join(tmp, "logs"), os.path.join(tmp, "r.json")
            self.assertEqual(main(["generate", logs]), 0)
            code = main(["analyze", logs, "--config", CONFIG_PATH, "--format", "json",
                         "--output", report, "--fail-on", "CRITICAL"])
            self.assertEqual(code, 2)
            data = json.loads(read(report))
            self.assertGreater(data["alert_count"], 10)
            self.assertEqual(data["by_severity"]["CRITICAL"], 1)

    def test_min_severity_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            logs, report = os.path.join(tmp, "logs"), os.path.join(tmp, "r.json")
            main(["generate", logs])
            main(["analyze", logs, "--config", CONFIG_PATH, "--format", "json",
                  "--output", report, "--min-severity", "CRITICAL"])
            self.assertEqual(json.loads(read(report))["alert_count"], 1)

    def test_missing_file_returns_error_code(self):
        self.assertEqual(main(["analyze", "/no/such/file.log"]), 1)


if __name__ == "__main__":
    unittest.main()
