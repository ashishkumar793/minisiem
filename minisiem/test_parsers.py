import unittest
from datetime import datetime

from minisiem.parsers import default_parsers, parse_lines
from minisiem.parsers.ssh import SSHParser
from minisiem.parsers.web import WebParser
from minisiem.parsers.windows import WindowsParser

WEB_LINE = ('203.0.113.9 - - [10/Oct/2026:13:55:36 +0530] "GET /index.html HTTP/1.1" '
            '200 2326 "-" "Mozilla/5.0"')


class SSHParserTests(unittest.TestCase):
    def setUp(self):
        self.parser = SSHParser(2026)

    def test_failed_password(self):
        e = self.parser.parse_line(
            "Oct 10 10:00:01 server sshd[101]: Failed password for root from 203.0.113.45 port 22 ssh2")
        self.assertEqual((e.action, e.user, e.ip), ("login_failed", "root", "203.0.113.45"))
        self.assertEqual(e.timestamp, datetime(2026, 10, 10, 10, 0, 1))

    def test_invalid_user_variant(self):
        e = self.parser.parse_line(
            "Oct  9 10:00:01 server sshd[1]: Failed password for invalid user admin from 198.51.100.7 port 1 ssh2")
        self.assertEqual((e.action, e.user), ("login_failed", "admin"))

    def test_accepted(self):
        e = self.parser.parse_line(
            "Oct 10 10:00:01 server sshd[1]: Accepted publickey for alice from 192.0.2.10 port 1 ssh2")
        self.assertEqual(e.action, "login_success")

    def test_rejects_other_formats(self):
        self.assertIsNone(self.parser.parse_line("this is not a log line"))
        self.assertIsNone(self.parser.parse_line(WEB_LINE))


class WebParserTests(unittest.TestCase):
    def test_combined_format_and_timezone(self):
        e = WebParser().parse_line(WEB_LINE)
        self.assertEqual(e.ip, "203.0.113.9")
        self.assertEqual(e.extra["status"], 200)
        self.assertEqual(e.extra["path"], "/index.html")
        # +05:30 offset must be converted to UTC
        self.assertEqual(e.timestamp, datetime(2026, 10, 10, 8, 25, 36))

    def test_rejects_garbage(self):
        self.assertIsNone(WebParser().parse_line("hello world"))


class WindowsParserTests(unittest.TestCase):
    def test_failed_logon(self):
        e = WindowsParser().parse_line("2026-10-10T15:00:00,4625,SRV-DB,svc_backup,198.51.100.77,")
        self.assertEqual((e.action, e.user, e.ip), ("login_failed", "svc_backup", "198.51.100.77"))

    def test_account_created_target(self):
        e = WindowsParser().parse_line("2026-10-10T16:30:00,4720,DC-01,admin2,192.0.2.30,temp_admin")
        self.assertEqual(e.action, "account_created")
        self.assertEqual(e.extra["target"], "temp_admin")

    def test_unknown_event_id(self):
        e = WindowsParser().parse_line("2026-10-10T16:30:00,9999,DC-01,x,-,")
        self.assertEqual(e.action, "windows_event")
        self.assertIsNone(e.ip)


class AutoDetectTests(unittest.TestCase):
    def test_mixed_lines_and_skips(self):
        lines = [
            "timestamp,event_id,host,user,ip,target",   # header: ignored, not counted as skipped
            "Oct 10 10:00:01 server sshd[1]: Failed password for root from 203.0.113.45 port 22 ssh2",
            WEB_LINE,
            "2026-10-10T15:00:00,4625,SRV-DB,svc_backup,198.51.100.77,",
            "garbage line",
            "",
        ]
        result = parse_lines(lines, default_parsers(2026))
        self.assertEqual(result.total_lines, 4)
        self.assertEqual(result.skipped, 1)
        self.assertEqual(result.by_source, {"ssh": 1, "web": 1, "windows": 1})


if __name__ == "__main__":
    unittest.main()
