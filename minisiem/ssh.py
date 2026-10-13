"""Parser for OpenSSH entries in syslog / auth.log format."""
import re
from datetime import datetime

from ..models import Event
from .base import BaseParser

SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) sshd(?:\[\d+\])?: (?P<msg>.*)$"
)
FAILED = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)")
ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)")
INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")


class SSHParser(BaseParser):
    name = "ssh"

    def __init__(self, default_year=None):
        # syslog timestamps have no year, so we have to supply one
        self.year = default_year or datetime.now().year

    def parse_line(self, line):
        m = SYSLOG.match(line.strip())
        if not m:
            return None
        try:
            ts = datetime.strptime(
                f"{self.year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        msg = m["msg"]
        for pattern, action in ((FAILED, "login_failed"), (ACCEPTED, "login_success"),
                                (INVALID, "invalid_user")):
            hit = pattern.search(msg)
            if hit:
                return Event(ts, "ssh", m["host"], action, ip=hit["ip"],
                             user=hit["user"], raw=line.strip())
        # a valid sshd line we do not care about (e.g. "Connection closed")
        return Event(ts, "ssh", m["host"], "ssh_other", raw=line.strip())
