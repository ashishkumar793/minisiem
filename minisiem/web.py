"""Parser for Apache / Nginx access logs in the "combined" format."""
import re
from datetime import datetime, timezone

from ..models import Event
from .base import BaseParser

COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: [^"]*)?" (?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)


class WebParser(BaseParser):
    name = "web"

    def parse_line(self, line):
        m = COMBINED.match(line.strip())
        if not m:
            return None
        try:
            ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return None
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)  # store everything as naive UTC
        user = None if m["user"] == "-" else m["user"]
        return Event(
            ts, "web", "webserver", "http_request", ip=m["ip"], user=user, raw=line.strip(),
            extra={"method": m["method"], "path": m["path"], "status": int(m["status"]),
                   "user_agent": m["ua"] or ""},
        )
