"""Parser for Windows security events exported as CSV.

Columns: timestamp,event_id,host,user,ip[,target]
"""
import re
from datetime import datetime

from ..models import Event
from .base import BaseParser

ROW = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}),(?P<eid>\d{4}),(?P<host>[^,]*),"
    r"(?P<user>[^,]*),(?P<ip>[^,]*)(?:,(?P<target>[^,]*))?$"
)

EVENT_ACTIONS = {
    "4624": "login_success",     # successful logon
    "4625": "login_failed",      # failed logon
    "4720": "account_created",   # a user account was created
    "4740": "account_locked",    # a user account was locked out
}


def _clean(value):
    value = (value or "").strip()
    return None if value in ("", "-") else value


class WindowsParser(BaseParser):
    name = "windows"

    def parse_line(self, line):
        m = ROW.match(line.strip())
        if not m:
            return None
        ts = datetime.strptime(m["ts"], "%Y-%m-%dT%H:%M:%S")
        action = EVENT_ACTIONS.get(m["eid"], "windows_event")
        return Event(ts, "windows", _clean(m["host"]) or "unknown", action,
                     ip=_clean(m["ip"]), user=_clean(m["user"]), raw=line.strip(),
                     extra={"event_id": m["eid"], "target": _clean(m["target"])})
