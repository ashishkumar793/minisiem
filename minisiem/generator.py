"""Generates fictional sample logs that contain known attack scenarios.

All IPs come from the reserved documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), so nothing here points at a real machine. The random generator is seeded,
so the same seed always produces the same files.
"""
import os
import random
import zlib
from datetime import datetime, timedelta
from urllib.parse import quote

OFFICE_IPS = ["192.0.2.10", "192.0.2.20", "192.0.2.30"]
PAGES = ["/", "/index.html", "/about", "/contact", "/products", "/blog/welcome"]
NORMAL_UA = "Mozilla/5.0 (X11; Linux x86_64) Firefox/118.0"


def _at(day, hour, minute, second=0):
    return day.replace(hour=hour, minute=minute, second=second)


# ---------------------------------------------------------------- SSH
def _ssh_line(ts, pid, msg):
    return ts, f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} server sshd[{pid}]: {msg}"


def generate_ssh(rng, day):
    rows, pid = [], 1000

    def add(ts, msg):
        nonlocal pid
        pid += 1
        rows.append(_ssh_line(ts, pid, msg))

    # normal activity
    for hour, minute, user, ip in [(9, 5, "alice", "192.0.2.10"), (10, 20, "bob", "192.0.2.20"),
                                   (12, 30, "bob", "192.0.2.20"), (15, 0, "alice", "192.0.2.10"),
                                   (16, 45, "bob", "192.0.2.20")]:
        add(_at(day, hour, minute), f"Accepted password for {user} from {ip} port {rng.randint(40000, 60000)} ssh2")
    add(_at(day, 10, 19), "Failed password for bob from 192.0.2.20 port 51000 ssh2")  # a typo

    # impossible travel: alice appears in another country 35 minutes later
    add(_at(day, 9, 40), "Accepted password for alice from 198.51.100.33 port 52000 ssh2")

    # off-hours login
    add(_at(day, 3, 12), "Accepted publickey for bob from 192.0.2.20 port 53000 ssh2")

    # brute force that ends with a successful login
    start = _at(day, 2, 15)
    for i in range(12):
        add(start + timedelta(seconds=10 * i + rng.randint(0, 3)),
            f"Failed password for root from 203.0.113.45 port {rng.randint(30000, 40000)} ssh2")
    add(start + timedelta(seconds=140), "Accepted password for root from 203.0.113.45 port 41000 ssh2")

    # password spray
    start = _at(day, 14, 30)
    users = ["admin", "test", "oracle", "postgres", "ubuntu", "guest", "deploy", "jenkins"]
    for i, user in enumerate(users):
        add(start + timedelta(seconds=25 * i),
            f"Failed password for invalid user {user} from 198.51.100.7 port {rng.randint(30000, 40000)} ssh2")
    return sorted(rows)


# ---------------------------------------------------------------- web
def _web_line(ts, ip, path, status, ua=NORMAL_UA, method="GET"):
    size = 200 + zlib.crc32(f"{ip}{path}".encode()) % 4800 if status == 200 else 150
    return ts, (f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" '
                f'{status} {size} "-" "{ua}"')


def generate_web(rng, day):
    rows = []

    # normal visitors
    for i in range(40):
        ts = _at(day, rng.randint(8, 18), rng.randint(0, 59), rng.randint(0, 59))
        rows.append(_web_line(ts, rng.choice(OFFICE_IPS), rng.choice(PAGES), 200))

    # directory scanner using Nikto
    start = _at(day, 11, 0)
    for i in range(40):
        rows.append(_web_line(start + timedelta(seconds=i), "203.0.113.77",
                              f"/admin{i}/login.php", 404, ua="Mozilla/5.00 (Nikto/2.1.6)"))

    # attack strings (payloads are URL-encoded the way a browser or tool would send them)
    sqli = ["/products?id=1' OR '1'='1", "/products?id=1 UNION SELECT username,password FROM users",
            "/search?q=x'; DROP TABLE users;--"]
    for i, payload in enumerate(sqli):
        rows.append(_web_line(_at(day, 13, 0, 10 * i), "198.51.100.50", quote(payload, safe="/?=&"), 200))
    rows.append(_web_line(_at(day, 13, 10), "198.51.100.51",
                          quote("/download?file=../../../../etc/passwd", safe="/?=&"), 404))
    rows.append(_web_line(_at(day, 13, 20), "198.51.100.52",
                          quote("/search?q=<script>alert(1)</script>", safe="/?=&"), 200))

    # a blocklisted address makes a harmless-looking request
    rows.append(_web_line(_at(day, 16, 0), "203.0.113.200", "/", 200))
    return sorted(rows)


# ------------------------------------------------------------ windows
def _win_line(ts, event_id, host, user, ip, target=""):
    return ts, f"{ts:%Y-%m-%dT%H:%M:%S},{event_id},{host},{user},{ip},{target}"


def generate_windows(rng, day):
    rows = [_win_line(_at(day, 9, 10), 4624, "WS-01", "alice", "192.0.2.10"),
            _win_line(_at(day, 14, 5), 4624, "WS-02", "bob", "192.0.2.20")]

    start = _at(day, 15, 0)  # failed logons against a service account, then a lockout
    for i in range(6):
        rows.append(_win_line(start + timedelta(seconds=15 * i), 4625, "SRV-DB", "svc_backup", "198.51.100.77"))
    rows.append(_win_line(_at(day, 15, 2), 4740, "SRV-DB", "svc_backup", "198.51.100.77"))

    rows.append(_win_line(_at(day, 16, 30), 4720, "DC-01", "admin2", "192.0.2.30", "temp_admin"))
    return sorted(rows)


# --------------------------------------------------------------- main
def generate_sample(out_dir, seed=7, year=2026, month=10, day_of_month=10):
    """Write auth.log, access.log and windows_events.csv into out_dir. Returns a summary dict."""
    rng = random.Random(seed)
    day = datetime(year, month, day_of_month)
    os.makedirs(out_dir, exist_ok=True)
    files = {
        "auth.log": [line for _, line in generate_ssh(rng, day)],
        "access.log": [line for _, line in generate_web(rng, day)],
        "windows_events.csv": ["timestamp,event_id,host,user,ip,target"]
                              + [line for _, line in generate_windows(rng, day)],
    }
    summary = {}
    for name, lines in files.items():
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        summary[path] = len(lines)
    return summary
