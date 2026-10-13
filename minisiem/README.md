# MiniSIEM

A small security monitoring tool written in Python (standard library only). It reads SSH, web server and
Windows event logs, converts them into one common format, runs detection rules over them and prints a
prioritised list of alerts. It is a learning project that shows how a real SIEM works.

## Quick start
```
python -m minisiem generate sample_logs                         # fictional logs with attack scenarios
python -m minisiem analyze sample_logs --config config/rules.json
python -m minisiem analyze sample_logs --config config/rules.json --format json --output report.json
python -m minisiem rules                                        # list the detection rules
python -m unittest discover -s tests -t .                       # run the tests
```
Useful options: `--min-severity HIGH` hides weaker alerts. `--fail-on CRITICAL` exits with code 2
if an alert of that level exists, so a script or CI job can react.

## How it works
```
log files -> parsers -> Event objects -> rules -> Alerts -> deduplication -> report
```
1. **Parsers** (`minisiem/parsers/`) detect each line's format automatically: OpenSSH syslog,
   Apache/Nginx combined access logs and Windows security events (CSV). All timestamps become UTC.
2. **Rules** (`minisiem/rules/`) look for suspicious behaviour. Each rule is a class with its own
   thresholds, set in `config/rules.json`.
3. **Engine** (`minisiem/engine.py`) runs every rule, merges repeated alerts and sorts by severity.
4. **Reporting** (`minisiem/reporting.py`) prints text or JSON.

## Detection rules
| Rule | Detects | MITRE ATT&CK |
|------|---------|--------------|
| `brute_force` | Many failed logins from one IP in a short window | T1110.001 |
| `password_spray` | One IP trying many usernames | T1110.003 |
| `success_after_failures` | Successful login right after many failures (likely compromise) | T1078 |
| `off_hours_login` | Login outside working hours | T1078 |
| `impossible_travel` | Same user in two countries within hours | T1078 |
| `web_scan` | Bursts of 403/404 responses (directory scanning) | T1595 |
| `web_attack` | SQL injection, XSS, path traversal, command injection strings in URLs | T1190 |
| `bad_user_agent` | Known scanner tools (sqlmap, nikto, ...) | T1595.002 |
| `blocklisted_ip` | Activity from IPs in `config/blocklist.txt` | T1071 |
| `account_created` | Windows event 4720 | T1136 |
| `account_lockout` | Windows event 4740 | T1110 |

## Project layout
```
minisiem/
  models.py        Event and Alert data classes
  parsers/         ssh.py, web.py, windows.py + auto-detection
  rules/           auth, web, windows and intel rules + registry
  intel.py         IP blocklist and IP-to-country lookup
  engine.py        runs rules, deduplicates, sorts
  config.py        config loading with defaults
  generator.py     fictional sample logs (seeded, reproducible)
  reporting.py     text / JSON output
  cli.py           command-line interface
config/            rules.json, geo.json, blocklist.txt
tests/             unit and end-to-end tests
```

## Adding your own rule
Create a class with `name`, `severity`, `mitre`, `defaults` and an `evaluate(events)` method that
returns `Alert` objects, add it to `ALL_RULES` in `minisiem/rules/__init__.py`, and give it a section in
`config/rules.json`.

## Limitations
- Batch analysis only (it reads files; it does not watch logs live yet).
- Geo-lookup uses a tiny local table, and the sample IPs are reserved documentation addresses.
- Rule-based detection can produce false positives; tune the thresholds for your own logs.

## Roadmap
SQLite storage for events and alerts, a Flask dashboard with charts, e-mail/Telegram alerts,
HTML/PDF incident reports, live log tailing.
