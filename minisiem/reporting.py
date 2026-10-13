"""Turn alerts into text or JSON output."""
import json
from collections import Counter

from .models import SEVERITIES


def severity_counts(alerts):
    counts = Counter(a.severity for a in alerts)
    return {s: counts.get(s, 0) for s in reversed(SEVERITIES)}


def to_json(alerts, parse_result=None) -> str:
    payload = {"alert_count": len(alerts), "by_severity": severity_counts(alerts),
               "alerts": [a.to_dict() for a in alerts]}
    if parse_result is not None:
        payload["parsing"] = {"lines": parse_result.total_lines, "skipped": parse_result.skipped,
                              "by_source": parse_result.by_source}
    return json.dumps(payload, indent=2)


def to_text(alerts, parse_result=None) -> str:
    lines = ["=" * 70, "MiniSIEM report", "=" * 70]
    if parse_result is not None:
        sources = ", ".join(f"{k}={v}" for k, v in sorted(parse_result.by_source.items())) or "none"
        lines.append(f"Log lines read: {parse_result.total_lines}  "
                     f"(skipped: {parse_result.skipped})  sources: {sources}")
    counts = severity_counts(alerts)
    lines.append(f"Alerts: {len(alerts)}  (" + ", ".join(f"{k} {v}" for k, v in counts.items() if v) + ")"
                 if alerts else "Alerts: 0")
    lines.append("")
    for a in alerts:
        who = " ".join(x for x in (f"ip={a.ip}" if a.ip else "", f"user={a.user}" if a.user else "") if x)
        repeat = f"  (x{a.count})" if a.count > 1 else ""
        tag = f"/{a.tag}" if a.tag else ""
        lines.append(f"[{a.severity}] {a.timestamp:%Y-%m-%d %H:%M:%S}  {a.rule}{tag}{repeat}")
        lines.append(f"    {a.summary}")
        if who or a.mitre:
            lines.append(f"    {who}  mitre={a.mitre}".rstrip())
        for ev in a.evidence[:2]:
            lines.append(f"    > {ev[:110]}")
        lines.append("")
    return "\n".join(lines)
