"""Command-line interface.

  python -m minisiem generate sample_logs
  python -m minisiem analyze sample_logs --config config/rules.json
  python -m minisiem rules
"""
import argparse
import os
import sys

from .config import load_config
from .engine import Engine
from .generator import generate_sample
from .models import SEVERITIES, severity_rank
from .parsers import ParseResult, default_parsers, parse_file
from .reporting import to_json, to_text
from .rules import ALL_RULES


def collect_files(paths):
    """Expand directories into the files inside them."""
    files = []
    for path in paths:
        if os.path.isdir(path):
            files.extend(sorted(os.path.join(path, name) for name in os.listdir(path)
                                if os.path.isfile(os.path.join(path, name))))
        elif os.path.isfile(path):
            files.append(path)
        else:
            raise FileNotFoundError(f"No such file or folder: {path}")
    return files


def cmd_generate(args):
    summary = generate_sample(args.folder, seed=args.seed)
    for path, count in summary.items():
        print(f"Wrote {count:4d} lines to {path}")
    return 0


def cmd_rules(args):
    for rule in ALL_RULES:
        print(f"{rule.name:24} {rule.severity:9} {rule.mitre:10} {rule.description}")
    return 0


def cmd_analyze(args):
    config = load_config(args.config)
    parsers = default_parsers(config.default_year)
    combined = ParseResult()
    for path in collect_files(args.paths):
        combined.merge(parse_file(path, parsers))
    alerts = Engine(config).run(combined.events)
    alerts = [a for a in alerts if severity_rank(a.severity) >= severity_rank(args.min_severity)]

    output = to_json(alerts, combined) if args.format == "json" else to_text(alerts, combined)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Report written to {args.output} ({len(alerts)} alerts)")
    else:
        print(output)

    if args.fail_on and any(severity_rank(a.severity) >= severity_rank(args.fail_on) for a in alerts):
        return 2  # lets scripts and CI react to serious alerts
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="minisiem", description="Small security log analyzer")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="create fictional sample logs")
    gen.add_argument("folder")
    gen.add_argument("--seed", type=int, default=7)
    gen.set_defaults(func=cmd_generate)

    ana = sub.add_parser("analyze", help="analyze log files or folders")
    ana.add_argument("paths", nargs="+")
    ana.add_argument("--config")
    ana.add_argument("--format", choices=["text", "json"], default="text")
    ana.add_argument("--output", help="write the report to a file")
    ana.add_argument("--min-severity", choices=SEVERITIES, default="INFO")
    ana.add_argument("--fail-on", choices=SEVERITIES, help="exit with code 2 if an alert is this severe")
    ana.set_defaults(func=cmd_analyze)

    rules = sub.add_parser("rules", help="list the detection rules")
    rules.set_defaults(func=cmd_rules)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
