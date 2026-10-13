"""Log parsing: detect each line's format automatically and convert it to Events."""
from dataclasses import dataclass, field
from typing import List

from ..models import Event
from .ssh import SSHParser
from .web import WebParser
from .windows import WindowsParser


CSV_HEADER_PREFIX = "timestamp,event_id"


def default_parsers(default_year=None):
    return [SSHParser(default_year), WebParser(), WindowsParser()]


@dataclass
class ParseResult:
    events: List[Event] = field(default_factory=list)
    total_lines: int = 0
    skipped: int = 0
    by_source: dict = field(default_factory=dict)

    def merge(self, other):
        self.events.extend(other.events)
        self.total_lines += other.total_lines
        self.skipped += other.skipped
        for source, n in other.by_source.items():
            self.by_source[source] = self.by_source.get(source, 0) + n


def parse_lines(lines, parsers) -> ParseResult:
    result = ParseResult()
    preferred = 0  # index of the parser that worked last; logs usually have one format per file
    for line in lines:
        if not line.strip() or line.lower().startswith(CSV_HEADER_PREFIX):
            continue  # blank lines and the CSV header are not log entries
        result.total_lines += 1
        order = [preferred] + [i for i in range(len(parsers)) if i != preferred]
        for i in order:
            event = parsers[i].parse_line(line)
            if event is not None:
                preferred = i
                result.events.append(event)
                result.by_source[event.source] = result.by_source.get(event.source, 0) + 1
                break
        else:
            result.skipped += 1
    return result


def parse_file(path, parsers) -> ParseResult:
    with open(path, encoding="utf-8", errors="replace") as f:
        return parse_lines(f, parsers)
