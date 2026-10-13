"""Small local threat-intelligence helpers: an IP blocklist and an IP-to-country table."""
import ipaddress
import json
import os


def _parse_ip(text):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


class Blocklist:
    """A set of IP addresses and CIDR ranges that should always raise an alert."""

    def __init__(self, entries=()):
        self.networks = []
        for entry in entries:
            entry = entry.strip()
            if not entry or entry.startswith("#"):
                continue
            try:
                self.networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                continue  # ignore malformed lines instead of crashing

    @classmethod
    def from_file(cls, path):
        with open(path, encoding="utf-8") as f:
            return cls(f.read().splitlines())

    def contains(self, ip) -> bool:
        addr = _parse_ip(ip) if ip else None
        return addr is not None and any(addr in net for net in self.networks)

    def __len__(self):
        return len(self.networks)


class GeoDB:
    """Maps IP ranges to country codes using a JSON file {"cidr": "CC"}."""

    def __init__(self, mapping=None):
        self.table = []
        for cidr, country in (mapping or {}).items():
            try:
                self.table.append((ipaddress.ip_network(cidr, strict=False), country))
            except ValueError:
                continue
        # most specific range first, so a /24 beats a /16
        self.table.sort(key=lambda item: item[0].prefixlen, reverse=True)

    @classmethod
    def from_file(cls, path):
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f))

    def country(self, ip):
        addr = _parse_ip(ip) if ip else None
        if addr is None:
            return None
        for net, country in self.table:
            if addr in net:
                return country
        return None


def load_optional(path, loader):
    """Load a data file if it exists, otherwise return None."""
    if path and os.path.exists(path):
        return loader(path)
    return None
