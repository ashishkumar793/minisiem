"""Configuration loading. Everything has a sensible default, so a config file is optional."""
import json
import os
from dataclasses import dataclass, field

DEFAULT_CONFIG = {
    "default_year": 2026,
    "dedupe_minutes": 30,
    "blocklist_file": None,
    "geo_file": None,
    "rules": {},
}


@dataclass
class Config:
    default_year: int = 2026
    dedupe_minutes: int = 30
    blocklist_path: str = None
    geo_path: str = None
    rule_params: dict = field(default_factory=dict)


def _resolve(base_dir, path):
    if not path:
        return None
    return path if os.path.isabs(path) else os.path.join(base_dir, path)


def load_config(path=None) -> Config:
    """Load config from a JSON file. File paths inside it are relative to the file."""
    data = dict(DEFAULT_CONFIG)
    base_dir = "."
    if path:
        base_dir = os.path.dirname(os.path.abspath(path))
        with open(path, encoding="utf-8") as f:
            data.update(json.load(f))
    if not isinstance(data["rules"], dict):
        raise ValueError("'rules' in the config must be an object")
    return Config(
        default_year=int(data["default_year"]),
        dedupe_minutes=int(data["dedupe_minutes"]),
        blocklist_path=_resolve(base_dir, data["blocklist_file"]),
        geo_path=_resolve(base_dir, data["geo_file"]),
        rule_params=data["rules"],
    )
