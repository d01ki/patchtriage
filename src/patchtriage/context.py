"""Layer 4 — Organizational context.

Scanners know nothing about YOUR environment. This layer applies an asset
inventory (simple YAML, checked into your repo) onto findings:

    assets:
      - match: "web-frontend*"        # glob against asset identifier
        criticality: critical         # business criticality
        internet_exposed: true
        owner: platform-team
        notes: "customer-facing checkout"
      - match: "batch-*"
        criticality: low
        internet_exposed: false

The same CVE on an internet-exposed checkout service and on an internal batch
box should never get the same priority. This file is how the tool learns the
difference.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

import yaml

from .models import Finding


def load_inventory(path: str | Path) -> list[dict]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    entries = data.get("assets", [])
    for e in entries:
        if "match" not in e:
            raise ValueError(f"inventory entry missing 'match': {e}")
    return entries


def apply_context(findings: list[Finding], inventory: list[dict]) -> int:
    """Apply the first matching inventory rule to each finding's asset.

    Returns the number of findings that matched a rule.
    """
    matched = 0
    for f in findings:
        for rule in inventory:
            if fnmatch.fnmatch(f.asset.identifier, rule["match"]):
                if "criticality" in rule:
                    f.asset.criticality = str(rule["criticality"])
                if "internet_exposed" in rule:
                    f.asset.internet_exposed = bool(rule["internet_exposed"])
                matched += 1
                break
    return matched
