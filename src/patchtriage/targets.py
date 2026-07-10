"""Target registry for the GUI.

A "target" is one system you want to keep patched — an internal service, a
repository, a host. Organizations have many, so PatchTriage lets you register
a list of them, each with:

  * name          human label (used as the finding's asset identifier)
  * url           a link to the system (dashboard, repo, runbook) — shown as a
                  clickable link in the GUI so reviewers/operators can jump
                  straight to it
  * criticality   business criticality (drives risk weighting)
  * internet_exposed
  * source        an attached scan (Trivy/Grype/OSV JSON) or SBOM
                  (CycloneDX/SPDX), stored alongside the registry

Everything is persisted as JSON under the config dir, so the registry
survives restarts and can be version-controlled if desired.
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

from . import config as cfgmod


def targets_dir() -> Path:
    d = cfgmod.config_dir() / "targets"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _registry_path() -> Path:
    return targets_dir() / "targets.json"


def load_targets() -> list[dict]:
    p = _registry_path()
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
    return []


def save_targets(targets: list[dict]) -> None:
    _registry_path().write_text(json.dumps(targets, indent=2), encoding="utf-8")


def add_target(name: str, url: str = "", criticality: str = "unknown",
               internet_exposed: bool = False) -> dict:
    targets = load_targets()
    target = {
        "id": uuid.uuid4().hex[:12],
        "name": name.strip() or "unnamed",
        "url": url.strip(),
        "criticality": (criticality or "unknown").strip().lower(),
        "internet_exposed": bool(internet_exposed),
        "source_file": "",
        "source_format": "",
        "created_at": time.time(),
    }
    targets.append(target)
    save_targets(targets)
    return target


def update_target(target_id: str, **fields) -> dict | None:
    targets = load_targets()
    for t in targets:
        if t["id"] == target_id:
            for k in ("name", "url", "criticality", "internet_exposed",
                      "source_file", "source_format"):
                if k in fields and fields[k] is not None:
                    t[k] = fields[k]
            save_targets(targets)
            return t
    return None


def delete_target(target_id: str) -> bool:
    targets = load_targets()
    remaining = [t for t in targets if t["id"] != target_id]
    if len(remaining) == len(targets):
        return False
    # clean up any attached source / report files
    for suffix in ("_source.json", "_report.html"):
        p = targets_dir() / f"{target_id}{suffix}"
        p.unlink(missing_ok=True)
    save_targets(remaining)
    return True


def get_target(target_id: str) -> dict | None:
    return next((t for t in load_targets() if t["id"] == target_id), None)


def save_source(target_id: str, content: str, fmt: str = "") -> Path:
    """Persist an uploaded scan/SBOM for a target and link it in the registry."""
    path = targets_dir() / f"{target_id}_source.json"
    path.write_text(content, encoding="utf-8")
    update_target(target_id, source_file=str(path), source_format=fmt)
    return path


def report_path(target_id: str) -> Path:
    return targets_dir() / f"{target_id}_report.html"
