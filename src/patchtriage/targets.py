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
import re
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from . import config as cfgmod

_LOCK = threading.RLock()
_TARGET_ID = re.compile(r"^[0-9a-f]{12}$")
_CRITICALITIES = {"critical", "high", "medium", "low", "unknown"}


def _validate_target_id(target_id: str) -> str:
    if not _TARGET_ID.fullmatch(str(target_id)):
        raise ValueError("invalid target id")
    return str(target_id)


def _clean_name(value: str) -> str:
    name = str(value or "").strip()
    if not name:
        raise ValueError("name is required")
    if len(name) > 120:
        raise ValueError("name must be 120 characters or fewer")
    return name


def _clean_url(value: str) -> str:
    url = str(value or "").strip()
    if not url:
        return ""
    if len(url) > 2048:
        raise ValueError("url is too long")
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("url must be an absolute http:// or https:// URL")
    return url


def _clean_criticality(value: str) -> str:
    criticality = str(value or "unknown").strip().lower()
    if criticality not in _CRITICALITIES:
        raise ValueError(
            "criticality must be critical, high, medium, low, or unknown")
    return criticality


def _clean_sources(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise ValueError("context_sources must be a list")
    return [str(item).strip()[:80] for item in value[:10] if str(item).strip()]


def _clean_bool(value, field: str, optional: bool = False) -> bool | None:
    if value is None and optional:
        return None
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be true or false")
    return value


def targets_dir() -> Path:
    d = cfgmod.config_dir() / "targets"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _registry_path() -> Path:
    return targets_dir() / "targets.json"


def load_targets() -> list[dict]:
    with _LOCK:
        p = _registry_path()
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                return data if isinstance(data, list) else []
            except (json.JSONDecodeError, OSError):
                return []
        return []


def save_targets(targets: list[dict]) -> None:
    with _LOCK:
        path = _registry_path()
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(targets, indent=2), encoding="utf-8")
        tmp.replace(path)


def add_target(name: str, url: str = "", criticality: str = "unknown",
               internet_exposed: bool = False,
               reachable: bool | None = None,
               runtime_observed: bool | None = None,
               context_sources: list[str] | None = None,
               demo: bool = False) -> dict:
    with _LOCK:
        targets = load_targets()
        target = {
            "id": uuid.uuid4().hex[:12],
            "name": _clean_name(name),
            "url": _clean_url(url),
            "criticality": _clean_criticality(criticality),
            "internet_exposed": _clean_bool(internet_exposed, "internet_exposed"),
            "reachable": _clean_bool(reachable, "reachable", optional=True),
            "runtime_observed": _clean_bool(
                runtime_observed, "runtime_observed", optional=True),
            "context_sources": _clean_sources(context_sources),
            "demo": bool(demo),
            "source_file": "",
            "source_format": "",
            "created_at": time.time(),
        }
        targets.append(target)
        save_targets(targets)
        return target


def update_target(target_id: str, **fields) -> dict | None:
    target_id = _validate_target_id(target_id)
    with _LOCK:
        targets = load_targets()
        for t in targets:
            if t["id"] == target_id:
                if fields.get("name") is not None:
                    t["name"] = _clean_name(fields["name"])
                if fields.get("url") is not None:
                    t["url"] = _clean_url(fields["url"])
                if fields.get("criticality") is not None:
                    t["criticality"] = _clean_criticality(fields["criticality"])
                for key in ("internet_exposed", "reachable", "runtime_observed"):
                    if key in fields and fields[key] is not None:
                        t[key] = _clean_bool(fields[key], key)
                if fields.get("context_sources") is not None:
                    t["context_sources"] = _clean_sources(fields["context_sources"])
                for key in ("source_file", "source_format"):
                    if key in fields and fields[key] is not None:
                        t[key] = str(fields[key])
                save_targets(targets)
                return t
        return None


def delete_target(target_id: str) -> bool:
    target_id = _validate_target_id(target_id)
    with _LOCK:
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
    target_id = _validate_target_id(target_id)
    return next((t for t in load_targets() if t["id"] == target_id), None)


def save_source(target_id: str, content: str, fmt: str = "") -> Path:
    """Persist an uploaded scan/SBOM for a target and link it in the registry."""
    target_id = _validate_target_id(target_id)
    with _LOCK:
        if get_target(target_id) is None:
            raise KeyError("no such target")
        path = targets_dir() / f"{target_id}_source.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(path)
        update_target(target_id, source_file=str(path), source_format=fmt)
        return path


def report_path(target_id: str) -> Path:
    target_id = _validate_target_id(target_id)
    return targets_dir() / f"{target_id}_report.html"
