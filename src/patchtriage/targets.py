"""Target registry for the GUI.

A "target" is one system you want to keep patched — an internal service, a
repository, a host. Organizations have many, so PatchTriage lets you register
a list of them, each with:

  * name          human label (used as the finding's asset identifier)
  * url           a link to the system (dashboard, repo, runbook) — shown as a
                  clickable link in the GUI so reviewers/operators can jump
                  straight to it
  * system_exposure, automatable, mission_impact, safety_impact
                  explicit SSVC Deployer context
  * reachable/runtime_observed
                  supplemental confidence evidence
  * source        an attached scan (Trivy/Grype/OSV JSON) or SBOM
                  (CycloneDX/SPDX), stored alongside the registry

Everything is persisted as JSON under the config dir, so the registry
survives restarts and can be version-controlled if desired.
"""

from __future__ import annotations

import json
import re
import shutil
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from . import config as cfgmod

_LOCK = threading.RLock()
_TARGET_ID = re.compile(r"^[0-9a-f]{12}$")
_WORKSPACE_ID = re.compile(r"^[0-9a-f]{32}$")
_CRITICALITIES = {"critical", "high", "medium", "low", "unknown"}
_SSVC_CHOICES = {
    "system_exposure": {"small", "controlled", "open", "unknown"},
    "automatable": {"yes", "no", "unknown"},
    "mission_impact": {
        "degraded", "mef_support_crippled", "mef_failure",
        "mission_failure", "unknown",
    },
    "safety_impact": {
        "negligible", "marginal", "critical", "catastrophic", "unknown",
    },
}


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


def _clean_ssvc(value: str | None, field: str) -> str:
    if field == "automatable" and isinstance(value, bool):
        return "yes" if value else "no"
    normalized = str(value or "unknown").strip().lower().replace("-", "_")
    if normalized not in _SSVC_CHOICES[field]:
        allowed = ", ".join(sorted(_SSVC_CHOICES[field]))
        raise ValueError(f"{field} must be one of: {allowed}")
    return normalized


def _clean_bool(value, field: str, optional: bool = False) -> bool | None:
    if value is None and optional:
        return None
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be true or false")
    return value


def _clean_workspace_id(workspace_id: str | None) -> str | None:
    if workspace_id is None:
        return None
    value = str(workspace_id)
    if not _WORKSPACE_ID.fullmatch(value):
        raise ValueError("invalid workspace id")
    return value


def targets_dir(workspace_id: str | None = None) -> Path:
    """Return the private target directory for one browser workspace.

    ``None`` preserves the original local/CLI store.  The public GUI passes a
    cryptographically random workspace id held in an HttpOnly cookie, so two
    anonymous visitors never read or write the same registry or evidence.
    """
    workspace_id = _clean_workspace_id(workspace_id)
    d = (cfgmod.config_dir() / "targets" if workspace_id is None else
         cfgmod.config_dir() / "sessions" / workspace_id / "targets")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _registry_path(workspace_id: str | None = None) -> Path:
    return targets_dir(workspace_id) / "targets.json"


def load_targets(workspace_id: str | None = None) -> list[dict]:
    with _LOCK:
        p = _registry_path(workspace_id)
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                return data if isinstance(data, list) else []
            except (json.JSONDecodeError, OSError):
                return []
        return []


def save_targets(targets: list[dict], workspace_id: str | None = None) -> None:
    with _LOCK:
        path = _registry_path(workspace_id)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(targets, indent=2), encoding="utf-8")
        tmp.replace(path)


def add_target(name: str, url: str = "", criticality: str = "unknown",
               internet_exposed: bool | None = None,
               reachable: bool | None = None,
               runtime_observed: bool | None = None,
               system_exposure: str = "unknown",
               automatable: str = "unknown",
               mission_impact: str = "unknown",
               safety_impact: str = "unknown",
               context_sources: list[str] | None = None,
               demo: bool = False,
               workspace_id: str | None = None) -> dict:
    with _LOCK:
        targets = load_targets(workspace_id)
        target = {
            "id": uuid.uuid4().hex[:12],
            "name": _clean_name(name),
            "url": _clean_url(url),
            "criticality": _clean_criticality(criticality),
            "internet_exposed": _clean_bool(
                internet_exposed, "internet_exposed", optional=True),
            "reachable": _clean_bool(reachable, "reachable", optional=True),
            "runtime_observed": _clean_bool(
                runtime_observed, "runtime_observed", optional=True),
            "system_exposure": _clean_ssvc(
                system_exposure, "system_exposure"),
            "automatable": _clean_ssvc(automatable, "automatable"),
            "mission_impact": _clean_ssvc(mission_impact, "mission_impact"),
            "safety_impact": _clean_ssvc(safety_impact, "safety_impact"),
            "context_sources": _clean_sources(context_sources),
            "ssvc_overrides": {},
            "demo": bool(demo),
            "source_file": "",
            "source_format": "",
            "created_at": time.time(),
        }
        targets.append(target)
        save_targets(targets, workspace_id)
        return target


def update_target(target_id: str, workspace_id: str | None = None,
                  **fields) -> dict | None:
    target_id = _validate_target_id(target_id)
    with _LOCK:
        targets = load_targets(workspace_id)
        for t in targets:
            if t["id"] == target_id:
                if fields.get("name") is not None:
                    t["name"] = _clean_name(fields["name"])
                if fields.get("url") is not None:
                    t["url"] = _clean_url(fields["url"])
                if fields.get("criticality") is not None:
                    t["criticality"] = _clean_criticality(fields["criticality"])
                for key in ("internet_exposed", "reachable", "runtime_observed"):
                    if key in fields:
                        t[key] = _clean_bool(fields[key], key, optional=True)
                for key in _SSVC_CHOICES:
                    if key in fields and fields[key] is not None:
                        t[key] = _clean_ssvc(fields[key], key)
                if fields.get("context_sources") is not None:
                    t["context_sources"] = _clean_sources(fields["context_sources"])
                for key in ("source_file", "source_format"):
                    if key in fields and fields[key] is not None:
                        t[key] = str(fields[key])
                if fields.get("ssvc_overrides") is not None:
                    overrides = fields["ssvc_overrides"]
                    if not isinstance(overrides, dict) or len(overrides) > 1000:
                        raise ValueError("ssvc_overrides must be an object")
                    t["ssvc_overrides"] = overrides
                save_targets(targets, workspace_id)
                return t
        return None


def delete_target(target_id: str, workspace_id: str | None = None) -> bool:
    target_id = _validate_target_id(target_id)
    with _LOCK:
        targets = load_targets(workspace_id)
        remaining = [t for t in targets if t["id"] != target_id]
        if len(remaining) == len(targets):
            return False
        # clean up any attached source / report files
        for suffix in ("_source.json", "_report.html"):
            p = targets_dir(workspace_id) / f"{target_id}{suffix}"
            p.unlink(missing_ok=True)
        save_targets(remaining, workspace_id)
        return True


def get_target(target_id: str, workspace_id: str | None = None) -> dict | None:
    target_id = _validate_target_id(target_id)
    return next((t for t in load_targets(workspace_id) if t["id"] == target_id), None)


def save_source(target_id: str, content: str, fmt: str = "",
                workspace_id: str | None = None) -> Path:
    """Persist an uploaded scan/SBOM for a target and link it in the registry."""
    target_id = _validate_target_id(target_id)
    with _LOCK:
        if get_target(target_id, workspace_id) is None:
            raise KeyError("no such target")
        path = targets_dir(workspace_id) / f"{target_id}_source.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(path)
        update_target(target_id, workspace_id=workspace_id,
                      source_file=str(path), source_format=fmt)
        return path


def report_path(target_id: str, workspace_id: str | None = None) -> Path:
    target_id = _validate_target_id(target_id)
    return targets_dir(workspace_id) / f"{target_id}_report.html"


def cleanup_workspaces(max_age_seconds: int = 6 * 60 * 60) -> int:
    """Delete expired anonymous GUI workspaces and their uploaded evidence."""
    root = cfgmod.config_dir() / "sessions"
    if not root.exists():
        return 0
    cutoff = time.time() - max_age_seconds
    removed = 0
    with _LOCK:
        for directory in root.iterdir():
            if (not directory.is_dir()
                    or not _WORKSPACE_ID.fullmatch(directory.name)):
                continue
            try:
                if directory.stat().st_mtime < cutoff:
                    shutil.rmtree(directory)
                    removed += 1
            except OSError:
                continue
    return removed
