"""Standard-library HTTP server backing the PatchTriage GUI.

No web framework: one ThreadingHTTPServer + a small router. The browser reads
uploaded files client-side and POSTs their text as JSON, so there is no
multipart parsing. Binds to localhost only.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
import webbrowser
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import urlsplit

from .. import targets as tstore
from ..ingest.sbom import is_sbom
from ..ingest.parsers import sniff_format
from .page import INDEX_HTML
from .runner import run_target

MAX_REQUEST_BYTES = 64 * 1024 * 1024
SESSION_COOKIE = "patchtriage_session"
SESSION_TTL_SECONDS = 6 * 60 * 60
_RUN_LOCKS: dict[tuple[str, str], threading.Lock] = {}
_RUN_LOCKS_GUARD = threading.Lock()


class RequestError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _detect_format(content: str) -> str:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return ""
    return is_sbom(data) or sniff_format(data) or ""


def _public_target(target: dict | None) -> dict | None:
    """Return GUI-safe target metadata without server paths or overrides."""
    if target is None:
        return None
    result = dict(target)
    result["source_file"] = bool(result.get("source_file"))
    result.pop("ssvc_overrides", None)
    return result


class Handler(BaseHTTPRequestHandler):
    server_version = "PatchTriage"

    # ------------------------------------------------------------ helpers
    def _workspace(self) -> str:
        existing = getattr(self, "_workspace_id", None)
        if existing:
            return existing
        value = ""
        try:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            morsel = cookie.get(SESSION_COOKIE)
            value = morsel.value if morsel else ""
        except CookieError:
            value = ""
        if not re.fullmatch(r"[0-9a-f]{32}", value):
            value = secrets.token_hex(16)
            tstore.cleanup_workspaces(SESSION_TTL_SECONDS)
        self._workspace_id = value
        return value

    def _session_cookie(self) -> str:
        value = self._workspace()
        host = self.headers.get("Host", "").split(":", 1)[0].lower()
        secure = "" if host in {"localhost", "127.0.0.1", "[::1]"} else "; Secure"
        return (
            f"{SESSION_COOKIE}={value}; Path=/; Max-Age={SESSION_TTL_SECONDS}; "
            f"HttpOnly; SameSite=Strict{secure}"
        )

    def _security_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("Set-Cookie", self._session_cookie())
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'self'",
        )

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send(self, body: bytes, ctype="text/html; charset=utf-8", status=200):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].lower()
        if content_type != "application/json":
            raise RequestError("Content-Type must be application/json", 415)
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError as exc:
            raise RequestError("invalid Content-Length") from exc
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise RequestError("request body is too large", 413)
        if not length:
            return {}
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RequestError("request body must be valid UTF-8 JSON") from exc
        if not isinstance(body, dict):
            raise RequestError("request body must be a JSON object")
        return body

    def _origin_allowed(self) -> bool:
        """Reject browser cross-site writes while allowing non-browser clients."""
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlsplit(origin)
        host = self.headers.get("Host", "")
        return parsed.scheme in ("http", "https") and parsed.netloc.lower() == host.lower()

    def log_message(self, *args):  # quiet by default
        pass

    # ------------------------------------------------------------ routing
    def _guard(self, fn):
        """Never drop the connection on an unhandled error — return JSON 500
        so the browser shows a message instead of a dead request."""
        try:
            fn()
        except RequestError as exc:
            self._send_json({"error": str(exc)}, exc.status)
        except BrokenPipeError:
            raise
        except Exception as exc:
            try:
                self._send_json(
                    {"error": f"{type(exc).__name__}: {exc}"}, 500)
            except Exception:
                pass

    def do_GET(self):
        self._guard(self._do_GET)

    def do_POST(self):
        if not self._origin_allowed():
            return self._send_json({"error": "cross-origin request rejected"}, 403)
        self._guard(self._do_POST)

    def do_DELETE(self):
        if not self._origin_allowed():
            return self._send_json({"error": "cross-origin request rejected"}, 403)
        self._guard(self._do_DELETE)

    def _do_GET(self):
        workspace = self._workspace()
        path = self.path.split("?", 1)[0]
        if path == "/":
            return self._send(INDEX_HTML.encode("utf-8"))
        if path == "/api/config":
            has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
            backends = ["rules"] + (["claude", "cascade"] if has_key else [])
            return self._send_json({
                "backends": backends,
                "has_key": has_key,
                "capabilities": ["offline-demo", "ssvc-deployer",
                                 "epss-baseline", "kev-baseline",
                                 "reachability", "runtime-context",
                                 "vendor-advisories"],
                "data_isolation": "anonymous-session",
                "retention_hours": SESSION_TTL_SECONDS // 3600,
                "connectors": {
                    "msrc": "public", "rhsa": "public", "usn": "public",
                    "debian": "public",
                    "ghsa": ("token" if (os.environ.get("GITHUB_TOKEN") or
                                           os.environ.get("GH_TOKEN"))
                             else "public-rate-limit"),
                },
            })
        if path == "/api/targets":
            return self._send_json([
                _public_target(target)
                for target in tstore.load_targets(workspace)
            ])
        m = re.fullmatch(r"/report/([0-9a-f]{12})", path)
        if m:
            rp = tstore.report_path(m.group(1), workspace)
            if rp.exists():
                return self._send(rp.read_bytes())
            return self._send(b"report not generated yet", status=404)
        return self._send(b"not found", status=404)

    def _do_POST(self):
        workspace = self._workspace()
        path = self.path.split("?", 1)[0]
        if path == "/api/demo":
            self._read_json()
            existing = next(
                (target for target in tstore.load_targets(workspace)
                 if target.get("demo")),
                None,
            )
            created = existing is None
            target = existing or tstore.add_target(
                name="Demo",
                criticality="critical",
                internet_exposed=True,
                reachable=True,
                runtime_observed=True,
                system_exposure="open",
                mission_impact="mef_failure",
                safety_impact="critical",
                context_sources=["OpenTelemetry", "Falco"],
                demo=True,
                workspace_id=workspace,
            )
            fixture = (resources.files("patchtriage") / "data" / "fixtures"
                       / "trivy_sample.json")
            tstore.save_source(
                target["id"], fixture.read_text(encoding="utf-8"), "trivy",
                workspace_id=workspace)
            target = tstore.get_target(target["id"], workspace)
            return self._send_json(
                _public_target(target), 201 if created else 200)

        if path == "/api/targets":
            body = self._read_json()
            if not body.get("name"):
                return self._send_json({"error": "name is required"}, 400)
            try:
                t = tstore.add_target(
                    name=body["name"], url=body.get("url", ""),
                    criticality=body.get("criticality", "unknown"),
                    internet_exposed=body.get("internet_exposed"),
                    reachable=body.get("reachable"),
                    runtime_observed=body.get("runtime_observed"),
                    system_exposure=body.get("system_exposure", "unknown"),
                    mission_impact=body.get("mission_impact", "unknown"),
                    safety_impact=body.get("safety_impact", "unknown"),
                    context_sources=body.get("context_sources"),
                    workspace_id=workspace,
                )
            except ValueError as exc:
                return self._send_json({"error": str(exc)}, 400)
            return self._send_json(_public_target(t), 201)

        m = re.fullmatch(r"/api/targets/([0-9a-f]{12})/context", path)
        if m:
            if not tstore.get_target(m.group(1), workspace):
                return self._send_json({"error": "no such target"}, 404)
            body = self._read_json()
            allowed = {
                "criticality", "internet_exposed", "reachable",
                "runtime_observed", "system_exposure",
                "mission_impact", "safety_impact", "context_sources",
            }
            try:
                target = tstore.update_target(
                    m.group(1), workspace_id=workspace,
                    **{key: value for key, value in body.items()
                       if key in allowed})
            except ValueError as exc:
                return self._send_json({"error": str(exc)}, 400)
            return self._send_json(_public_target(target))

        m = re.fullmatch(r"/api/targets/([0-9a-f]{12})/ssvc-inputs", path)
        if m:
            target = tstore.get_target(m.group(1), workspace)
            if not target:
                return self._send_json({"error": "no such target"}, 404)
            body = self._read_json()
            inputs = body.get("inputs")
            if not isinstance(inputs, list) or len(inputs) > 1000:
                return self._send_json(
                    {"error": "inputs must be a list of at most 1000 items"}, 400)
            overrides = dict(target.get("ssvc_overrides") or {})
            for item in inputs:
                if not isinstance(item, dict):
                    return self._send_json({"error": "invalid SSVC input"}, 400)
                key = str(item.get("finding_key") or "")
                if not key or len(key) > 512:
                    return self._send_json({"error": "invalid finding key"}, 400)
                values = {}
                exploitation = item.get("exploitation", "auto")
                automatable = item.get("automatable", "auto")
                if exploitation != "auto":
                    if exploitation not in {"none", "public_poc", "active"}:
                        return self._send_json(
                            {"error": "invalid Exploitation value"}, 400)
                    values["exploitation"] = exploitation
                if automatable != "auto":
                    if automatable not in {"no", "yes"}:
                        return self._send_json(
                            {"error": "invalid Automatable value"}, 400)
                    values["automatable"] = automatable
                if values:
                    overrides[key] = values
                else:
                    overrides.pop(key, None)
            target = tstore.update_target(
                m.group(1), workspace_id=workspace,
                ssvc_overrides=overrides)
            return self._send_json({"ok": True, "overrides": len(overrides)})

        m = re.fullmatch(r"/api/targets/([0-9a-f]{12})/source", path)
        if m:
            if not tstore.get_target(m.group(1), workspace):
                return self._send_json({"error": "no such target"}, 404)
            body = self._read_json()
            content = body.get("content", "")
            if not content:
                return self._send_json({"error": "empty file"}, 400)
            fmt = _detect_format(content)
            if not fmt:
                return self._send_json(
                    {"error": "unrecognized file — expected Trivy/Grype/OSV "
                              "JSON or a CycloneDX/SPDX SBOM"}, 400)
            tstore.save_source(m.group(1), content, fmt, workspace)
            return self._send_json({"ok": True, "format": fmt})

        m = re.fullmatch(r"/api/targets/([0-9a-f]{12})/run", path)
        if m:
            target = tstore.get_target(m.group(1), workspace)
            if not target:
                return self._send_json({"error": "no such target"}, 404)
            body = self._read_json()
            backend = body.get("backend", "rules")
            allowed = {"rules"}
            if os.environ.get("ANTHROPIC_API_KEY"):
                allowed.update(("claude", "cascade"))
            if backend not in allowed:
                return self._send_json({"error": "backend is not available"}, 400)
            try:
                with _RUN_LOCKS_GUARD:
                    run_lock = _RUN_LOCKS.setdefault(
                        (workspace, target["id"]), threading.Lock())
                with run_lock:
                    summary = run_target(
                        target, backend=backend,
                        use_nvd=bool(os.environ.get("NVD_API_KEY")),
                        nvd_api_key=os.environ.get("NVD_API_KEY"),
                        workspace_id=workspace)
            except Exception as exc:  # surface to the UI, don't 500 blindly
                return self._send_json(
                    {"error": f"{type(exc).__name__}: {exc}"}, 400)
            return self._send_json(summary)

        return self._send_json({"error": "not found"}, 404)

    def _do_DELETE(self):
        workspace = self._workspace()
        m = re.fullmatch(
            r"/api/targets/([0-9a-f]{12})", self.path.split("?", 1)[0])
        if m:
            if not tstore.delete_target(m.group(1), workspace):
                return self._send_json({"error": "no such target"}, 404)
            self.send_response(204)
            self._security_headers()
            self.end_headers()
            return
        return self._send_json({"error": "not found"}, 404)


def serve(host: str = "127.0.0.1", port: int = 8765,
          open_browser: bool = True) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/"
    print(f"PatchTriage console: {url}  (Ctrl-C to stop)")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping…")
    finally:
        httpd.server_close()
