"""Standard-library HTTP server backing the PatchTriage GUI.

No web framework: one ThreadingHTTPServer + a small router. The browser reads
uploaded files client-side and POSTs their text as JSON, so there is no
multipart parsing. Binds to localhost only.
"""

from __future__ import annotations

import json
import os
import re
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import urlsplit

from .. import targets as tstore
from ..ingest.sbom import is_sbom
from ..ingest.parsers import sniff_format
from .page import INDEX_HTML
from .runner import run_target

MAX_REQUEST_BYTES = 64 * 1024 * 1024


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


class Handler(BaseHTTPRequestHandler):
    server_version = "PatchTriage"

    # ------------------------------------------------------------ helpers
    def _security_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
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
                "connectors": {
                    "msrc": "public", "rhsa": "public", "usn": "public",
                    "debian": "public",
                    "ghsa": ("token" if (os.environ.get("GITHUB_TOKEN") or
                                           os.environ.get("GH_TOKEN"))
                             else "public-rate-limit"),
                },
            })
        if path == "/api/targets":
            return self._send_json(tstore.load_targets())
        m = re.fullmatch(r"/report/([0-9a-f]{12})", path)
        if m:
            rp = tstore.report_path(m.group(1))
            if rp.exists():
                return self._send(rp.read_bytes())
            return self._send(b"report not generated yet", status=404)
        return self._send(b"not found", status=404)

    def _do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/demo":
            self._read_json()
            existing = next(
                (target for target in tstore.load_targets() if target.get("demo")),
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
            )
            fixture = (resources.files("patchtriage") / "data" / "fixtures"
                       / "trivy_sample.json")
            tstore.save_source(
                target["id"], fixture.read_text(encoding="utf-8"), "trivy")
            target = tstore.get_target(target["id"])
            return self._send_json(target, 201 if created else 200)

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
                )
            except ValueError as exc:
                return self._send_json({"error": str(exc)}, 400)
            return self._send_json(t, 201)

        m = re.fullmatch(r"/api/targets/([0-9a-f]{12})/context", path)
        if m:
            if not tstore.get_target(m.group(1)):
                return self._send_json({"error": "no such target"}, 404)
            body = self._read_json()
            allowed = {
                "criticality", "internet_exposed", "reachable",
                "runtime_observed", "system_exposure",
                "mission_impact", "safety_impact", "context_sources",
            }
            try:
                target = tstore.update_target(
                    m.group(1), **{key: value for key, value in body.items()
                                  if key in allowed})
            except ValueError as exc:
                return self._send_json({"error": str(exc)}, 400)
            return self._send_json(target)

        m = re.fullmatch(r"/api/targets/([0-9a-f]{12})/source", path)
        if m:
            if not tstore.get_target(m.group(1)):
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
            tstore.save_source(m.group(1), content, fmt)
            return self._send_json({"ok": True, "format": fmt})

        m = re.fullmatch(r"/api/targets/([0-9a-f]{12})/run", path)
        if m:
            target = tstore.get_target(m.group(1))
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
                summary = run_target(
                    target, backend=backend,
                    use_nvd=bool(os.environ.get("NVD_API_KEY")),
                    nvd_api_key=os.environ.get("NVD_API_KEY"))
            except Exception as exc:  # surface to the UI, don't 500 blindly
                return self._send_json(
                    {"error": f"{type(exc).__name__}: {exc}"}, 400)
            return self._send_json(summary)

        return self._send_json({"error": "not found"}, 404)

    def _do_DELETE(self):
        m = re.fullmatch(
            r"/api/targets/([0-9a-f]{12})", self.path.split("?", 1)[0])
        if m:
            if not tstore.delete_target(m.group(1)):
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
