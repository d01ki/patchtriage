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

from .. import targets as tstore
from ..ingest.sbom import is_sbom
from ..ingest.parsers import sniff_format
from .page import INDEX_HTML
from .runner import run_target


def _detect_format(content: str) -> str:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return ""
    return is_sbom(data) or sniff_format(data) or ""


class Handler(BaseHTTPRequestHandler):
    server_version = "PatchTriage"

    # ------------------------------------------------------------ helpers
    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send(self, body: bytes, ctype="text/html; charset=utf-8", status=200):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def log_message(self, *args):  # quiet by default
        pass

    # ------------------------------------------------------------ routing
    def _guard(self, fn):
        """Never drop the connection on an unhandled error — return JSON 500
        so the browser shows a message instead of a dead request."""
        try:
            fn()
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
        self._guard(self._do_POST)

    def do_DELETE(self):
        self._guard(self._do_DELETE)

    def _do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            return self._send(INDEX_HTML.encode("utf-8"))
        if path == "/api/config":
            has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
            backends = ["rules"] + (["claude", "cascade"] if has_key else [])
            return self._send_json({"backends": backends, "has_key": has_key})
        if path == "/api/targets":
            return self._send_json(tstore.load_targets())
        m = re.fullmatch(r"/report/([0-9a-f]+)", path)
        if m:
            rp = tstore.report_path(m.group(1))
            if rp.exists():
                return self._send(rp.read_bytes())
            return self._send(b"report not generated yet", status=404)
        return self._send(b"not found", status=404)

    def _do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/targets":
            body = self._read_json()
            if not body.get("name"):
                return self._send_json({"error": "name is required"}, 400)
            t = tstore.add_target(
                name=body["name"], url=body.get("url", ""),
                criticality=body.get("criticality", "unknown"),
                internet_exposed=bool(body.get("internet_exposed")))
            return self._send_json(t, 201)

        m = re.fullmatch(r"/api/targets/([0-9a-f]+)/source", path)
        if m:
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

        m = re.fullmatch(r"/api/targets/([0-9a-f]+)/run", path)
        if m:
            target = tstore.get_target(m.group(1))
            if not target:
                return self._send_json({"error": "no such target"}, 404)
            body = self._read_json()
            backend = body.get("backend", "rules")
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
        m = re.fullmatch(r"/api/targets/([0-9a-f]+)", self.path.split("?", 1)[0])
        if m:
            tstore.delete_target(m.group(1))
            self.send_response(204)
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
