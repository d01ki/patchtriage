"""End-to-end GUI API test against a live localhost server (no browser).

Exercises the full flow: add target -> attach SBOM -> run -> fetch report.
The SBOM run hits OSV.dev, so this test needs network; skip it offline.
"""

import json
import socket
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from patchtriage.webapp.server import Handler

FIX = Path(__file__).parent / "fixtures"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    port = _free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


def _req(method, url, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    request_headers = {"Content-Type": "application/json"}
    request_headers.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method,
                                 headers=request_headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_config_lists_rules_backend(server):
    status, cfg = _req("GET", server + "/api/config")
    assert status == 200
    assert cfg["backends"] == ["rules"]
    assert cfg["has_key"] is False
    assert "offline-demo" in cfg["capabilities"]


def test_add_and_delete_target(server):
    status, t = _req("POST", server + "/api/targets",
                     {"name": "checkout", "url": "https://example.com",
                      "criticality": "critical", "internet_exposed": True,
                      "reachable": True, "runtime_observed": True,
                      "context_sources": ["otel"]})
    assert status == 201
    assert t["name"] == "checkout" and t["url"] == "https://example.com"
    assert t["reachable"] is True and t["runtime_observed"] is True
    assert t["context_sources"] == ["otel"]
    _, targets = _req("GET", server + "/api/targets")
    assert len(targets) == 1
    status, _ = _req("DELETE", server + f"/api/targets/{t['id']}")
    assert status == 204
    _, targets = _req("GET", server + "/api/targets")
    assert targets == []


def test_rejects_unsafe_target_url(server):
    status, response = _req(
        "POST", server + "/api/targets",
        {"name": "unsafe", "url": "javascript:alert(1)"},
    )
    assert status == 400
    assert "http:// or https://" in response["error"]


def test_rejects_cross_origin_mutation(server):
    status, response = _req(
        "POST", server + "/api/targets", {"name": "cross-site"},
        headers={"Origin": "https://attacker.example"},
    )
    assert status == 403
    assert "cross-origin" in response["error"]


def test_security_headers_are_present(server):
    with urllib.request.urlopen(server + "/") as response:
        page = response.read().decode("utf-8")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert "Run the offline demo" in page
    assert "Patch what matters" in page


def test_reject_non_scan_non_sbom(server):
    _, t = _req("POST", server + "/api/targets", {"name": "x"})
    status, resp = _req("POST", server + f"/api/targets/{t['id']}/source",
                        {"content": '{"hello": "world"}', "filename": "x.json"})
    assert status == 400
    assert "unrecognized" in resp["error"]


def test_source_requires_existing_target(server):
    status, response = _req(
        "POST", server + "/api/targets/000000000000/source",
        {"content": '{"hello": "world"}', "filename": "x.json"},
    )
    assert status == 404
    assert response["error"] == "no such target"


def test_source_detects_sbom_format(server):
    _, t = _req("POST", server + "/api/targets", {"name": "x"})
    content = (FIX / "sbom_spdx.json").read_text(encoding="utf-8")
    status, resp = _req("POST", server + f"/api/targets/{t['id']}/source",
                        {"content": content, "filename": "sbom_spdx.json"})
    assert status == 200
    assert resp["format"] == "spdx"


def test_offline_arsenal_demo_runs_end_to_end(server):
    status, target = _req("POST", server + "/api/demo", {})
    assert status == 201
    assert target["demo"] is True
    status, summary = _req(
        "POST", server + f"/api/targets/{target['id']}/run",
        {"backend": "rules"},
    )
    assert status == 200
    assert summary["total"] == 3
    assert summary["kev"] == 1
    assert summary["comparison"]["kev"] == {
        "cvss": 0, "epss": 1, "patchtriage": 1,
    }
    assert summary["explanation"]["factors"]["runtime_observed"] is True
    assert summary["duration_ms"] >= 0
    status, same_target = _req("POST", server + "/api/demo", {})
    assert status == 200
    assert same_target["id"] == target["id"]
    _, targets = _req("GET", server + "/api/targets")
    assert len(targets) == 1


@pytest.mark.network
def test_full_run_over_sbom(server):
    """add -> attach SPDX -> run (OSV) -> report. Needs network."""
    _, t = _req("POST", server + "/api/targets",
                {"name": "demo", "url": "https://example.com",
                 "criticality": "high", "internet_exposed": True})
    content = (FIX / "sbom_spdx.json").read_text(encoding="utf-8")
    st, _ = _req("POST", server + f"/api/targets/{t['id']}/source",
                 {"content": content, "filename": "sbom_spdx.json"})
    assert st == 200
    try:
        st, summary = _req("POST", server + f"/api/targets/{t['id']}/run",
                           {"backend": "rules"})
    except urllib.error.URLError:
        pytest.skip("no network for OSV.dev")
    if st != 200:
        pytest.skip(f"OSV unreachable: {summary}")
    assert summary["total"] > 0
    assert summary["report_url"] == f"/report/{t['id']}"
    # report is now fetchable
    with urllib.request.urlopen(server + f"/report/{t['id']}") as r:
        html = r.read().decode()
    assert "<!doctype html>" in html
    assert "1E3A31" not in html  # no green in the redesigned palette
