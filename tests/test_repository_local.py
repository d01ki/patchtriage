"""Local generic repository scanner safety and provenance tests."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import patchtriage.repository_local as local
from patchtriage.repository import RepositoryFetchError, RepositoryTooLargeError


def test_public_address_check_rejects_private_resolution(monkeypatch):
    monkeypatch.setattr(
        local.socket, "getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("127.0.0.1", 443))],
    )
    with pytest.raises(RepositoryFetchError, match="non-public"):
        local._public_addresses("example.test")


def test_public_address_check_requires_every_answer_to_be_global(monkeypatch):
    monkeypatch.setattr(
        local.socket, "getaddrinfo",
        lambda *args, **kwargs: [
            (None, None, None, None, ("93.184.216.34", 443)),
            (None, None, None, None, ("10.0.0.4", 443)),
        ],
    )
    with pytest.raises(RepositoryFetchError, match="10.0.0.4"):
        local._public_addresses("mixed.example")


def test_local_scan_uses_static_tools_and_records_commit(monkeypatch):
    monkeypatch.setattr(local, "_public_addresses", lambda *args: ["93.184.216.34"])
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if "clone" in command:
            checkout = Path(command[-1])
            checkout.mkdir()
            (checkout / "package-lock.json").write_text("{}", encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "rev-parse" in command:
            return SimpleNamespace(returncode=0, stdout="a" * 40 + "\n", stderr="")
        output = Path(command[command.index("--output-file") + 1])
        output.write_text(json.dumps({
            "results": [{
                "source": {"path": "package-lock.json", "type": "lockfile"},
                "packages": [{
                    "package": {"name": "lodash", "version": "4.17.20",
                                "ecosystem": "npm"},
                    "vulnerabilities": [],
                }],
            }],
        }), encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(local, "_run_monitored", fake_run)
    monkeypatch.setattr(local.subprocess, "run", fake_run)
    result = local.scan_public_repository(
        "https://gitlab.example/acme/widgets.git",
        git_binary="git", scanner_binary="osv-scanner",
    )
    assert result.format == "osv"
    assert result.provenance["coverage_status"] == "complete"
    assert result.provenance["resolved_commit"] == "a" * 40
    assert result.provenance["manifests_detected"] == ["package-lock.json"]
    assert result.provenance["scanner_config"] == "trusted-empty-config"
    clone = calls[0]
    assert "--no-recurse-submodules" in clone
    assert "protocol.allow=never" in clone
    scanner = calls[1]
    assert scanner[:3] == ["osv-scanner", "scan", "source"]
    assert "--config" in scanner
    assert "trusted-osv-scanner.toml" in scanner[
        scanner.index("--config") + 1]
    assert "--no-resolve" in scanner
    assert "--all-packages" in scanner


def test_local_scan_does_not_call_result_clean_without_manifest(monkeypatch):
    monkeypatch.setattr(local, "_public_addresses", lambda *args: ["93.184.216.34"])

    def fake_run(command, **kwargs):
        if "clone" in command:
            checkout = Path(command[-1])
            checkout.mkdir()
            (checkout / "README.md").write_text("hello", encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "rev-parse" in command:
            return SimpleNamespace(returncode=0, stdout="b" * 40, stderr="")
        output = Path(command[command.index("--output-file") + 1])
        output.write_text('{"results": []}', encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(local, "_run_monitored", fake_run)
    monkeypatch.setattr(local.subprocess, "run", fake_run)
    result = local.scan_public_repository(
        "https://codeberg.org/acme/widgets.git",
        git_binary="git", scanner_binary="osv-scanner",
    )
    assert result.provenance["coverage_status"] == "no_supported_manifest"
    assert result.provenance["coverage"]["complete"] is False
    assert "zero findings" in result.provenance["warnings"][0]


def test_local_scan_accepts_osv_no_packages_exit_code(monkeypatch):
    monkeypatch.setattr(local, "_public_addresses", lambda *args: ["93.184.216.34"])

    def fake_run(command, **kwargs):
        if "clone" in command:
            checkout = Path(command[-1])
            checkout.mkdir()
            (checkout / "README.md").write_text("empty", encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "rev-parse" in command:
            return SimpleNamespace(returncode=0, stdout="deadbeef\n", stderr="")
        return SimpleNamespace(returncode=128, stdout="",
                               stderr="no packages found")

    monkeypatch.setattr(local, "_run_monitored", fake_run)
    monkeypatch.setattr(local.subprocess, "run", fake_run)
    result = local.scan_public_repository(
        "https://git.example.com/acme/empty.git",
        git_binary="git", scanner_binary="osv-scanner",
    )
    assert json.loads(result.content) == {"results": []}
    assert result.provenance["coverage_status"] == "no_supported_manifest"
    assert result.provenance["coverage"]["complete"] is False


def test_local_scan_rejects_output_before_reading_it_wholesale(monkeypatch):
    monkeypatch.setattr(local, "_public_addresses", lambda *args: ["93.184.216.34"])

    def fake_run(command, **kwargs):
        if "clone" in command:
            checkout = Path(command[-1])
            checkout.mkdir()
            (checkout / "package-lock.json").write_text("{}", encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "rev-parse" in command:
            return SimpleNamespace(returncode=0, stdout="c" * 40, stderr="")
        output = Path(command[command.index("--output-file") + 1])
        output.write_text("x" * 32, encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(local, "_run_monitored", fake_run)
    monkeypatch.setattr(local.subprocess, "run", fake_run)
    with pytest.raises(RepositoryTooLargeError, match="output exceeds"):
        local.scan_public_repository(
            "https://git.example.com/acme/large.git",
            git_binary="git", scanner_binary="osv-scanner",
            max_output_bytes=16,
        )


def test_monitored_process_is_stopped_when_tree_grows_past_limit(
        tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "pack").write_bytes(b"x" * 17)

    class FakeProcess:
        returncode = None
        terminated = False

        def poll(self):
            return self.returncode

        def terminate(self):
            self.terminated = True
            self.returncode = -15

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = -9

    process = FakeProcess()
    monkeypatch.setattr(local.subprocess, "Popen", lambda *args, **kwargs: process)
    with pytest.raises(RepositoryTooLargeError, match="repository clone exceeds"):
        local._run_monitored(
            ["git", "clone"], env={}, timeout=10,
            monitor_path=checkout, max_bytes=16, max_files=10,
            label="repository clone",
        )
    assert process.terminated is True


def test_process_tree_termination_uses_platform_tree_primitive(monkeypatch):
    calls = []

    class FakeProcess:
        pid = 12345

        def wait(self, timeout=None):
            return 0

        def terminate(self):
            calls.append("direct-terminate")

        def kill(self):
            calls.append("direct-kill")

    if local.os.name == "nt":
        monkeypatch.setattr(
            local.subprocess, "run",
            lambda command, **kwargs: (
                calls.append(command) or SimpleNamespace(returncode=0)),
        )
    else:
        monkeypatch.setattr(
            local.os, "killpg",
            lambda pid, sig: calls.append((pid, sig)),
        )
    local._stop_process(FakeProcess())
    if local.os.name == "nt":
        assert "/T" in calls[0]
        assert "/F" in calls[0]
    else:
        assert calls == [
            (12345, local.signal.SIGTERM),
            (12345, local.signal.SIGKILL),
        ]


def test_local_scan_requires_explicit_results_list(monkeypatch):
    monkeypatch.setattr(local, "_public_addresses", lambda *args: ["93.184.216.34"])

    def fake_run(command, **kwargs):
        if "clone" in command:
            checkout = Path(command[-1])
            checkout.mkdir()
            (checkout / "package-lock.json").write_text("{}", encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "rev-parse" in command:
            return SimpleNamespace(returncode=0, stdout="d" * 40, stderr="")
        output = Path(command[command.index("--output-file") + 1])
        output.write_text("{}", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(local, "_run_monitored", fake_run)
    monkeypatch.setattr(local.subprocess, "run", fake_run)
    with pytest.raises(RepositoryFetchError, match="results list"):
        local.scan_public_repository(
            "https://git.example.com/acme/malformed.git",
            git_binary="git", scanner_binary="osv-scanner",
        )


def test_manifest_without_package_inventory_is_not_complete(monkeypatch):
    monkeypatch.setattr(local, "_public_addresses", lambda *args: ["93.184.216.34"])

    def fake_run(command, **kwargs):
        if "clone" in command:
            checkout = Path(command[-1])
            checkout.mkdir()
            (checkout / "package-lock.json").write_text("{}", encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "rev-parse" in command:
            return SimpleNamespace(returncode=0, stdout="e" * 40, stderr="")
        output = Path(command[command.index("--output-file") + 1])
        output.write_text('{"results": []}', encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(local, "_run_monitored", fake_run)
    monkeypatch.setattr(local.subprocess, "run", fake_run)
    result = local.scan_public_repository(
        "https://git.example.com/acme/empty-lockfile.git",
        git_binary="git", scanner_binary="osv-scanner",
    )
    assert result.provenance["coverage_status"] == "no_package_inventory"
    assert result.provenance["coverage"]["complete"] is False
