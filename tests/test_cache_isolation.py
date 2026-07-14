"""Regression: the enrichment cache dir is overridable and the demo must
never write its tiny bundled KEV/EPSS snapshot into the user's real cache.

Bug this guards against: running `patchtriage demo` seeded a 1-entry KEV
snapshot into ~/.cache/patchtriage/kev.json; because fetch_kev serves any
cache younger than 24h without refreshing, every real scan for the next day
then saw a KEV catalog of one CVE and reported 0 known-exploited findings.
"""

from pathlib import Path

from patchtriage.enrich import clients


def test_cache_dir_honors_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PATCHTRIAGE_CACHE_DIR", str(tmp_path / "iso"))
    assert clients.cache_dir() == tmp_path / "iso"
    # _cache_path creates and points into the overridden dir
    p = clients._cache_path("kev.json")
    assert p.parent == tmp_path / "iso"


def test_cache_dir_defaults_without_env(monkeypatch):
    monkeypatch.delenv("PATCHTRIAGE_CACHE_DIR", raising=False)
    assert clients.cache_dir() == clients._DEFAULT_CACHE_DIR


def test_demo_does_not_touch_real_cache(tmp_path, monkeypatch):
    """Run the offline demo and assert the real cache dir is never written."""
    from typer.testing import CliRunner

    from patchtriage.cli import app

    real_cache = tmp_path / "real_cache"
    monkeypatch.setattr(clients, "_DEFAULT_CACHE_DIR", real_cache)
    monkeypatch.delenv("PATCHTRIAGE_CACHE_DIR", raising=False)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(
        app, ["demo", "--html", "reports/d.html",
              "--output", "reports/d.json"])
    assert result.exit_code == 0, result.output
    assert Path("reports/d.json").exists()
    assert Path("reports/d.html").exists()
    # The demo ran fully offline against its isolated snapshot, so the real
    # cache dir must not have been created or populated.
    assert not real_cache.exists()
