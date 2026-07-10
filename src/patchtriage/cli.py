"""PatchTriage CLI.

Quick start (reviewers: this needs NO network and NO API keys):

    patchtriage demo

First-time interactive setup and guided run:

    patchtriage setup     # asks for API keys step by step, validates, saves
    patchtriage start     # asks what to triage, runs, opens the report

Scriptable usage:

    patchtriage run trivy.json grype.json --assets assets.yaml \
        --html report.html -o report.json --triage cascade
"""

from __future__ import annotations

import glob as globmod
import json
import os
import shutil
import sys
import webbrowser
from importlib import resources
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from . import config as cfgmod
from .context import apply_context, load_inventory
from .dedup import dedup
from .enrich.clients import CACHE_DIR, enrich
from .evalcmp import evaluate
from .ingest.parsers import load_file
from .models import Asset
from .plan import build_plan
from .report.html import render_html
from .triage.audit import audit_all
from .triage.engine import get_backend, run_triage, run_triage_batch

app = typer.Typer(add_completion=False, help="AI-assisted patch triage pipeline")
console = Console()


@app.callback()
def _load_config() -> None:
    """Export keys saved by `patchtriage setup` into the environment.

    Environment variables set by the user always take precedence.
    """
    # Never let a console that can't encode a character (e.g. cp932 on
    # Windows) crash a run: unencodable characters degrade to '?'.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except (OSError, ValueError):
                pass
    cfgmod.apply_to_env()


def _pipeline(files, fmt, asset_override, inventory_path, use_nvd, nvd_api_key,
              triage_backend, model, limit, escalation_model=None, jobs=4,
              batch=False):
    # Layer 1 - ingest
    raw = []
    for f in files:
        parsed = load_file(f, fmt=fmt, asset=asset_override)
        console.print(f"[dim]ingested {len(parsed):>5} findings from {f}[/dim]")
        raw += parsed

    # Layer 2 - dedup
    findings = dedup(raw)
    console.print(f"[bold]{len(raw)} raw -> {len(findings)} deduplicated findings[/bold]")

    # Layer 4 - context (before triage so the AI sees it)
    if inventory_path:
        matched = apply_context(findings, load_inventory(inventory_path))
        console.print(f"[dim]asset context applied to {matched} findings "
                      f"from {inventory_path}[/dim]")

    # Layer 3 - enrich
    with console.status("enriching with EPSS / CISA KEV / NVD..."):
        enrich(findings, nvd_api_key=nvd_api_key, use_nvd=use_nvd)

    # Layer 5 - triage
    subset = findings[:limit] if limit else findings
    if batch and triage_backend == "claude":
        run_triage_batch(subset, model or "claude-opus-4-8",
                         progress=lambda msg: console.print(f"[dim]{msg}[/dim]"))
    else:
        backend = get_backend(triage_backend, model, escalation_model)
        n_jobs = 1 if triage_backend == "rules" else max(1, jobs)
        with console.status(f"triaging {len(subset)} findings via "
                            f"'{triage_backend}' ({n_jobs} workers)..."):
            run_triage(subset, backend, jobs=n_jobs)
        if triage_backend == "cascade":
            esc = sum(1 for f in subset
                      if (f.triage or {}).get("escalated"))
            console.print(f"[dim]cascade: {esc}/{len(subset)} findings "
                          f"escalated to the frontier model[/dim]")
    fell_back = sum(1 for f in subset
                    if (f.triage or {}).get("backend") == "rules_fallback")
    if fell_back:
        console.print(f"[yellow]{fell_back} findings fell back to the rules "
                      f"baseline after API errors (tagged in the report)[/yellow]")

    # Audit - every AI decision is machine-verified against its signals
    summary = audit_all(subset)
    if summary["flagged"]:
        console.print(f"[yellow]audit: {summary['verified']}/{summary['total']} "
                      f"decisions verified; {len(summary['flagged'])} flagged "
                      f"for human review:[/yellow]")
        for vid, flags in summary["flagged"][:10]:
            console.print(f"  [yellow]FLAG {vid}: {', '.join(flags)}[/yellow]")
    else:
        console.print(f"[green]audit: {summary['verified']}/{summary['total']} "
                      f"decisions verified against deterministic signals[/green]")

    # Layer 6 - plan
    actions = build_plan(subset)
    # practicality evaluation
    eval_rows = evaluate(subset)
    return findings, subset, actions, eval_rows


def _emit(findings, subset, actions, eval_rows, output, html):
    _print_actions(actions)
    _print_eval(eval_rows)
    if html:
        Path(html).write_text(render_html(subset, actions, eval_rows),
                              encoding="utf-8")
        console.print(f"HTML report: [bold]{html}[/bold]")
    if output:
        report = {
            "findings": [f.model_dump(mode="json") for f in findings],
            "actions": [a.model_dump(mode="json") for a in actions],
            "evaluation": [r.model_dump(mode="json") for r in eval_rows],
        }
        Path(output).write_text(json.dumps(report, indent=2, default=str),
                                encoding="utf-8")
        console.print(f"JSON report: [bold]{output}[/bold]")


@app.command()
def run(
    files: list[Path] = typer.Argument(..., help="Scanner JSON outputs (Trivy/Grype/OSV)"),
    fmt: Optional[str] = typer.Option(None, help="Force format: trivy|grype|osv"),
    assets: Optional[Path] = typer.Option(None, help="Asset inventory YAML (Layer 4)"),
    asset_id: Optional[str] = typer.Option(None, help="Override asset identifier"),
    criticality: str = typer.Option("unknown", help="Asset criticality override"),
    exposed: bool = typer.Option(False, "--exposed", help="Asset is internet-exposed"),
    no_nvd: bool = typer.Option(False, help="Skip NVD (faster; EPSS/KEV only)"),
    nvd_api_key: Optional[str] = typer.Option(None, envvar="NVD_API_KEY"),
    triage: Optional[str] = typer.Option(
        None, help="Triage backend: rules|claude|cascade "
                   "(default: your `patchtriage setup` choice, else rules)"),
    model: Optional[str] = typer.Option(
        None, help="Model id (claude: triage model; cascade: screening model)"),
    escalation_model: Optional[str] = typer.Option(
        None, help="cascade only: frontier model for escalated findings"),
    jobs: int = typer.Option(4, help="Parallel API calls for claude/cascade"),
    batch: bool = typer.Option(
        False, "--batch",
        help="claude only: use the Message Batches API (50% cost, ~1h latency)"),
    output: Optional[Path] = typer.Option(None, "-o", help="Write full JSON report"),
    html: Optional[Path] = typer.Option(None, help="Write self-contained HTML dashboard"),
    limit: Optional[int] = typer.Option(None, help="Triage only top-N findings"),
):
    """Ingest -> dedup -> context -> enrich -> triage -> plan -> report."""
    triage = triage or cfgmod.load().get("default_backend") or "rules"
    override = None
    if asset_id or exposed or criticality != "unknown":
        override = Asset(identifier=asset_id or "override", kind="host",
                         criticality=criticality, internet_exposed=exposed)
    findings, subset, actions, eval_rows = _pipeline(
        files, fmt, override, assets, not no_nvd, nvd_api_key, triage, model,
        limit, escalation_model=escalation_model, jobs=jobs, batch=batch)
    _emit(findings, subset, actions, eval_rows, output, html)


@app.command()
def setup():
    """Interactive first-run wizard: enter API keys step by step, get them
    validated live, and save defaults to ~/.config/patchtriage/config.json.
    """
    cfg = cfgmod.load()
    console.print("\n[bold]PatchTriage setup[/bold] - press Enter to skip or "
                  "keep the current value.\n")
    # Hidden input requires a real terminal; piped/CI stdin would hang on
    # Windows' getpass, so fall back to visible input there.
    hidden = sys.stdin.isatty()

    # 1. Anthropic API key (enables the claude/cascade backends)
    current = cfg.get("ANTHROPIC_API_KEY", "")
    label = "Anthropic API key (sk-ant-...)"
    if current:
        label += f" [current: {cfgmod.mask(current)}]"
    while True:
        key = typer.prompt(label, default="", show_default=False,
                           hide_input=hidden).strip()
        if not key:
            key = current
            if not key:
                console.print("[dim]skipped - the deterministic 'rules' "
                              "backend needs no key[/dim]")
            break
        with console.status("validating key against the Anthropic API..."):
            ok, msg = cfgmod.validate_anthropic_key(key)
        if ok:
            console.print(f"[green]OK: {msg}[/green]")
            break
        console.print(f"[red]{msg}[/red]")
        if not typer.confirm("Try again?", default=True):
            key = current
            break
    if key:
        cfg["ANTHROPIC_API_KEY"] = key

    # 2. NVD API key (optional - only raises NVD rate limits)
    current_nvd = cfg.get("NVD_API_KEY", "")
    label = "NVD API key (optional, faster NVD enrichment)"
    if current_nvd:
        label += f" [current: {cfgmod.mask(current_nvd)}]"
    nvd = typer.prompt(label, default="", show_default=False,
                       hide_input=hidden).strip()
    if nvd:
        cfg["NVD_API_KEY"] = nvd

    # 3. Default triage backend
    has_key = bool(cfg.get("ANTHROPIC_API_KEY"))
    choices = ["rules", "claude", "cascade"] if has_key else ["rules"]
    default_backend = cfg.get("default_backend",
                              "cascade" if has_key else "rules")
    if has_key:
        while True:
            backend = typer.prompt(
                f"Default triage backend {choices} - cascade screens with a "
                f"fast model and escalates only what matters",
                default=default_backend).strip().lower()
            if backend in choices:
                break
            console.print(f"[red]pick one of {choices}[/red]")
    else:
        backend = "rules"
    cfg["default_backend"] = backend

    path = cfgmod.save(cfg)
    console.print(f"\n[green]Saved to {path}[/green] "
                  "(environment variables always take precedence)")
    console.print("\nNext steps:\n"
                  "  [bold]patchtriage demo[/bold]   offline demo, no keys needed\n"
                  "  [bold]patchtriage start[/bold]  guided run on your own scans\n")


@app.command()
def start():
    """Guided run: answer a few questions, get a prioritized patch plan."""
    if not cfgmod.config_path().exists():
        console.print("[yellow]No saved configuration found.[/yellow]")
        if typer.confirm("Run setup first?", default=True):
            setup()
    cfgmod.apply_to_env()
    cfg = cfgmod.load()

    # 1. what to triage
    console.print("\n[bold]1. Scanner output[/bold] - PatchTriage reads "
                  "Trivy / Grype / osv-scanner JSON.\n[dim]No scans yet? "
                  "e.g.  trivy image --format json -o trivy.json nginx:1.24[/dim]")
    while True:
        pattern = typer.prompt("Path or glob (e.g. scans/*.json)").strip()
        files = sorted(Path(p) for p in globmod.glob(pattern))
        if files:
            console.print(f"[dim]{len(files)} file(s): "
                          f"{', '.join(str(f) for f in files[:5])}"
                          f"{' ...' if len(files) > 5 else ''}[/dim]")
            break
        console.print(f"[red]no files match {pattern!r}[/red]")
        if os.name != "nt" and len(pattern) > 2 and pattern[1] == ":" \
                and pattern[2] in "\\/":
            console.print("[yellow]that looks like a Windows path, but this "
                          "is not a Windows machine - copy the file here "
                          "first (e.g. scp), or run patchtriage where the "
                          "file lives[/yellow]")

    # 2. environment context
    console.print("\n[bold]2. Asset context[/bold] - the same CVE on an "
                  "exposed checkout service and an internal batch box should "
                  "never rank the same.")
    assets_path = typer.prompt("assets.yaml inventory (Enter to skip)",
                               default="", show_default=False).strip()
    inventory = Path(assets_path) if assets_path else None
    override = None
    if inventory is None:
        exposed = typer.confirm("Are these assets internet-exposed?",
                                default=False)
        criticality = typer.prompt(
            "Business criticality [critical/high/medium/low/unknown]",
            default="unknown").strip().lower()
        if exposed or criticality != "unknown":
            override = Asset(identifier="interactive", kind="host",
                             criticality=criticality, internet_exposed=exposed)

    # 3. triage backend
    console.print("\n[bold]3. Triage backend[/bold]")
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    choices = ["rules", "claude", "cascade"] if has_key else ["rules"]
    if not has_key:
        console.print("[dim]no Anthropic key configured - run "
                      "`patchtriage setup` to enable claude/cascade[/dim]")
    default_backend = cfg.get("default_backend",
                              "cascade" if has_key else "rules")
    if default_backend not in choices:
        default_backend = choices[0]
    while True:
        backend = typer.prompt(f"Backend {choices}",
                               default=default_backend).strip().lower()
        if backend in choices:
            break
        console.print(f"[red]pick one of {choices}[/red]")

    use_nvd = typer.confirm(
        "Enrich with NVD (official CVSS/CWE - slower without an NVD key)?",
        default=bool(os.environ.get("NVD_API_KEY")))

    # 4. outputs
    console.print("\n[bold]4. Report[/bold]")
    html = typer.prompt("HTML report path", default="report.html").strip()
    output = typer.prompt("JSON report path", default="report.json").strip()

    try:
        findings, subset, actions, eval_rows = _pipeline(
            files, None, override, inventory, use_nvd,
            os.environ.get("NVD_API_KEY"), backend, None, None)
    except ValueError as exc:  # e.g. SBOM instead of a scan, unknown format
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    _emit(findings, subset, actions, eval_rows, Path(output), Path(html))

    if typer.confirm("Open the HTML report in your browser?", default=True):
        webbrowser.open(Path(html).resolve().as_uri())


@app.command()
def demo(
    html: Path = typer.Option(Path("demo_report.html"), help="HTML output path"),
    output: Path = typer.Option(Path("demo_report.json"), help="JSON output path"),
):
    """Fully offline demo: bundled scanner outputs + bundled EPSS/KEV/NVD snapshots.

    No network, no API keys. This is what reviewers should run first.
    """
    data = resources.files("patchtriage") / "data"
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    for src, dst in (("demo_epss.json", "epss.json"),
                     ("demo_kev.json", "kev.json"),
                     ("demo_nvd.json", "nvd.json")):
        target = CACHE_DIR / dst
        if not target.exists():
            target.write_text((data / src).read_text(encoding="utf-8"),
                              encoding="utf-8")
    console.print("[dim]seeded offline enrichment snapshot into "
                  f"{CACHE_DIR}[/dim]")

    fixtures = resources.files("patchtriage") / "data" / "fixtures"
    tmp = Path(".patchtriage_demo")
    tmp.mkdir(exist_ok=True)
    files = []
    for name in ("trivy_sample.json", "grype_sample.json"):
        p = tmp / name
        p.write_text((fixtures / name).read_text(encoding="utf-8"),
                     encoding="utf-8")
        files.append(p)
    assets_yaml = tmp / "assets.yaml"
    assets_yaml.write_text((data / "demo_assets.yaml").read_text(encoding="utf-8"),
                           encoding="utf-8")

    findings, subset, actions, eval_rows = _pipeline(
        files, None, None, assets_yaml, True, None, "rules", None, None)
    _emit(findings, subset, actions, eval_rows, output, html)
    shutil.rmtree(tmp, ignore_errors=True)
    console.print("\n[bold green]Demo complete.[/bold green] Open "
                  f"[bold]{html}[/bold] in a browser. To try the AI backend: "
                  "export ANTHROPIC_API_KEY=... and re-run with "
                  "`patchtriage run ... --triage claude`.")


def _print_actions(actions) -> None:
    table = Table(title="Remediation plan - highest risk reduced first")
    for col in ("#", "Pri", "Action", "CVEs", "KEV", "Due", "Risk cut"):
        table.add_column(col)
    for i, a in enumerate(actions[:15], 1):
        style = {"P1": "bold red", "P2": "yellow"}.get(a.top_priority, "")
        pri = f"[{style}]{a.top_priority}[/{style}]" if style else a.top_priority
        table.add_row(str(i), pri, a.summary[:60], str(len(a.cves)),
                      str(a.kev_count) if a.kev_count else "-",
                      f"{a.deadline_days}d", f"{a.risk_reduced:.2f}")
    console.print(table)


def _print_eval(rows) -> None:
    table = Table(title="Practicality check: CVSS-order vs PatchTriage-order")
    for col in ("Budget", "KEV@k CVSS", "KEV@k PT", "EPSS@k CVSS", "EPSS@k PT"):
        table.add_column(col)
    for r in rows:
        pt_kev = f"[bold green]{r.kev_patchtriage}/{r.kev_total}[/bold green]" \
            if r.kev_patchtriage >= r.kev_baseline else f"{r.kev_patchtriage}/{r.kev_total}"
        table.add_row(f"top {r.k}", f"{r.kev_baseline}/{r.kev_total}", pt_kev,
                      str(r.epss_baseline), str(r.epss_patchtriage))
    console.print(table)


if __name__ == "__main__":
    app()
