"""PatchTriage CLI.

Quick start (reviewers: this needs NO network and NO API keys):

    patchtriage demo

Real usage:

    patchtriage run trivy.json grype.json --assets assets.yaml \
        --html report.html -o report.json --triage claude
"""

from __future__ import annotations

import json
import shutil
from importlib import resources
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

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


def _pipeline(files, fmt, asset_override, inventory_path, use_nvd, nvd_api_key,
              triage_backend, model, limit, escalation_model=None, jobs=4,
              batch=False):
    # Layer 1 — ingest
    raw = []
    for f in files:
        batch = load_file(f, fmt=fmt, asset=asset_override)
        console.print(f"[dim]ingested {len(batch):>5} findings from {f}[/dim]")
        raw += batch

    # Layer 2 — dedup
    findings = dedup(raw)
    console.print(f"[bold]{len(raw)} raw -> {len(findings)} deduplicated findings[/bold]")

    # Layer 4 — context (before triage so the AI sees it)
    if inventory_path:
        matched = apply_context(findings, load_inventory(inventory_path))
        console.print(f"[dim]asset context applied to {matched} findings "
                      f"from {inventory_path}[/dim]")

    # Layer 3 — enrich
    with console.status("enriching with EPSS / CISA KEV / NVD..."):
        enrich(findings, nvd_api_key=nvd_api_key, use_nvd=use_nvd)

    # Layer 5 — triage
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

    # Audit — every AI decision is machine-verified against its signals
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

    # Layer 6 — plan
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
    triage: str = typer.Option("rules", help="Triage backend: rules|claude|cascade"),
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
    override = None
    if asset_id or exposed or criticality != "unknown":
        override = Asset(identifier=asset_id or "override", kind="host",
                         criticality=criticality, internet_exposed=exposed)
    findings, subset, actions, eval_rows = _pipeline(
        files, fmt, override, assets, not no_nvd, nvd_api_key, triage, model,
        limit, escalation_model=escalation_model, jobs=jobs, batch=batch)
    _emit(findings, subset, actions, eval_rows, output, html)


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
