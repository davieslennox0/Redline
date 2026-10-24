"""Redline CLI."""
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from redline.config import load_config, require_env
from redline.firewall.gate import Gate, GateDenied
from redline.firewall.log import FirewallLog
from redline.models import ToolCall
from redline.sandbox import docker_runner

app = typer.Typer(no_args_is_help=True, help="Redline: prove smart-contract bugs by executing them.")
con = Console()


@app.command()
def models():
    """List Nemotron models for the active provider; test main + firewall models."""
    import os

    from pydantic import BaseModel

    from redline.llm import LLM

    class Ping(BaseModel):
        status: str
        n: int

    cfg = load_config()
    p = cfg.provider
    con.print(f"provider: [bold]{cfg.active_provider}[/bold] ({p.base_url})")
    if not os.environ.get(p.key_env):
        con.print(f"[yellow]{p.key_env} not set[/yellow]: listing models only (unauthenticated)")
        import httpx

        ids = sorted(m["id"] for m in httpx.get(p.base_url + "/models", timeout=30).json()["data"])
    else:
        llm = LLM(cfg)
        ids = sorted(m.id for m in llm.client.models.list().data)
    t = Table("Nemotron models available")
    for i in (i for i in ids if "nemotron" in i.lower()):
        t.add_row(i)
    con.print(t)
    con.print(f"[dim]{len(ids)} models total[/dim]")
    if not os.environ.get(p.key_env):
        raise typer.Exit(1)
    for role, mid in (("main", cfg.models.main), ("firewall", cfg.models.firewall)):
        if mid not in ids:
            con.print(f"[red]{role}: {mid} NOT FOUND[/red] - fix config.toml")
            continue
        try:
            llm.chat(mid, [{"role": "user", "content": "Reply with the single word: ready"}],
                     role=role, max_tokens=64)
            s = llm.stats[-1]
            msg = f"[green]{role}[/green] {mid}: ok ({s.latency_s:.1f}s, {s.provider})"
            try:
                llm.structured(mid, [{"role": "user", "content":
                               'Reply with ONLY this JSON: {"status": "ok", "n": 1}'}], Ping,
                               role=role + "-json", max_tokens=128)
                msg += f"; JSON ok ({llm.stats[-1].latency_s:.1f}s)"
            except Exception as e:
                msg += f"; [red]JSON FAILED[/red] {str(e)[:80]}"
            con.print(msg)
        except Exception as e:
            con.print(f"[red]{role} {mid} call failed:[/red] {str(e)[:200]}")


@app.command()
def preflight():
    """Submission guard: fails unless the active provider is Nebius Token Factory."""
    cfg = load_config()
    if cfg.active_provider != "nebius":
        con.print(f"[bold red]PREFLIGHT FAILED[/bold red]: active_provider={cfg.active_provider!r}. "
                  "The hackathon requires the final run on Nebius Token Factory. "
                  "Set active_provider = \"nebius\" in config.toml (and REDLINE_PROVIDER unset).")
        raise typer.Exit(1)
    require_env(cfg.provider.key_env)
    con.print("[green]preflight ok[/green]: provider=nebius")


@app.command("sandbox-test")
def sandbox_test(repo: Path):
    """Run `forge test` for a repo inside the sandbox (via the firewall gate)."""
    cfg = load_config()
    ws = docker_runner.make_workspace(repo.resolve())
    gate = Gate(ws, FirewallLog(ws.parent / "firewall.jsonl"))
    call = ToolCall(kind="shell", command="forge test", purpose="run test suite")
    try:
        run = gate.run(call, lambda tok: docker_runner.run_forge(tok, ws, cfg))
    except GateDenied as e:
        con.print(f"[red]DENIED[/red] {e}")
        raise typer.Exit(2)
    t = Table("test", "result", "reason")
    for r in run.results:
        t.add_row(r.name, "[green]pass[/green]" if r.passed else "[red]FAIL[/red]", r.reason)
    con.print(t)
    if not run.ok:
        con.print(run.stderr[-1500:] or run.stdout[-1500:])
    con.print(f"{len(run.results)} tests, {run.duration_s:.1f}s")
    raise typer.Exit(0 if run.all_passed else 1)


@app.command("firewall-test")
def firewall_test(command: str = typer.Argument(..., help="shell command to evaluate")):
    """Evaluate a single shell command against Layer 1."""
    gate = Gate(Path.cwd())
    d = gate.check(ToolCall(kind="shell", command=command))
    color = "green" if d.verdict == "allow" else "red"
    con.print(f"[{color}]{d.verdict.upper()}[/{color}] {d.layer}:{d.rule} - {d.reason}")


@app.command()
def audit(repo: Path, no_patch: bool = False, no_research: bool = False):
    """Audit a Foundry repo end to end."""
    from redline.agent import orchestrator
    from redline.llm import LLM

    cfg = load_config()
    llm = LLM(cfg)
    con.print(f"provider: [bold]{cfg.active_provider}[/bold]")
    res = orchestrator.audit(repo, cfg, llm, log=con.print, do_patch=not no_patch,
                             do_research=not no_research)
    t = Table("id", "sev", "status", "patch", "title")
    for f in res.findings:
        pt = "-" if not f.patch else ("[green]fixed[/green]" if f.patch.applied else "[red]no[/red]")
        t.add_row(f.finding.id, f.finding.severity, f.status, pt, f.finding.title)
    con.print(t)
    con.print(f"quarantined spans: {len(res.quarantined)}; firewall denials: "
              f"{sum(e['verdict'] == 'deny' for e in res.firewall_log)}; "
              f"tokens: {sum(c['prompt_tokens'] + c['completion_tokens'] for c in res.calls)}")
    con.print(f"report: {res.out_dir}/report.json")


if __name__ == "__main__":
    app()
