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
    """List Nemotron models on Token Factory and test-complete with main + firewall models."""
    from redline.llm import LLM

    cfg = load_config()
    require_env("NEBIUS_API_KEY")
    llm = LLM(cfg)
    ids = sorted(m.id for m in llm.client.models.list().data)
    nemo = [i for i in ids if "nemotron" in i.lower()]
    t = Table("Nemotron models available")
    for i in nemo:
        t.add_row(i)
    con.print(t)
    con.print(f"[dim]{len(ids)} models total[/dim]")
    for role, mid in (("main", cfg.models.main), ("firewall", cfg.models.firewall)):
        if mid not in ids:
            con.print(f"[red]{role}: {mid} NOT FOUND[/red] - fix config.toml")
            continue
        out = llm.chat(mid, [{"role": "user", "content": "Reply with the single word: ready"}],
                       role=role, max_tokens=64)
        s = llm.stats[-1]
        con.print(f"[green]{role}[/green] {mid}: {out.strip()[:40]!r} "
                  f"({s.prompt_tokens}+{s.completion_tokens} tok, {s.latency_s:.1f}s)")


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
def audit(repo: Path):
    """Full audit loop (M2+)."""
    raise typer.Exit("audit loop lands in M2")


if __name__ == "__main__":
    app()
