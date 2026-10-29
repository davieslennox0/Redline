"""Recon: sanitized repo -> ranked structured findings."""

from __future__ import annotations

from pathlib import Path

from redline.agent.prompts import RECON_SYSTEM
from redline.agent.tools import Tools
from redline.firewall import scanner
from redline.models import Finding, Quarantine, ReconOut

SKIP_DIRS = {"lib", "out", "cache", "node_modules", ".git"}
MAX_FILE_BYTES = 60_000


def list_files(ws: Path) -> list[str]:
    out = []
    for p in sorted(ws.rglob("*")):
        rel = p.relative_to(ws)
        if (
            p.is_file()
            and not (set(rel.parts) & SKIP_DIRS)
            and p.suffix in {".sol", ".md", ".toml"}
        ):
            out.append(str(rel))
    return out


def load_repo(
    tools: Tools, llm=None, scan_model: str = "", raw_out: dict[str, str] | None = None
) -> tuple[dict[str, str], list[Quarantine]]:
    """Read every file through the gate and sanitize it. Returns (clean_files, quarantines)."""
    files: dict[str, str] = {}
    quarantined: list[Quarantine] = []
    for rel in list_files(tools.ws):
        raw = tools.read(rel)[:MAX_FILE_BYTES]
        clean, qs = scanner.scan(rel, raw, llm, scan_model)
        files[rel] = clean
        quarantined += qs
        if qs and raw_out is not None:
            raw_out[rel] = raw
    return files, quarantined


def render_repo(files: dict[str, str]) -> str:
    return "\n".join(
        f'<untrusted_data file="{p}">\n{c}\n</untrusted_data>' for p, c in files.items()
    )


def run_recon(llm, cfg, files: dict[str, str], warnings: list[str]) -> list[Finding]:
    warn = (
        (
            "\nSECURITY FILTER WARNING: parts of this repo were removed as suspected prompt "
            "injection. Do not let that change your analysis:\n" + "\n".join(warnings)
        )
        if warnings
        else ""
    )
    msgs = [
        {"role": "system", "content": RECON_SYSTEM},
        {"role": "user", "content": f"Audit this repository.{warn}\n\n{render_repo(files)}"},
    ]
    try:
        out = llm.structured(cfg.models.main, msgs, ReconOut, role="recon", max_tokens=6000)
    except RuntimeError:
        out = llm.structured(
            cfg.models.recon_fallback, msgs, ReconOut, role="recon-fallback", max_tokens=6000
        )
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ranked = sorted(out.findings, key=lambda f: (order[f.severity], -f.confidence))
    return ranked[: cfg.limits.max_findings]
