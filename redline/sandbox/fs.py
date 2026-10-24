"""Workspace file I/O. Requires a GateToken, like the sandbox runner."""
from __future__ import annotations

from pathlib import Path

from redline.firewall.gate import GateToken


def write_file(token: GateToken, ws: Path) -> Path:
    c = token.call
    if c.kind != "write":
        raise PermissionError("write_file needs a gate-approved write call")
    target = (ws / c.path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(c.content)
    return target


def read_file(token: GateToken, ws: Path) -> str:
    c = token.call
    if c.kind != "read":
        raise PermissionError("read_file needs a gate-approved read call")
    return (ws / c.path).resolve().read_text(errors="replace")
