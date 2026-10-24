"""Run `forge` inside a locked-down container. Requires a GateToken: no gate, no execution."""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import time
import uuid
from pathlib import Path

from redline.config import ROOT, Config
from redline.firewall.gate import GateToken
from redline.models import ForgeRun, TestResult

SHARED_LIB = ROOT / "fixtures" / "_lib" / "forge-std"
JOBS = ROOT / "jobs"


def make_workspace(repo: Path, name: str | None = None) -> Path:
    """Copy the repo into a fresh job workspace (never mutate the original)."""
    ws = JOBS / (name or f"{repo.name}-{uuid.uuid4().hex[:6]}") / "ws"
    if ws.exists():
        shutil.rmtree(ws)
    shutil.copytree(repo, ws, symlinks=False,
                    ignore=shutil.ignore_patterns("out", "cache", ".git", "node_modules"))
    lib = ws / "lib" / "forge-std"
    if not lib.exists() and SHARED_LIB.exists():
        lib.parent.mkdir(exist_ok=True)
        shutil.copytree(SHARED_LIB, lib)
    return ws


def _parse(stdout: str) -> list[TestResult]:
    out: list[TestResult] = []
    start = stdout.find("{")
    if start < 0:
        return out
    try:
        data = json.loads(stdout[start:])
    except json.JSONDecodeError:
        return out
    for suite, body in data.items():
        for name, r in body.get("test_results", {}).items():
            out.append(TestResult(name=f"{suite.split(':')[-1]}.{name}",
                                  passed=r.get("status") == "Success",
                                  reason=r.get("reason") or ""))
    return out


def run_forge(token: GateToken, workspace: Path, cfg: Config) -> ForgeRun:
    """Execute the already-gate-approved `forge ...` command in the sandbox."""
    argv = shlex.split(token.call.command)
    if token.call.kind != "shell" or argv[0] != "forge":
        raise PermissionError("run_forge only executes gate-approved forge commands")
    if argv[1] == "test" and "--json" not in argv:
        argv.append("--json")
    sb = cfg.sandbox
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--user", f"{os.getuid()}:{os.getgid()}", "--tmpfs", "/tmp:rw,size=256m,mode=1777",
        "--memory", sb.memory, "--cpus", sb.cpus, "--pids-limit", "256",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "-e", "FOUNDRY_FFI=false", "-e", "HOME=/tmp",
        "-v", f"{workspace}:/work:rw", "-w", "/work",
    ]
    if sb.solc_path:
        cmd += ["-v", f"{sb.solc_path}:/solc/solc:ro"]
    cmd += ["--entrypoint", "forge", sb.image, *argv[1:]]
    t0 = time.perf_counter()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=sb.timeout_s)
    except subprocess.TimeoutExpired as e:
        # container may outlive the client; best-effort cleanup is by --rm on exit
        return ForgeRun(ok=False, timed_out=True, stderr=f"timeout after {sb.timeout_s}s",
                        stdout=(e.stdout or b"")[-2000:].decode() if isinstance(e.stdout, bytes)
                        else (e.stdout or "")[-2000:], duration_s=time.perf_counter() - t0)
    cap = 200_000
    results = _parse(p.stdout) if argv[1] == "test" else []
    return ForgeRun(ok=p.returncode == 0 or bool(results), results=results,
                    stdout=p.stdout[-cap:], stderr=p.stderr[-cap:],
                    duration_s=time.perf_counter() - t0)
