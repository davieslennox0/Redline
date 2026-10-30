"""Web-triggered audits: validate a public GitHub URL, shallow-clone it, run the normal audit.

The clone happens in server code (not an agent tool call); everything the agent does with the
cloned repo afterwards still goes through the firewall gate and the offline sandbox.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from redline.config import ROOT

URL_RE = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100}?)(?:\.git)?/?$"
)
CLONES = ROOT / "jobs" / "_clones"
MAX_BYTES = 40 * 1024 * 1024
CLONE_TIMEOUT_S = 150

_pool = ThreadPoolExecutor(max_workers=1)  # one audit at a time: single sandbox CPU, one API key
_lock = threading.Lock()
_hits: dict[str, list[float]] = {}  # client ip -> start times of audits in the window
WINDOW_S = 12 * 3600
_busy: set[str] = set()


class AuditRejected(Exception):
    def __init__(self, msg: str, status: int = 422):
        super().__init__(msg)
        self.status = status


def parse_url(url: str) -> tuple[str, str]:
    m = URL_RE.match(url.strip())
    if not m:
        raise AuditRejected("Only public https://github.com/<owner>/<repo> URLs are supported.")
    return m.group(1), m.group(2)


def _dir_size(p: Path) -> int:
    return sum(f.stat().st_size for f in p.rglob("*") if f.is_file() and not f.is_symlink())


def _clone(owner: str, repo: str) -> Path:
    dest = CLONES / f"{repo}-{uuid.uuid4().hex[:6]}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true"}
    for k in ("NVIDIA_API_KEY", "NEBIUS_API_KEY", "TAVILY_API_KEY"):
        env.pop(k, None)  # the clone subprocess never needs the model/search keys
    cmd = [
        "git",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "clone",
        "--depth",
        "1",
        "--recurse-submodules",
        "--shallow-submodules",
        f"https://github.com/{owner}/{repo}.git",
        str(dest),
    ]
    try:
        r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=CLONE_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        shutil.rmtree(dest, ignore_errors=True)
        raise AuditRejected("Clone timed out; the repo is too large or slow.") from None
    if r.returncode != 0:
        shutil.rmtree(dest, ignore_errors=True)
        raise AuditRejected("Could not clone that repository (is it public?).")
    if _dir_size(dest) > MAX_BYTES:
        shutil.rmtree(dest, ignore_errors=True)
        raise AuditRejected(f"Repository is over the {MAX_BYTES // 2**20} MB limit.")
    if not (dest / "foundry.toml").exists() or not any((dest / "src").rglob("*.sol")):
        shutil.rmtree(dest, ignore_errors=True)
        raise AuditRejected("Not a Foundry project: need foundry.toml and Solidity files in src/.")
    return dest


def pin_offline_solc(repo: Path) -> None:
    """The sandbox has no network, so point forge at the host solc mounted at /solc/solc."""
    f = repo / "foundry.toml"
    lines = [
        ln
        for ln in f.read_text().splitlines()
        if not re.match(r"\s*(solc|solc_version|auto_detect_solc|offline)\s*=", ln)
    ]
    pin = ['solc = "/solc/solc"', "auto_detect_solc = false"]
    if "[profile.default]" in lines:
        i = lines.index("[profile.default]")
        lines[i + 1 : i + 1] = pin
    else:
        lines = ["[profile.default]", *pin, *lines]
    f.write_text("\n".join(lines) + "\n")


def submit(url: str, run_audit, ip: str = "unknown") -> str:
    """Validate, rate-limit per client IP, clone, queue. Returns the run id."""
    if os.environ.get("REDLINE_WEB_AUDIT", "1") == "0":
        raise AuditRejected("Web audits are disabled on this server.", 403)
    owner, repo = parse_url(url)
    cap = int(os.environ.get("REDLINE_WEB_AUDITS_PER_IP", "6"))
    key = f"{owner}/{repo}".lower()
    with _lock:
        now = time.time()
        mine = _hits[ip] = [t for t in _hits.get(ip, []) if now - t < WINDOW_S]
        if len(mine) >= cap:
            wait_h = (mine[0] + WINDOW_S - now) / 3600
            raise AuditRejected(
                f"Limit of {cap} audits per 12 hours per IP reached; try again in {wait_h:.1f} h.",
                429,
            )
        if _busy:
            raise AuditRejected("An audit is already running; try again when it finishes.", 429)
        _busy.add(key)
        mine.append(now)
    try:
        path = _clone(owner, repo)
        pin_offline_solc(path)
    except Exception:
        with _lock:
            _busy.discard(key)
        raise
    run_name = f"web-{repo}-{uuid.uuid4().hex[:6]}"

    def job():
        try:
            # the orchestrator already wrote run_finished(ok=false) with the error
            with contextlib.suppress(Exception):
                run_audit(path, run_name)
        finally:
            shutil.rmtree(path, ignore_errors=True)
            with _lock:
                _busy.discard(key)

    _pool.submit(job)
    return run_name
