"""Layer 1: deterministic, unbypassable policy. No model involved.

Deny wins. Anything not explicitly allowed is denied.
"""
from __future__ import annotations

import re
import shlex
import time
from pathlib import Path
from urllib.parse import urlparse

from redline.models import FirewallDecision, ToolCall

MAX_WRITE_BYTES = 100_000
NET_ALLOW_HOSTS = {"api.tavily.com", "api.tokenfactory.nebius.com"}
WRITE_ALLOW_DIRS = ("src", "test")  # relative to workspace
WRITE_ALLOW_SUFFIX = (".sol",)

FORGE_SUBCMDS = {"build", "test", "fmt", "inspect", "snapshot"}
FORGE_DENY_FLAGS = {"--ffi", "--fork-url", "--rpc-url", "--broadcast", "--private-key",
                    "--mnemonic", "--keystore", "--ledger", "--trezor", "--etherscan-api-key"}
GIT_RO_SUBCMDS = {"status", "log", "diff", "show", "ls-files", "rev-parse", "blame"}
READ_CMDS = {"cat", "ls", "head", "tail", "wc", "grep"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3", "node", "perl", "ruby"}
SHELL_META = re.compile(r"[|;&`<>\n]|\$\(|\$\{")
SENSITIVE = re.compile(
    r"(^|[\s/=])(\.env[^/]*|id_rsa[^/]*|id_ed25519[^/]*|.*\.pem|.*\.key|\.ssh|\.aws|\.netrc|"
    r"\.npmrc|\.git-credentials|keystores?|credentials[^/]*|secrets?[^/]*)($|/)"
    r"|/proc/[^/]+/environ|/etc/(passwd|shadow)",
    re.I,
)
ENV_DUMP = re.compile(r"(^|\s)(env|printenv|export|set)(\s|$)")


def _d(verdict: str, rule: str, reason: str, t0: float, needs_l2: bool = False) -> FirewallDecision:
    return FirewallDecision(verdict=verdict, layer="L1", rule=rule, reason=reason,
                            latency_ms=(time.perf_counter() - t0) * 1000, needs_l2=needs_l2)


def _inside(workspace: Path, p: str) -> Path | None:
    """Resolve p (relative paths are workspace-relative) and return it iff inside workspace."""
    ws = workspace.resolve()
    cand = Path(p)
    cand = cand if cand.is_absolute() else ws / cand
    try:
        r = cand.resolve()  # follows symlinks: a link pointing outside is rejected
    except OSError:
        return None
    return r if r == ws or ws in r.parents else None


def evaluate(call: ToolCall, workspace: Path) -> FirewallDecision:
    t0 = time.perf_counter()
    if call.kind == "shell":
        return _shell(call, workspace, t0)
    if call.kind == "write":
        return _write(call, workspace, t0)
    if call.kind == "read":
        return _read(call, workspace, t0)
    if call.kind == "net":
        return _net(call, t0)
    return _d("deny", "unknown-kind", f"unknown tool kind {call.kind!r}", t0)


def _shell(call: ToolCall, ws: Path, t0: float) -> FirewallDecision:
    cmd = call.command.strip()
    if not cmd:
        return _d("deny", "empty-command", "empty command", t0)
    if "|" in cmd and re.search(r"\|\s*(sudo\s+)?(\S*/)?(" + "|".join(SHELLS) + r")\b", cmd):
        return _d("deny", "pipe-to-shell", "piping into a shell/interpreter is forbidden", t0)
    if SHELL_META.search(cmd):
        return _d("deny", "shell-metachar",
                  "pipes, redirects, chaining and substitution are not allowed", t0)
    try:
        argv = shlex.split(cmd)
    except ValueError as e:
        return _d("deny", "unparseable", f"cannot parse command: {e}", t0)
    prog = Path(argv[0]).name
    if prog in {"curl", "wget", "nc", "ncat", "ssh", "scp", "ftp", "telnet", "socat"}:
        return _d("deny", "network-tool", f"{prog} is a network tool; sandbox has no network", t0)
    if prog in SHELLS or prog in {"sudo", "su", "eval", "exec", "xargs", "env", "printenv"}:
        return _d("deny", "no-interpreter", f"{prog} is not allowed", t0)
    if ENV_DUMP.search(cmd):
        return _d("deny", "env-read", "reading the environment is forbidden", t0)
    if SENSITIVE.search(cmd):
        return _d("deny", "sensitive-path", "command references a credential/secret path", t0)

    if prog == "forge":
        if len(argv) < 2 or argv[1] not in FORGE_SUBCMDS:
            return _d("deny", "forge-subcmd", f"forge subcommand not allowed: {argv[1:2]}", t0)
        for a in argv[2:]:
            if a.split("=")[0] in FORGE_DENY_FLAGS:
                return _d("deny", "forge-flag", f"forge flag not allowed: {a}", t0)
        return _check_paths(argv[2:], ws, t0, "forge")
    if prog == "git":
        if len(argv) < 2 or argv[1] not in GIT_RO_SUBCMDS:
            return _d("deny", "git-readonly", "only read-only git subcommands are allowed", t0)
        return _check_paths(argv[2:], ws, t0, "git")
    if prog in READ_CMDS:
        return _check_paths(argv[1:], ws, t0, prog)
    return _d("deny", "not-allowlisted", f"{prog!r} is not on the command allowlist", t0)


def _check_paths(args: list[str], ws: Path, t0: float, prog: str) -> FirewallDecision:
    for a in args:
        if a.startswith("-") and "=" not in a:
            continue
        val = a.split("=", 1)[1] if a.startswith("-") else a
        if not val or not ("/" in val or val.startswith((".", "~"))):
            continue
        if "://" in val:
            return _d("deny", "url-arg", f"URL argument not allowed: {val}", t0)
        if val.startswith("~") or _inside(ws, val) is None:
            return _d("deny", "path-jail", f"path escapes the workspace: {val}", t0)
    # routine = a plain forge build/test or read; anything else gets a second opinion
    routine = prog in {"forge", "cat", "ls", "head", "tail", "wc", "grep"}
    return _d("allow", "allowlist", f"{prog} allowed", t0, needs_l2=not routine)


def _write(call: ToolCall, ws: Path, t0: float) -> FirewallDecision:
    if SENSITIVE.search(call.path):
        return _d("deny", "sensitive-path", "write to a credential/secret path", t0)
    target = _inside(ws, call.path)
    if target is None:
        return _d("deny", "path-jail", f"write outside workspace: {call.path}", t0)
    rel = target.relative_to(ws.resolve())
    if not rel.parts or rel.parts[0] not in WRITE_ALLOW_DIRS:
        return _d("deny", "write-dir", f"writes limited to {WRITE_ALLOW_DIRS}, got {rel}", t0)
    if target.suffix not in WRITE_ALLOW_SUFFIX:
        return _d("deny", "write-suffix", f"only {WRITE_ALLOW_SUFFIX} files may be written", t0)
    if len(call.content.encode()) > MAX_WRITE_BYTES:
        return _d("deny", "write-size", f"content exceeds {MAX_WRITE_BYTES} bytes", t0)
    if re.search(r"vm\.ffi|vm\.(readFile|writeFile|removeFile|setEnv|envString|envBytes32"
                 r"|projectRoot|createFork|rpcUrl)|vm\.readLine|vm\.closeFile", call.content):
        return _d("deny", "cheatcode", "cheatcode that touches host/network is forbidden", t0)
    # src/ edits are patches (higher stakes) -> second opinion; test/ PoCs are routine
    return _d("allow", "write-ok", "write inside jail", t0, needs_l2=(rel.parts[0] == "src"))


def _read(call: ToolCall, ws: Path, t0: float) -> FirewallDecision:
    if SENSITIVE.search(call.path):
        return _d("deny", "sensitive-path", "read of a credential/secret path", t0)
    if _inside(ws, call.path) is None:
        return _d("deny", "path-jail", f"read outside workspace: {call.path}", t0)
    return _d("allow", "read-ok", "read inside jail", t0)


def _net(call: ToolCall, t0: float) -> FirewallDecision:
    u = urlparse(call.url)
    if u.scheme != "https":
        return _d("deny", "net-scheme", "only https is allowed", t0)
    if u.username or u.password:
        return _d("deny", "net-creds", "credentials in URL", t0)
    if (u.hostname or "") not in NET_ALLOW_HOSTS:
        return _d("deny", "net-host", f"host not allowlisted: {u.hostname}", t0)
    return _d("allow", "net-allowlist", f"{u.hostname} allowlisted", t0, needs_l2=True)
