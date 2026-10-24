"""State machine: LOAD/SCAN -> RECON -> per finding (RESEARCH -> EXPLOIT -> PATCH) -> REPORT."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from redline.agent import exploit, patch, recon, research
from redline.agent.tools import Tools
from redline.config import Config
from redline.firewall.gate import Gate
from redline.firewall.log import FirewallLog
from redline.firewall.policy import NanoPolicy
from redline.models import FindingReport, Quarantine
from redline.sandbox import docker_runner


@dataclass
class AuditResult:
    repo: str
    provider: str
    findings: list[FindingReport] = field(default_factory=list)
    quarantined: list[Quarantine] = field(default_factory=list)
    firewall_log: list[dict] = field(default_factory=list)
    calls: list[dict] = field(default_factory=list)
    baseline_green: bool = False
    elapsed_s: float = 0.0
    out_dir: str = ""

    def to_json(self) -> str:
        d = {**self.__dict__, "findings": [f.model_dump() for f in self.findings],
             "quarantined": [q.model_dump() for q in self.quarantined]}
        return json.dumps(d, indent=2)


def audit(repo: Path, cfg: Config, llm, log=print, do_patch: bool = True,
          do_research: bool = True) -> AuditResult:
    t0 = time.perf_counter()
    ws = docker_runner.make_workspace(repo.resolve())
    flog = FirewallLog(ws.parent / "firewall.jsonl")
    gate = Gate(ws, flog, policy=NanoPolicy(llm, cfg.models.firewall))
    tools = Tools(gate, cfg)
    res = AuditResult(repo=str(repo), provider=cfg.active_provider, out_dir=str(ws.parent))

    log("[1/5] baseline: forge test on the untouched repo")
    base = tools.forge("test", purpose="baseline test run")
    res.baseline_green = base.all_passed
    if not base.ok:
        raise RuntimeError(f"repo does not build in the sandbox: {base.stderr[-500:]}")

    log("[2/5] scan + load repo through the firewall")
    files, res.quarantined = recon.load_repo(tools, llm, cfg.models.firewall)
    for q in res.quarantined:
        log(f"  QUARANTINED {q.file}:{q.start_line}-{q.end_line} ({q.detector}: {q.reason})")
    warnings = [f"{q.file}:{q.start_line}-{q.end_line}" for q in res.quarantined]

    log("[3/5] recon")
    findings = recon.run_recon(llm, cfg, files, warnings)
    log(f"  {len(findings)} suspected finding(s)")

    for f in findings:
        fr = FindingReport(finding=f)
        log(f"[4/5] {f.id} {f.severity} {f.title}")
        if do_research:
            try:
                fr.citations = research.research(tools, f, llm, cfg.models.firewall, res.quarantined)
            except Exception as e:
                log(f"  research failed: {e}")
        fr.poc = exploit.run_exploit(llm, cfg, tools, f, files)
        fr.status = "confirmed" if fr.poc.confirmed else "unconfirmed"
        log(f"  PoC: {fr.status} after {fr.poc.attempts} attempt(s)")
        if fr.poc.confirmed and do_patch:
            fr.patch = patch.run_patch(llm, cfg, tools, f, fr.poc, files)
            log(f"  patch: applied={fr.patch.applied} (attempts {fr.patch.attempts})")
        res.findings.append(fr)

    log("[5/5] report")
    res.firewall_log = flog.entries
    res.calls = [s.__dict__ for s in llm.stats]
    res.elapsed_s = time.perf_counter() - t0
    (ws.parent / "report.json").write_text(res.to_json())
    return res
