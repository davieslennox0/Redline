"""State machine: LOAD/SCAN -> RECON -> per finding (RESEARCH -> EXPLOIT -> PATCH) -> REPORT.

Emits events.jsonl (see redline/events.py) and writes report.json.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from redline import events as ev
from redline.agent import exploit, patch, recon, research
from redline.agent.tools import Tools
from redline.config import Config
from redline.firewall.gate import Gate
from redline.firewall.log import FirewallLog
from redline.firewall.policy import NanoPolicy
from redline.models import FindingReport, PatchResult, PoCResult, Quarantine
from redline.sandbox import docker_runner


@dataclass
class AuditResult:
    run_id: str
    repo: str
    provider: str
    findings: list[FindingReport] = field(default_factory=list)
    quarantined: list[Quarantine] = field(default_factory=list)
    quarantine_files: dict[str, str] = field(default_factory=dict)  # original text, for the viewer
    firewall_log: list[dict] = field(default_factory=list)
    calls: list[dict] = field(default_factory=list)
    baseline_green: bool = False
    elapsed_s: float = 0.0
    out_dir: str = ""
    scripted: bool = False
    label: str = ""
    models: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        d = {
            **self.__dict__,
            "findings": [f.model_dump() for f in self.findings],
            "quarantined": [q.model_dump() for q in self.quarantined],
        }
        return json.dumps(d, indent=2)


def audit(
    repo: Path,
    cfg: Config,
    llm,
    log=print,
    do_patch: bool = True,
    do_research: bool = True,
    run_name: str | None = None,
    scripted: bool = False,
    label: str = "",
    out_root: Path | None = None,
) -> AuditResult:
    t0 = time.perf_counter()
    ws = docker_runner.make_workspace(repo.resolve(), name=run_name, root=out_root)
    run_id = ws.parent.name
    em = ev.Emitter(ws.parent / "events.jsonl")

    def on_fw(call, d, e):
        em.emit(
            ev.FirewallDecisionEvent(
                layer=d.layer,
                kind=call.kind,
                action=e["action"],
                verdict=d.verdict,
                rule=d.rule,
                reason=d.reason,
                latency_ms=round(d.latency_ms, 3),
                provider=d.provider,
            )
        )

    flog = FirewallLog(ws.parent / "firewall.jsonl", on_record=on_fw)
    gate = Gate(ws, flog, policy=NanoPolicy(llm, cfg.models.firewall))
    tools = Tools(gate, cfg)
    models = {"main": cfg.models.main, "firewall": cfg.models.firewall}
    provider = getattr(llm, "provider", cfg.active_provider)
    res = AuditResult(
        run_id=run_id,
        repo=str(repo),
        provider=provider,
        out_dir=str(ws.parent),
        scripted=scripted,
        label=label,
        models=models,
    )
    em.emit(
        ev.RunStarted(
            run_id=run_id,
            repo=repo.name,
            provider=provider,
            models=models,
            scripted=scripted,
            label=label,
        )
    )

    class stage:  # context manager emitting stage_started / stage_finished
        def __init__(self, name, fid=""):
            self.name, self.fid, self.ok, self.detail, self.cites = name, fid, True, "", []

        def __enter__(self):
            self.t = time.perf_counter()
            em.emit(ev.StageStarted(stage=self.name, finding_id=self.fid))
            return self

        def __exit__(self, et, exc, tb):
            em.flush_llm(llm)
            em.emit(
                ev.StageFinished(
                    stage=self.name,
                    finding_id=self.fid,
                    ok=self.ok and et is None,
                    duration_s=round(time.perf_counter() - self.t, 3),
                    detail=self.detail or (str(exc)[:300] if exc else ""),
                    citations=self.cites,
                )
            )

    try:
        log("[1/5] baseline: forge test on the untouched repo")
        with stage("baseline") as st:
            base = tools.forge("test", purpose="baseline test run")
            res.baseline_green = base.all_passed
            st.ok, st.detail = base.ok, f"{len(base.results)} tests, all green={base.all_passed}"
            if not base.ok:
                raise RuntimeError(f"repo does not build in the sandbox: {base.stderr[-500:]}")

        log("[2/5] scan + load repo through the firewall")
        with stage("scan") as st:
            files, res.quarantined = recon.load_repo(
                tools, llm, cfg.models.firewall, raw_out=res.quarantine_files
            )
            for q in res.quarantined:
                log(
                    f"  QUARANTINED {q.file}:{q.start_line}-{q.end_line} ({q.detector}: {q.reason})"
                )
                em.emit(ev.InputQuarantined(**q.model_dump()))
            st.detail = f"{len(files)} files, {len(res.quarantined)} span(s) quarantined"
        warnings = [f"{q.file}:{q.start_line}-{q.end_line}" for q in res.quarantined]

        log("[3/5] recon")
        with stage("recon") as st:
            findings = recon.run_recon(llm, cfg, files, warnings)
            st.detail = f"{len(findings)} suspected finding(s)"
        log(f"  {len(findings)} suspected finding(s)")
        for f in findings:
            em.emit(ev.FindingAdded(finding=f))

        for f in findings:
            fr = FindingReport(finding=f)
            log(f"[4/5] {f.id} {f.severity} {f.title}")
            ctx = f"audit a Solidity repo; current finding {f.id}: {f.title[:120]}. Current stage: "
            gate.task = ctx + "web research (Tavily search for public write-ups of this pattern)."
            if do_research:
                with stage("research", f.id) as st:
                    try:
                        fr.citations = research.research(
                            tools, f, llm, cfg.models.firewall, res.quarantined
                        )
                    except Exception as e:
                        st.ok, st.detail = False, f"research failed: {e}"[:300]
                    st.cites = fr.citations

            def on_attempt(p, passed, fid=f.id):
                em.emit(
                    ev.PocResultEvent(
                        finding_id=fid,
                        attempt=p.attempts,
                        passed=passed,
                        confirmed=passed,
                        test_file=p.test_file,
                        code=p.code,
                        output=p.output,
                        note=p.note,
                    )
                )

            gate.task = ctx + "exploit (writing and running a Foundry PoC test in test/)."
            with stage("exploit", f.id) as st:
                try:
                    fr.poc = exploit.run_exploit(llm, cfg, tools, f, files, on_attempt=on_attempt)
                except Exception as e:  # one bad finding must not abort the whole audit
                    fr.poc = PoCResult(
                        confirmed=False, attempts=0, note=f"exploit error: {e}"[:400]
                    )
                fr.status = "confirmed" if fr.poc.confirmed else "unconfirmed"
                st.ok = fr.poc.confirmed
                st.detail = f"{fr.status} after {fr.poc.attempts} attempt(s)"
            log(f"  PoC: {fr.status} after {fr.poc.attempts} attempt(s)")
            if fr.poc.confirmed and do_patch:
                gate.task = ctx + "patch (rewriting the vulnerable src/ file to fix this finding)."
                with stage("patch", f.id) as st:
                    try:
                        fr.patch = patch.run_patch(llm, cfg, tools, f, fr.poc, files)
                    except Exception as e:
                        fr.patch = PatchResult(
                            applied=False, attempts=0, note=f"patch error: {e}"[:400]
                        )
                    st.ok, st.detail = fr.patch.applied, fr.patch.note[:300]
                p = fr.patch
                em.emit(
                    ev.PatchResultEvent(
                        finding_id=f.id,
                        applied=p.applied,
                        attempts=p.attempts,
                        poc_blocked=p.poc_blocked,
                        suite_green=p.suite_green,
                        diff=p.diff,
                        output=p.output,
                        note=p.note,
                    )
                )
                log(f"  patch: applied={p.applied} (attempts {p.attempts})")
            res.findings.append(fr)
        err = ""
    except Exception as e:
        err = str(e)[:500]
        res.elapsed_s = time.perf_counter() - t0
        em.flush_llm(llm)
        em.emit(ev.RunFinished(ok=False, duration_s=round(res.elapsed_s, 3), error=err))
        raise
    log("[5/5] report")
    res.firewall_log = flog.entries
    res.calls = [s.__dict__ for s in llm.stats]
    res.elapsed_s = time.perf_counter() - t0
    (ws.parent / "report.json").write_text(res.to_json())
    em.emit(ev.RunFinished(ok=True, duration_s=round(res.elapsed_s, 3)))
    return res
