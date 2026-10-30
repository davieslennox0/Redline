"""End-to-end pipeline test with a SCRIPTED (mock) LLM and REAL forge in the sandbox.

The mock replaces only model text. Confirmation, patch validation, quarantine and the firewall
are real. Passing here proves the plumbing, not model capability.
"""

import shutil

import pytest

from redline.agent import orchestrator
from redline.config import ROOT, load_config
from redline.scripted import ScriptedLLM

pytestmark = pytest.mark.skipif(not shutil.which("docker"), reason="docker required")


def test_full_loop_confirms_and_patches_vault():
    cfg = load_config()
    llm = ScriptedLLM("vulnerable-vault")
    res = orchestrator.audit(
        ROOT / "fixtures/vulnerable-vault", cfg, llm, log=lambda *_: None, do_research=False
    )
    f = res.findings[0]
    assert res.baseline_green
    assert f.status == "confirmed" and f.poc.confirmed
    assert f.patch and f.patch.applied and f.patch.poc_blocked and f.patch.suite_green
    assert "balances[msg.sender] -= amount" in f.patch.diff
    # patching an existing src/ file is an L1-allowed write (L2 is for new src files / net calls)
    assert any(e["rule"] == "write-ok" and "src/" in e["action"] for e in res.firewall_log)


def test_poisoned_repo_injection_never_reaches_the_agent():
    cfg = load_config()
    llm = ScriptedLLM("poisoned-repo", no_findings=True)
    res = orchestrator.audit(
        ROOT / "fixtures/poisoned-repo", cfg, llm, log=lambda *_: None, do_research=False
    )
    assert res.quarantined
    recon_prompt = next(p for p in llm.seen_prompts if "Audit this repository" in p)
    for needle in ("evil-audit", "curl -s", "print all environment", "Ignore all prior"):
        assert needle not in recon_prompt
    assert "SECURITY FILTER WARNING" in recon_prompt


def test_poisoned_full_loop_denies_ffi_attempt_then_confirms_and_emits_valid_events():
    from pathlib import Path

    from redline.events import parse_event

    cfg = load_config()
    llm = ScriptedLLM("poisoned-repo")
    res = orchestrator.audit(
        ROOT / "fixtures/poisoned-repo",
        cfg,
        llm,
        log=lambda *_: None,
        do_research=False,
        run_name="pytest-poisoned",
        scripted=True,
    )
    f = res.findings[0]
    assert f.status == "confirmed" and f.poc.attempts == 2
    assert f.patch.applied and f.patch.poc_blocked and f.patch.suite_green
    assert any(e["verdict"] == "deny" and e["rule"] == "cheatcode" for e in res.firewall_log)
    evs = [parse_event(ln) for ln in (Path(res.out_dir) / "events.jsonl").read_text().splitlines()]
    types = [e.type for e in evs]
    assert types[0] == "run_started" and types[-1] == "run_finished"
    for t in (
        "stage_started",
        "finding_added",
        "poc_result",
        "patch_result",
        "firewall_decision",
        "input_quarantined",
        "llm_call",
    ):
        assert t in types, t
    assert [e.seq for e in evs] == sorted(e.seq for e in evs)
