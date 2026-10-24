"""The single entry point every tool call goes through.

Execution capability (`GateToken`) is minted only here. Executors in sandbox/ require it, so
code that skips the gate fails at the type/runtime level, not by convention.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from redline.firewall import rules
from redline.firewall.log import FirewallLog
from redline.models import FirewallDecision, ToolCall


class PolicyJudge(Protocol):
    def judge(self, call: ToolCall, task: str) -> FirewallDecision: ...


class GateToken:
    """Proof that a call was approved. Cannot be built outside Gate."""

    __slots__ = ("call",)
    _mint_key = object()

    def __init__(self, key: object, call: ToolCall):
        if key is not GateToken._mint_key:
            raise PermissionError("GateToken can only be issued by Gate.authorize()")
        self.call = call


class GateDenied(Exception):
    def __init__(self, decision: FirewallDecision):
        super().__init__(f"[{decision.layer}:{decision.rule}] {decision.reason}")
        self.decision = decision


class Gate:
    def __init__(self, workspace: Path, log: FirewallLog | None = None,
                 policy: PolicyJudge | None = None, task: str = "audit a Solidity repository"):
        self.workspace = workspace.resolve()
        self.log = log or FirewallLog()
        self.policy = policy
        self.task = task

    def check(self, call: ToolCall) -> FirewallDecision:
        d = rules.evaluate(call, self.workspace)
        self.log.record(call, d)
        if d.verdict == "allow" and d.needs_l2 and self.policy is not None:
            t0 = time.perf_counter()
            try:
                d2 = self.policy.judge(call, self.task)
            except Exception as e:  # fail closed
                d2 = FirewallDecision(verdict="deny", layer="L2", rule="policy-error",
                                      reason=f"policy model failed: {e}", confidence=0.0)
            d2.latency_ms = (time.perf_counter() - t0) * 1000
            self.log.record(call, d2)
            return d2 if d2.verdict == "deny" else d
        return d

    def authorize(self, call: ToolCall) -> GateToken:
        d = self.check(call)
        if d.verdict != "allow":
            raise GateDenied(d)
        return GateToken(GateToken._mint_key, call)

    def run(self, call: ToolCall, executor: Callable[[GateToken], object]) -> object:
        """Check, then execute. Returns executor's result; raises GateDenied on deny."""
        return executor(self.authorize(call))
