"""Pydantic schemas shared across the system."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]


class ToolCall(BaseModel):
    """Anything the agent wants to do to the outside world. Every one passes the gate."""

    kind: Literal["shell", "write", "read", "net"]
    command: str = ""  # shell
    path: str = ""  # write / read
    content: str = ""  # write
    url: str = ""  # net
    purpose: str = ""  # free-text intent, shown to the Layer 2 judge

    def summary(self) -> str:
        if self.kind == "shell":
            return self.command[:200]
        if self.kind == "net":
            return self.url[:200]
        return f"{self.path} ({len(self.content)}B)" if self.kind == "write" else self.path


class FirewallDecision(BaseModel):
    verdict: Literal["allow", "deny"]
    layer: Literal["L1", "L2", "scanner"]
    rule: str
    reason: str
    confidence: float = 1.0
    latency_ms: float = 0.0
    needs_l2: bool = False  # L1 allowed, but the call is unusual: ask the policy model
    provider: str = ""  # which LLM provider served an L2/scanner model call


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    file: str
    function: str = ""
    description: str
    attack: str = Field(description="Step-by-step exploit idea")
    confidence: float = 0.5


class TestResult(BaseModel):
    name: str
    passed: bool
    reason: str = ""


class ForgeRun(BaseModel):
    ok: bool  # forge itself ran and compiled
    results: list[TestResult] = []
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration_s: float = 0.0

    @property
    def all_passed(self) -> bool:
        return self.ok and bool(self.results) and all(r.passed for r in self.results)


# ---- LLM output schemas (every structured reply is validated against one of these) ----

class ReconOut(BaseModel):
    findings: list[Finding]


class PoCDraft(BaseModel):
    contract_name: str = Field(description="Name of the Foundry test contract")
    code: str = Field(description="Complete Solidity test file")
    explanation: str = ""


class FileEdit(BaseModel):
    path: str
    content: str = Field(description="Complete new file content")


class PatchDraft(BaseModel):
    edits: list[FileEdit]
    rationale: str = ""


class JudgeOut(BaseModel):
    verdict: Literal["allow", "deny"]
    reason: str
    confidence: float = Field(ge=0, le=1)


class ScanOut(BaseModel):
    injected_lines: list[int] = []
    reason: str = ""


class Quarantine(BaseModel):
    file: str
    start_line: int
    end_line: int
    detector: str  # "regex" | "model"
    reason: str
    excerpt: str  # truncated original text, kept for the report only (never shown to the agent)


class Citation(BaseModel):
    title: str
    url: str
    snippet: str


class PoCResult(BaseModel):
    confirmed: bool
    attempts: int
    test_file: str = ""
    code: str = ""
    output: str = ""
    note: str = ""


class PatchResult(BaseModel):
    applied: bool
    attempts: int
    diff: str = ""
    poc_blocked: bool = False
    suite_green: bool = False
    output: str = ""
    note: str = ""


class FindingReport(BaseModel):
    finding: Finding
    citations: list[Citation] = []
    poc: PoCResult | None = None
    patch: PatchResult | None = None
    status: Literal["confirmed", "unconfirmed"] = "unconfirmed"
