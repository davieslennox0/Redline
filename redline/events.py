"""events.jsonl contract: one JSON event per line, emitted by the orchestrator.

The viewer renders purely from events.jsonl + report.json. Every event has `type`, `seq`
(monotonic per run) and `ts` (unix seconds).
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, Field, TypeAdapter

from redline.models import Citation, Finding

Stage = Literal["baseline", "scan", "recon", "research", "exploit", "patch"]


class _Base(BaseModel):
    seq: int = 0
    ts: float = 0.0


class RunStarted(_Base):
    type: Literal["run_started"] = "run_started"
    run_id: str
    repo: str
    provider: str
    models: dict[str, str]
    scripted: bool = False  # True: model text came from a scripted (mock) LLM, not a live model
    label: str = ""


class StageStarted(_Base):
    type: Literal["stage_started"] = "stage_started"
    stage: Stage
    finding_id: str = ""


class StageFinished(_Base):
    type: Literal["stage_finished"] = "stage_finished"
    stage: Stage
    finding_id: str = ""
    ok: bool = True
    duration_s: float = 0.0
    detail: str = ""
    citations: list[Citation] = []


class FindingAdded(_Base):
    type: Literal["finding_added"] = "finding_added"
    finding: Finding


class PocResultEvent(_Base):
    type: Literal["poc_result"] = "poc_result"
    finding_id: str
    attempt: int
    passed: bool  # True = exploit demonstrated (forge test passed)
    confirmed: bool  # final: no further attempts will be made
    test_file: str = ""
    code: str = ""
    output: str = ""  # forge output, truncated
    note: str = ""


class PatchResultEvent(_Base):
    type: Literal["patch_result"] = "patch_result"
    finding_id: str
    applied: bool
    attempts: int
    poc_blocked: bool
    suite_green: bool
    diff: str = ""
    output: str = ""
    note: str = ""


class FirewallDecisionEvent(_Base):
    type: Literal["firewall_decision"] = "firewall_decision"
    layer: str
    kind: str
    action: str
    verdict: Literal["allow", "deny"]
    rule: str
    reason: str
    latency_ms: float
    provider: str = ""


class InputQuarantined(_Base):
    type: Literal["input_quarantined"] = "input_quarantined"
    file: str
    start_line: int
    end_line: int
    detector: str
    reason: str
    excerpt: str


class LlmCall(_Base):
    type: Literal["llm_call"] = "llm_call"
    role: str
    model: str
    provider: str
    prompt_tokens: int
    completion_tokens: int
    latency_s: float


class RunFinished(_Base):
    type: Literal["run_finished"] = "run_finished"
    ok: bool = True
    duration_s: float
    error: str = ""


Event = Annotated[
    RunStarted | StageStarted | StageFinished | FindingAdded | PocResultEvent | PatchResultEvent
    | FirewallDecisionEvent | InputQuarantined | LlmCall | RunFinished,
    Field(discriminator="type"),
]
EventAdapter: TypeAdapter = TypeAdapter(Event)


def parse_event(line: str):
    return EventAdapter.validate_json(line)


class Emitter:
    """Validates and appends events to events.jsonl (flushed per line so SSE can tail it)."""

    def __init__(self, path: Path | None = None):
        self.path = path
        self.events: list[_Base] = []
        self._seq = 0
        self._lock = threading.Lock()
        self._llm_flushed = 0
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("")

    def emit(self, ev: _Base) -> None:
        with self._lock:
            self._seq += 1
            ev.seq, ev.ts = self._seq, time.time()
            parse_event(ev.model_dump_json())  # fail loudly if it violates the contract
            self.events.append(ev)
            if self.path:
                with self.path.open("a") as f:
                    f.write(ev.model_dump_json() + "\n")

    def flush_llm(self, llm) -> None:
        """Emit llm_call events for any LLM calls made since the last flush."""
        stats = getattr(llm, "stats", [])
        for s in stats[self._llm_flushed:]:
            self.emit(LlmCall(role=s.role, model=s.model, provider=s.provider,
                              prompt_tokens=s.prompt_tokens, completion_tokens=s.completion_tokens,
                              latency_s=round(s.latency_s, 3)))
        self._llm_flushed = len(stats)


def read_events(path: Path) -> list[dict]:
    out = []
    if path.exists():
        for ln in path.read_text().splitlines():
            if ln.strip():
                out.append(json.loads(ln))
    return out
