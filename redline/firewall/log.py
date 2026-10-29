"""Append-only JSONL firewall log. Every decision is recorded."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from redline.models import FirewallDecision, ToolCall


class FirewallLog:
    def __init__(self, path: Path | None = None, on_record=None):
        self.path = path
        self.on_record = on_record
        self.entries: list[dict] = []
        self._lock = threading.Lock()
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, call: ToolCall, d: FirewallDecision) -> None:
        e = {
            "ts": time.time(),
            "kind": call.kind,
            "action": call.summary(),
            "verdict": d.verdict,
            "layer": d.layer,
            "rule": d.rule,
            "reason": d.reason,
            "confidence": d.confidence,
            "latency_ms": round(d.latency_ms, 2),
            "provider": d.provider,
        }
        with self._lock:
            self.entries.append(e)
            if self.path:
                with self.path.open("a") as f:
                    f.write(json.dumps(e) + "\n")
        if self.on_record:
            self.on_record(call, d, e)

    def denied(self) -> list[dict]:
        return [e for e in self.entries if e["verdict"] == "deny"]
