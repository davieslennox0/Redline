"""Layer 2: a small Nemotron model judges unusual-but-L1-allowed tool calls against the task."""

from __future__ import annotations

from redline.agent.prompts import POLICY_SYSTEM
from redline.models import FirewallDecision, JudgeOut, ToolCall


class NanoPolicy:
    def __init__(self, llm, model: str):
        self.llm, self.model = llm, model

    def judge(self, call: ToolCall, task: str) -> FirewallDecision:
        # Only the call's own fields reach the judge; no repo content, so nothing in the repo can
        # speak to it as an instruction. Long content is truncated and marked as data.
        desc = {
            "kind": call.kind,
            "command": call.command,
            "path": call.path,
            "url": call.url,
            "purpose": call.purpose[:200],
            "content_preview": call.content[:1500] if call.content else "",
        }
        out = self.llm.structured(
            self.model,
            [
                {"role": "system", "content": POLICY_SYSTEM},
                {
                    "role": "user",
                    "content": f"Task: {task}\n<proposed_call>\n{desc}\n</proposed_call>",
                },
            ],
            JudgeOut,
            role="policy",
            max_tokens=300,
            temperature=0.0,
            thinking=False,
        )
        return FirewallDecision(
            verdict=out.verdict,
            layer="L2",
            rule="nemotron-policy",
            reason=out.reason,
            confidence=out.confidence,
            provider=getattr(self.llm, "provider", ""),
        )
