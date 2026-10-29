"""Token Factory client (OpenAI-compatible): retries, pydantic-validated output, usage log."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import TypeVar

from openai import OpenAI
from pydantic import BaseModel, ValidationError

from redline.config import Config, require_env

T = TypeVar("T", bound=BaseModel)


@dataclass
class CallStat:
    provider: str
    model: str
    role: str
    prompt_tokens: int
    completion_tokens: int
    latency_s: float


@dataclass
class LLM:
    cfg: Config
    stats: list[CallStat] = field(default_factory=list)

    def __post_init__(self):
        p = self.cfg.provider
        self.provider = self.cfg.active_provider
        self._last_call = 0.0
        self.client = OpenAI(
            base_url=p.base_url,
            api_key=require_env(p.key_env),
            timeout=self.cfg.llm.timeout_s,
            max_retries=4,
        )

    @property
    def total_tokens(self) -> int:
        return sum(s.prompt_tokens + s.completion_tokens for s in self.stats)

    def chat(
        self,
        model: str,
        messages: list[dict],
        role: str = "",
        temperature: float = 0.2,
        max_tokens: int = 4096,
        thinking: bool | None = None,
    ) -> str:
        if self.total_tokens > self.cfg.llm.token_budget_per_run:
            raise RuntimeError("token budget exhausted for this run")
        self._pace()
        t0 = time.perf_counter()
        extra = {}
        if thinking is not None and self.provider == "nvidia":
            extra["extra_body"] = {"chat_template_kwargs": {"enable_thinking": thinking}}
        r = self.client.chat.completions.create(
            model=model, messages=messages, temperature=temperature, max_tokens=max_tokens, **extra
        )
        u = r.usage
        self.stats.append(
            CallStat(
                self.provider,
                model,
                role,
                u.prompt_tokens if u else 0,
                u.completion_tokens if u else 0,
                time.perf_counter() - t0,
            )
        )
        return r.choices[0].message.content or ""

    def _pace(self) -> None:
        """Client-side rate limit so free-tier RPM caps are not hit."""
        rpm = self.cfg.llm.rpm_limit
        if rpm:
            wait = self._last_call + 60.0 / rpm - time.monotonic()
            if wait > 0:
                time.sleep(wait)
        self._last_call = time.monotonic()

    def structured(
        self, model: str, messages: list[dict], schema: type[T], role: str = "", **kw
    ) -> T:
        """Call, parse JSON, validate with pydantic; retry with the error (max cfg.max_retries)."""
        msgs = list(messages)
        err = ""
        for attempt in range(self.cfg.llm.max_retries + 1):
            raw = self.chat(model, msgs, role=role, **kw)
            try:
                return schema.model_validate(json.loads(_extract_json(raw)))
            except (ValueError, ValidationError) as e:
                err = str(e)[:1500]
                msgs = msgs + [
                    {"role": "assistant", "content": raw},
                    {
                        "role": "user",
                        "content": f"Your reply was invalid: {err}\nReply with ONLY valid JSON "
                        f"matching the schema.",
                    },
                ]
        raise RuntimeError(f"{role or 'llm'}: structured output failed after retries: {err}")


def _extract_json(text: str) -> str:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    m = re.search(r"```(?:json)?\s*(.*?)```", text, flags=re.S)
    if m:
        return m.group(1).strip()
    s = min([i for i in (text.find("{"), text.find("[")) if i >= 0], default=0)
    return text[s:]
