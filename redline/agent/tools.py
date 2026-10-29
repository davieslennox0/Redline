"""The agent's only hands. Every method routes through the firewall gate."""

from __future__ import annotations

import httpx

from redline.config import Config
from redline.firewall.gate import Gate
from redline.models import ForgeRun, ToolCall
from redline.sandbox import docker_runner, fs


class Tools:
    def __init__(self, gate: Gate, cfg: Config):
        self.gate, self.cfg, self.ws = gate, cfg, gate.workspace

    def read(self, path: str) -> str:
        return self.gate.run(ToolCall(kind="read", path=path), lambda t: fs.read_file(t, self.ws))

    def write(self, path: str, content: str, purpose: str = "") -> None:
        self.gate.run(
            ToolCall(kind="write", path=path, content=content, purpose=purpose),
            lambda t: fs.write_file(t, self.ws),
        )

    def forge(self, args: str, purpose: str = "") -> ForgeRun:
        call = ToolCall(kind="shell", command=f"forge {args}", purpose=purpose)
        return self.gate.run(call, lambda t: docker_runner.run_forge(t, self.ws, self.cfg))

    def post_json(self, url: str, payload: dict, headers: dict, purpose: str = "") -> dict:
        call = ToolCall(kind="net", url=url, purpose=purpose)
        return self.gate.run(
            call,
            lambda t: (
                httpx.post(t.call.url, json=payload, headers=headers, timeout=30)
                .raise_for_status()
                .json()
            ),
        )
