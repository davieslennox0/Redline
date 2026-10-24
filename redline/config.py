"""Config loading: config.toml + env. Model IDs live only in config.toml."""
from __future__ import annotations

import os
import tomllib
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent


class Models(BaseModel):
    main: str
    recon_fallback: str
    firewall: str


class LLMCfg(BaseModel):
    base_url: str
    timeout_s: int = 120
    max_retries: int = 2
    token_budget_per_run: int = 2_000_000


class Limits(BaseModel):
    max_findings: int = 6
    max_exploit_attempts: int = 3
    max_patch_attempts: int = 3


class SandboxCfg(BaseModel):
    image: str
    timeout_s: int = 180
    memory: str = "1g"
    cpus: str = "2"
    solc_path: str = ""  # host path to a solc binary mounted into the container


class FirewallCfg(BaseModel):
    max_output_bytes: int = 200_000
    command_timeout_s: int = 180


class Config(BaseModel):
    models: Models
    llm: LLMCfg
    limits: Limits
    sandbox: SandboxCfg
    firewall: FirewallCfg


def load_config(path: Path | None = None) -> Config:
    load_dotenv(ROOT / ".env")
    p = path or ROOT / "config.toml"
    cfg = Config(**tomllib.loads(p.read_text()))
    if os.environ.get("REDLINE_SOLC"):
        cfg.sandbox.solc_path = os.environ["REDLINE_SOLC"]
    return cfg


def require_env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise SystemExit(f"{name} is not set. Copy .env.example to .env and fill it in.")
    return v
