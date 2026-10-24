# Redline

Autonomous smart-contract security agent that **proves** its findings by executing them in a
sandbox, protected by a two-layer **agent firewall** (deterministic rules + a Nemotron policy
model) and an injection scanner for untrusted repo content.

> **Provider note:** development used NVIDIA's API catalog temporarily
> (`active_provider = "nvidia"`). All results in the submission were produced on
> **Nebius Token Factory**. `redline preflight` (run first by `scripts/demo.sh`) fails unless
> `active_provider = "nebius"`.

Status: M1 done; M2 plumbing done and tested with a scripted LLM; live-model runs pending keys.
See `docs/ACCESS.md` for how to get model access.

```
uv sync && cp .env.example .env   # add keys
uv run redline models             # provider, Nemotron models, latency, JSON-mode check
uv run redline sandbox-test fixtures/vulnerable-vault
uv run redline audit fixtures/vulnerable-vault
uv run pytest
```
