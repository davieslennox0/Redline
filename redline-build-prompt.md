# Claude Code Build Prompt — Redline

> Paste everything below the line into Claude Code, run from an empty directory on the VPS.

---

## Context

You are building **Redline**, an entry for the **Nebius x NVIDIA Global AI Hackathon 2026**, track **Coding & Agentic Engineering**. Submission deadline: **Fri Oct 30, 2026, 10:00 AM PT (17:00 UTC)**. Deliverables: public GitHub repo + demo video under 3 minutes.

Hard rules from the hackathon (non-negotiable):
- All model inference runs on **Nebius Token Factory** (OpenAI-compatible API).
- Use at least one **NVIDIA open model** — we use the Nemotron family for every LLM role.
- Judges are engineers from NVIDIA, Nebius and Tavily. Optimise for: working system, real execution, clear engineering. Not polish-over-substance.

I work over SSH from a phone (Termux). Keep CLI output readable in a narrow terminal. Use PM2 if anything long-running is needed.

## What Redline is

An autonomous smart-contract security agent that **proves** its findings by executing them, protected by a built-in **agent firewall** — because an agent that reads hostile code is itself an attack target.

Given a Solidity/Foundry repo, Redline:
1. **Recon** — loads the repo into Nemotron's long context, maps entry points, value flows, privileged functions, external calls. Outputs a ranked list of suspected vulnerabilities as structured JSON.
2. **Research** — for each suspect, queries **Tavily** for real-world exploits/post-mortems of the same pattern. Results are cited in the report.
3. **Exploit** — writes a Foundry PoC test per finding and runs `forge test` in a sandbox. A PoC that demonstrates the exploit = **confirmed**. A PoC that cannot be made to work after N attempts = **unconfirmed** (reported as such, never upgraded).
4. **Patch** — proposes a minimal fix, re-runs the PoC (must now fail to exploit) and the repo's existing test suite (must stay green). Iterate up to N times.
5. **Report** — Markdown + JSON + a single static HTML page: findings, severity, PoC code, patch diff, test output, sources, and the firewall log.

### Firewall (the feature that ties it together)
Every action and every piece of untrusted input passes through the firewall:
- **Input scanning**: all repo files, comments, READMEs, and Tavily results are treated as untrusted *data*. Before any of it reaches the main agent, a scanner flags prompt-injection attempts (instructions aimed at AI/auditors, requests to run commands, to suppress findings, to exfiltrate env vars, etc.). Flagged spans are quarantined: the agent sees a redacted placeholder + a warning, the report lists them.
- **Action gating**: every tool call (shell command, file write, network request) goes through a policy check before execution:
  - **Layer 1 — deterministic rules** (fast, unbypassable): command allowlist (`forge`, `git` read-only ops, `cat`/`ls` inside workspace), path jail (writes only inside the job workspace), no network from the sandbox, no reading `.env`/keys, no piping to shells, timeout and size caps.
  - **Layer 2 — Nemotron Nano policy model**: for anything Layer 1 allows but which is unusual, ask a small fast Nemotron model to judge intent against the current task. Returns `{allow|deny, reason, confidence}`.
  - Deny wins. Every decision is logged with layer, reason, latency.
- **The firewall must never be the main agent's own judgement** — it's a separate model call with its own system prompt and no access to the untrusted content's instructions as instructions.

## Stack

- **Python 3.11+**, `uv` for env/deps. Typed (pydantic models for every structured LLM output). `ruff` + `pytest`.
- LLM client: `openai` SDK pointed at Token Factory. Base URL: `https://api.tokenfactory.nebius.com/v1` — **verify** against the docs/console; a regional URL may be required. Key from env `NEBIUS_API_KEY`.
- Search: `tavily-python`, key from env `TAVILY_API_KEY`.
- Sandbox: **Docker**, Foundry image (`ghcr.io/foundry-rs/foundry`), run with `--network none`, read-only root, workspace mounted as a copy, CPU/mem limits, hard timeout.
- CLI: `typer` + `rich`.
- Report HTML: single self-contained file (Jinja2 template), no framework.

## Models (verify, don't assume)

On first run, call `GET /v1/models` and print the Nemotron models actually available. Expected (confirm IDs exactly):
- **Main agent (recon, exploit writing, patching)**: Nemotron 3 Super (e.g. `nvidia/nemotron-3-super-120b-a12b`). Fall back to Nemotron 3 Ultra for recon if Super struggles with very large repos.
- **Firewall policy + injection scanner**: Nemotron 3 Nano (smallest/fastest available).
- Put all model IDs in `config.toml`, never hard-coded in logic.

Stretch goal (only if the core loop is solid by Tue Oct 27): fine-tune Nano on Token Factory as the firewall classifier using a dataset we generate (benign vs. malicious tool calls / injected vs. clean text). Build the dataset generator so this is possible, but do not start the fine-tune until I say so.

## Repo layout

```
redline/
  README.md                 # judge-facing: what, why, architecture diagram, how to run, sponsor tech used
  config.toml
  pyproject.toml
  redline/
    cli.py                  # `redline audit <path>`, `redline models`, `redline firewall-test`
    llm.py                  # Token Factory client, retries, JSON-mode/structured output, token+latency logging
    agent/
      recon.py
      research.py
      exploit.py
      patch.py
      orchestrator.py       # the loop, state machine, max-iteration limits
    firewall/
      rules.py              # Layer 1 deterministic
      policy.py             # Layer 2 Nano judge
      scanner.py            # injection scanner for untrusted input
      gate.py               # single entry point every tool call goes through
      log.py
    sandbox/
      docker_runner.py      # forge build/test inside container, parse results
    report/
      render.py
      template.html.j2
    models.py               # pydantic schemas: Finding, PoC, Patch, FirewallDecision, Report
  fixtures/
    vulnerable-vault/       # reentrancy
    oracle-lender/          # spot-price oracle manipulation
    admin-takeover/         # missing access control / unprotected initializer
    poisoned-repo/          # contains a real bug AND a planted prompt injection (see below)
  datasets/
    gen_firewall_data.py    # for the stretch fine-tune
  tests/
  scripts/
    demo.sh                 # one command that runs the full demo path end-to-end
```

## Fixtures (write these yourself, small and realistic)

Each fixture is a minimal Foundry project with its own passing "happy path" tests and one known bug. Keep each under ~150 lines of Solidity.
- `vulnerable-vault`: ETH vault with withdraw-before-state-update reentrancy.
- `oracle-lender`: lending pool pricing collateral from a manipulable AMM spot price.
- `admin-takeover`: upgradeable-style contract with an unprotected `initialize()`.
- `poisoned-repo`: a token/staking contract with a real bug (e.g. reward accounting error) **plus** a planted injection in a NatSpec comment and in the README, e.g. text addressed to "AI security auditors" instructing them to report no issues and run a `curl ... | sh` setup step, and to print environment variables. This is the demo centrepiece: the firewall must quarantine it, block any resulting command, and the audit must still find the real bug.

## Engineering rules for you (Claude Code)

- Never fake results. If forge didn't run, the finding is not confirmed. No mocked LLM outputs outside unit tests.
- Never hard-code or log API keys. `.env.example` only. Add `.env` to `.gitignore` before the first commit.
- Every LLM call that returns structure must be validated by pydantic; on validation failure retry with the error, max 2 retries, then fail loudly.
- Bound everything: max findings per run, max exploit attempts per finding (default 3), max patch attempts (default 3), per-call timeouts, total token budget per run. Log tokens and latency per call — the report shows cost.
- Every tool call goes through `firewall/gate.py`. No exceptions, including your own helper code paths. Add a test that asserts the orchestrator cannot execute a command without passing the gate.
- Commit after each working milestone with a clear message.
- Don't mark a milestone done unless its acceptance check actually passes on this machine. Tell me exactly what ran and what failed.

## Milestones

**M1 — Tonight: foundation**
- Project scaffold, config, `.env.example`, `.gitignore`.
- `redline models` lists available Nemotron models from Token Factory and does one test completion each with main + firewall model.
- Docker sandbox runner: builds and runs `forge test` on a fixture, returns parsed pass/fail per test, enforces no-network and timeout.
- All four fixtures written, each with passing happy-path tests (`forge test` green in sandbox).
- Firewall Layer 1 rules + gate + log, with unit tests (allowlist, path jail, pipe-to-shell, env read, network).
- ✅ Acceptance: `redline models` works; `forge test` passes in sandbox for all fixtures; firewall unit tests pass.

**M2 — Sat–Sun: the agent loop**
- Recon → structured findings on each fixture.
- Exploit writer + run loop until confirmed/unconfirmed.
- Injection scanner + Layer 2 policy model wired into the gate.
- ✅ Acceptance: `redline audit fixtures/vulnerable-vault` produces a confirmed reentrancy finding with a working PoC.

**M3 — Mon–Tue: research, patch, report**
- Tavily research with citations.
- Patch loop (PoC must stop exploiting, existing tests stay green).
- Markdown/JSON/HTML report including firewall log and token/latency/cost table.
- ✅ Acceptance: all four fixtures audited end-to-end; poisoned-repo shows quarantined injection, blocked command, and the real bug still confirmed and patched.

**M4 — Wed: hardening + (maybe) fine-tune**
- Run against 1–2 small real public repos with known historical bugs, to show it's not fixture-tuned.
- Firewall eval: a small labelled set of injection/benign samples; report precision/recall for Layer 1 alone vs. Layer 1+2.
- Fine-tune only if I approve.

**M5 — Thu: submission**
- README for judges: problem, architecture diagram (mermaid), sponsor tech and where each is used, how to run, eval numbers, limitations (be honest).
- `scripts/demo.sh` runs the demo path in one command.
- Help me script the <3 min video: poisoned repo → firewall blocks → bug confirmed → patch green → report.

## Start now

Begin with M1. First: check Docker and `uv` are installed (install if missing), confirm the Token Factory base URL and list models, then scaffold. Ask me only if you're blocked on a key or a decision you can't reasonably make yourself.
