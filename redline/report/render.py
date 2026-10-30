"""Markdown report from a run's report.json (HTML comes from `redline export`)."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path


def _fence(code: str, lang: str = "") -> str:
    return f"```{lang}\n{code.rstrip()}\n```"


def render_markdown(report: dict) -> str:
    out = [f"# Redline audit: {report['repo']}", ""]
    tag = " (SAMPLE: scripted model)" if report.get("scripted") else ""
    m = report.get("models", {})
    out += [
        f"- run: `{report['run_id']}`{tag}",
        f"- provider: `{report.get('provider')}`; main model `{m.get('main')}`; "
        f"firewall model `{m.get('firewall')}`",
        f"- baseline tests green: {report.get('baseline_green')}; "
        f"elapsed: {report.get('elapsed_s', 0):.0f} s",
        "",
        "## Findings",
        "",
        "| id | severity | status | patch | title |",
        "|---|---|---|---|---|",
    ]
    for f in report["findings"]:
        p = f.get("patch")
        pt = "-" if not p else ("fixed" if p["applied"] else "not fixed")
        fd = f["finding"]
        out.append(f"| {fd['id']} | {fd['severity']} | {f['status']} | {pt} | {fd['title']} |")
    for f in report["findings"]:
        fd, poc, p = f["finding"], f.get("poc") or {}, f.get("patch")
        out += ["", f"### {fd['id']} - {fd['title']} ({fd['severity']}, {f['status']})", ""]
        for k in ("description", "location", "file", "function", "impact"):
            if fd.get(k):
                out.append(f"- {k}: {fd[k]}")
        if poc.get("code"):
            out += [
                "",
                f"**PoC** (`{poc.get('test_file', '')}`, {poc.get('attempts', 0)} attempt(s))",
                "",
                _fence(poc["code"], "solidity"),
            ]
        if poc.get("output"):
            out += ["", "forge output:", "", _fence(poc["output"])]
        if poc.get("note") and not poc.get("confirmed"):
            out += ["", f"not confirmed: {poc['note']}"]
        if p:
            out += [
                "",
                f"**Patch**: applied={p['applied']}, exploit blocked={p['poc_blocked']}, "
                f"existing suite green={p['suite_green']}",
                "",
            ]
            if p.get("diff"):
                out.append(_fence(p["diff"], "diff"))
        if f.get("citations"):
            out += ["", "**Sources (Tavily)**", ""]
            out += [f"- [{c['title']}]({c['url']})" for c in f["citations"]]
    out += ["", "## Firewall", ""]
    q = report.get("quarantined", [])
    out.append(f"Quarantined input spans: {len(q)}")
    for x in q:
        out.append(
            f"- `{x['file']}` lines {x['start_line']}-{x['end_line']} "
            f"({x['detector']}): {x['reason']}"
        )
    fw = report.get("firewall_log", [])
    by = defaultdict(int)
    for e in fw:
        by[(e["layer"], e["verdict"])] += 1
    out += [
        "",
        f"Tool-call decisions: {len(fw)} total; "
        + ", ".join(f"{lay} {v}: {n}" for (lay, v), n in sorted(by.items())),
    ]
    denies = [e for e in fw if e["verdict"] == "deny"]
    for e in denies:
        out.append(
            f"- DENY [{e['layer']}:{e['rule']}] {e['kind']} `{e['action'][:80]}`: {e['reason']}"
        )
    out += [
        "",
        "## Model calls",
        "",
        "| role | calls | prompt tok | completion tok | total s |",
        "|---|---|---|---|---|",
    ]
    agg = defaultdict(lambda: [0, 0, 0, 0.0])
    for c in report.get("calls", []):
        a = agg[c["role"]]
        a[0] += 1
        a[1] += c["prompt_tokens"]
        a[2] += c["completion_tokens"]
        a[3] += c["latency_s"]
    for role, (n, pt, ct, s) in sorted(agg.items()):
        out.append(f"| {role} | {n} | {pt} | {ct} | {s:.0f} |")
    out += ["", "Cost: n/a (no per-token pricing configured; token counts above are measured)."]
    return "\n".join(out) + "\n"


def write_markdown(run_dir: Path) -> Path:
    rep = json.loads((run_dir / "report.json").read_text())
    p = run_dir / "report.md"
    p.write_text(render_markdown(rep))
    return p
