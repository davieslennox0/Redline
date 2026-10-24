import { esc, solidity, diff } from "./highlight.js";
import { STAGES, totals, latencyByLayer } from "./state.js";

const fmtDur = (s) => (s >= 60 ? `${Math.floor(s / 60)}m ${Math.round(s % 60)}s` : `${s.toFixed(1)}s`);
const fmtMs = (ms) => (ms >= 100 ? `${ms.toFixed(0)}ms` : `${ms.toFixed(2)}ms`);
const SEV = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function banner(st) {
  if (!st.run?.scripted) return "";
  return `<div class="banner"><b>SAMPLE &mdash; scripted model.</b> Model text in this run was replayed
    from a script, not produced by an LLM. Forge execution, the scanner and the firewall are real.
    Token counts are 0 because no model was called.</div>`;
}

export function header(st) {
  const t = totals(st), r = st.run;
  if (!r) return `<div class="hdr"><div class="muted">waiting for run&hellip;</div></div>`;
  const state = st.finished ? (st.finished.ok ? "finished" : "failed") : "running";
  const cell = (k, v, cls = "") => `<div class="stat ${cls}"><div class="k">${k}</div><div class="v">${v}</div></div>`;
  return `<div class="hdr">
    <div class="hdr-top"><h1>${esc(r.repo)}</h1><span class="pill ${state}">${state}</span></div>
    <div class="stats">
      ${cell("findings", t.findings)}
      ${cell("confirmed", t.confirmed, t.confirmed ? "red" : "")}
      ${cell("patched", t.fixed, t.fixed ? "green" : "")}
      ${cell("fw denied", t.denies, t.denies ? "red" : "")}
      ${cell("quarantined", t.quarantined, t.quarantined ? "red" : "")}
      ${cell("duration", fmtDur(t.duration_s))}
      ${cell("tokens", t.tokens.toLocaleString() + (t.calls ? ` <small>(${t.calls} calls)</small>` : ""))}
      ${cell("cost", "n/a <small>no pricing configured</small>")}
      ${cell("providers", esc(t.providers.join(", ") || "-"))}
    </div></div>`;
}

const STAGE_LABEL = { baseline: "Baseline", scan: "Scan", recon: "Recon", research: "Research", exploit: "Exploit", patch: "Patch" };
export function stepper(st) {
  return `<div class="stepper">${STAGES.map((s, i) => {
    const x = st.stages[s];
    const n = x.runs.length, ok = x.runs.filter((r) => r.status === "ok").length;
    const meta = x.status === "pending" ? (st.finished ? "not run" : "pending") : n > 1 || ["research", "exploit", "patch"].includes(s) ? `${ok}/${n}` : x.status;
    return `<div class="step ${x.status}"><div class="dot">${x.status === "ok" ? "&#10003;" : x.status === "fail" ? "&#10005;" : i + 1}</div>
      <div class="lbl">${STAGE_LABEL[s]}<small>${meta}</small></div></div>`;
  }).join("")}</div>`;
}

function sevChip(s) { return `<span class="sev sev-${esc(s)}">${esc(s)}</span>`; }

function findingStatus(f) {
  if (f.attempts.some((a) => a.confirmed)) return ["confirmed", "CONFIRMED", "red"];
  if (f.attempts.length && f.stage.exploit && f.stage.exploit !== "running") return ["unconfirmed", "UNCONFIRMED", "grey"];
  if (f.stage.exploit === "running") return ["testing", "TESTING PoC", "amber"];
  return ["suspected", "SUSPECTED", "grey"];
}

export function findingCards(st) {
  const ids = st.order.filter((id) => st.findings[id].finding)
    .sort((a, b) => SEV[st.findings[a].finding.severity] - SEV[st.findings[b].finding.severity]);
  if (!ids.length) return `<div class="empty">No findings yet.</div>`;
  return ids.map((id) => {
    const f = st.findings[id], fd = f.finding, [, label, col] = findingStatus(f);
    const step = (name, key) => {
      const v = f.stage[key];
      return `<span class="mini ${v || "pending"}">${name}</span>`;
    };
    const patch = f.patch ? (f.patch.applied ? `<span class="mini ok">patched</span>` : `<span class="mini fail">patch failed</span>`) : "";
    return `<div class="card finding ${col}"><div class="row">${sevChip(fd.severity)}<b>${esc(fd.title)}</b>
      <span class="chip ${col}">${label}</span></div>
      <div class="muted mono">${esc(fd.file)}${fd.function ? " :: " + esc(fd.function) : ""}</div>
      <p>${esc(fd.description)}</p>
      <div class="minis">${step("research", "research")}${step("exploit", "exploit")}${patch || step("patch", "patch")}
      <span class="muted">${f.attempts.length ? f.attempts.length + " PoC attempt(s)" : ""}</span></div></div>`;
  }).join("");
}

export function fwFeed(st, limit = 200) {
  if (!st.fw.length) return `<div class="empty">No firewall activity yet.</div>`;
  const t0 = st.t0;
  return `<div class="feed">${[...st.fw].reverse().slice(0, limit).map((f) => `
    <div class="fw ${f.verdict}"><span class="vd">${f.verdict === "deny" ? "DENY" : "ALLOW"}</span>
    <span class="chip lay">${esc(f.layer)}</span><span class="mono act">${esc(f.kind)} ${esc(f.action)}</span>
    <span class="why">${esc(f.rule)} &mdash; ${esc(f.reason)}</span>
    <span class="meta">${fmtMs(f.latency_ms)}${f.provider ? " &middot; " + esc(f.provider) : ""} &middot; +${(f.ts - t0).toFixed(1)}s</span></div>`).join("")}</div>`;
}

export function live(st) {
  return `${stepper(st)}<div class="cols"><section><h2>Findings</h2>${findingCards(st)}</section>
    <section><h2>Firewall <small>${st.fw.length} decisions</small></h2>${fwFeed(st)}</section></div>`;
}

// ---------------- report ----------------
function code(html) { return `<pre class="code">${html}</pre>`; }

function reportFinding(st, id, rep) {
  const f = st.findings[id], fd = f.finding;
  const [, label, col] = findingStatus(f);
  const last = f.attempts[f.attempts.length - 1];
  const attempts = f.attempts.map((a) => `<details ${a === last ? "open" : ""}><summary>
      <span class="chip ${a.passed ? "red" : "grey"}">attempt ${a.attempt}: ${a.passed ? "exploit works" : a.note?.startsWith("blocked") ? "blocked by firewall" : "did not work"}</span></summary>
      ${a.note && !a.passed ? `<div class="muted small">${esc(a.note)}</div>` : ""}
      ${a.output ? code(esc(a.output)) : ""}</details>`).join("");
  const p = f.patch;
  const ba = `<div class="ba">
    <div class="ba-box red"><div class="k">before patch</div><div class="v">${f.attempts.some((a) => a.confirmed) ? "exploit PASSES &rarr; bug confirmed" : "exploit not demonstrated"}</div></div>
    <div class="arrow">&rarr;</div>
    <div class="ba-box ${p?.applied ? "green" : "grey"}"><div class="k">after patch</div><div class="v">${p ? (p.applied ? "exploit FAILS &middot; existing suite green" : "patch not accepted") : "no patch attempted"}</div></div></div>`;
  const cites = f.citations.length ? `<h4>Sources (Tavily)</h4><ul class="cites">${f.citations.map((c) =>
    `<li><a href="${esc(c.url)}" target="_blank" rel="noopener noreferrer">${esc(c.title || c.url)}</a><div class="muted small">${esc(c.snippet)}</div></li>`).join("")}</ul>` : "";
  return `<article class="card finding ${col}"><div class="row">${sevChip(fd.severity)}<b>${esc(fd.title)}</b><span class="chip ${col}">${label}</span></div>
    <div class="muted mono">${esc(fd.file)}${fd.function ? " :: " + esc(fd.function) : ""}</div>
    <p>${esc(fd.description)}</p><h4>Attack</h4><p>${esc(fd.attack)}</p>
    ${ba}
    <h4>Proof of concept <small>${f.attempts.length} attempt(s)</small></h4>${attempts || '<div class="empty">none</div>'}
    ${last?.code ? `<details open><summary>PoC code (${esc(last.test_file)})</summary>${code(solidity(last.code))}</details>` : ""}
    ${p?.diff ? `<h4>Patch <small>${p.attempts} attempt(s)</small></h4>${p.note ? `<p class="muted">${esc(p.note)}</p>` : ""}${code(diff(p.diff))}` : ""}
    ${cites}</article>`;
}

export function report(st, rep) {
  const ids = st.order.filter((id) => st.findings[id].finding)
    .sort((a, b) => SEV[st.findings[a].finding.severity] - SEV[st.findings[b].finding.severity]);
  const llm = {};
  for (const c of st.llm) { const k = `${c.provider} / ${c.model}`; (llm[k] ||= { n: 0, p: 0, c: 0, s: 0 }); llm[k].n++; llm[k].p += c.prompt_tokens; llm[k].c += c.completion_tokens; llm[k].s += c.latency_s; }
  const rows = Object.entries(llm).map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td>${v.n}</td><td>${v.p.toLocaleString()}</td><td>${v.c.toLocaleString()}</td><td>${v.s.toFixed(2)}s</td></tr>`).join("");
  return `${ids.length ? ids.map((id) => reportFinding(st, id, rep)).join("") : '<div class="empty">No findings.</div>'}
    <h2>Model calls</h2><div class="tablewrap"><table><tr><th>provider / model</th><th>calls</th><th>prompt tok</th><th>completion tok</th><th>time</th></tr>${rows || '<tr><td colspan="5" class="muted">none</td></tr>'}</table></div>`;
}

// ---------------- firewall ----------------
function quarantineFile(file, text, spans) {
  const lines = text.split("\n");
  const inSpan = (n) => spans.some((s) => n >= s.start_line && n <= s.end_line);
  return `<div class="qfile"><div class="qname mono">${esc(file)} <span class="chip red">${spans.length} span(s) quarantined</span></div>
    <pre class="code qsrc">${lines.map((l, i) => `<span class="ln">${i + 1}</span><span class="${inSpan(i + 1) ? "qhit" : ""}">${esc(l)}</span>`).join("\n")}</pre>
    ${spans.map((s) => `<div class="muted small">lines ${s.start_line}-${s.end_line}: ${esc(s.detector)} detector &mdash; ${esc(s.reason)}. The agent saw a <code>[REDACTED]</code> placeholder instead.</div>`).join("")}</div>`;
}

export function firewall(st, rep) {
  const byFile = {};
  for (const q of st.quarantines) (byFile[q.file] ||= []).push(q);
  const files = Object.entries(byFile).map(([f, spans]) => {
    const text = rep?.quarantine_files?.[f];
    return text ? quarantineFile(f, text, spans) :
      `<div class="qfile"><div class="qname mono">${esc(f)}</div>${spans.map((s) => `<pre class="code"><span class="qhit">${esc(s.excerpt)}</span></pre><div class="muted small">lines ${s.start_line}-${s.end_line}: ${esc(s.detector)} &mdash; ${esc(s.reason)}</div>`).join("")}</div>`;
  }).join("");
  const denied = st.fw.filter((f) => f.verdict === "deny");
  const lat = latencyByLayer(st);
  const maxMean = Math.max(...lat.map((l) => l.mean), 0.001);
  const LNAME = { L1: "L1 deterministic rules", L2: "L2 Nemotron policy", scanner: "scanner" };
  return `<h2>Quarantined input <small>${st.quarantines.length} span(s)</small></h2>${files || '<div class="empty">Nothing quarantined.</div>'}
    <h2>Blocked actions <small>${denied.length}</small></h2>
    ${denied.length ? `<div class="feed">${denied.map((f) => `<div class="fw deny"><span class="vd">DENY</span><span class="chip lay">${esc(f.layer)}</span>
      <span class="mono act">${esc(f.kind)} ${esc(f.action)}</span><span class="why">${esc(f.rule)} &mdash; ${esc(f.reason)}</span>
      <span class="meta">${fmtMs(f.latency_ms)}</span></div>`).join("")}</div>` : '<div class="empty">No actions were blocked in this run.</div>'}
    <h2>Latency by layer</h2><div class="tablewrap"><table><tr><th>layer</th><th>decisions</th><th>mean</th><th>p50</th><th>max</th><th></th></tr>
    ${lat.map((l) => `<tr><td>${esc(LNAME[l.layer] || l.layer)}</td><td>${l.n}</td><td>${fmtMs(l.mean)}</td><td>${fmtMs(l.p50)}</td><td>${fmtMs(l.max)}</td>
      <td class="barcell"><div class="bar" style="width:${Math.max(2, (l.mean / maxMean) * 100)}%"></div></td></tr>`).join("") || '<tr><td colspan="6" class="muted">no decisions</td></tr>'}</table></div>`;
}
