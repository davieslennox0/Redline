import { emptyState, reduce, fromEvents } from "./state.js";
import { banner, header, live, report, firewall } from "./views.js";

const $ = (s) => document.querySelector(s);
const EXPORT = window.__REDLINE_DATA__ || null;
let st = emptyState(), rep = null, view = "live", es = null, runs = [], runId = null, timer = null;

function shell() {
  $("#app").innerHTML = `<header class="top"><div class="brand"><span class="logo">&#9632;</span> REDLINE</div>
    <div class="ctl">${EXPORT ? "" : `<select id="runsel"></select>`}<button id="replay" title="Replay this run">&#9654; Replay</button></div></header>
    <nav class="tabs"><button data-v="live">Live</button><button data-v="report">Report</button><button data-v="firewall">Firewall</button></nav>
    <main><div id="banner"></div><div id="hdr"></div><div id="view"></div></main>`;
  document.querySelectorAll(".tabs button").forEach((b) => b.onclick = () => { view = b.dataset.v; history.replaceState(null, "", `#${runId || ""}/${view}`); paint(); });
  $("#replay").onclick = () => start(true);
  if (!EXPORT) $("#runsel").onchange = (e) => { runId = e.target.value; history.replaceState(null, "", `#${runId}/${view}`); start(true); };
}

let raf = 0;
function schedule() { if (!raf) raf = requestAnimationFrame(() => { raf = 0; paint(); }); }
function paint() {
  document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("on", b.dataset.v === view));
  $("#banner").innerHTML = banner(st);
  $("#hdr").innerHTML = header(st);
  const v = $("#view"), y = window.scrollY;
  v.innerHTML = view === "live" ? live(st) : view === "report" ? report(st, rep) : firewall(st, rep);
  window.scrollTo(0, y);
}

function clamp(d) { return Math.min(Math.max(d, 0.15), 2.5); }

function replayLocal(events) {
  st = emptyState();
  let i = 0, prev = null;
  const next = () => {
    if (i >= events.length) return;
    const e = events[i++];
    const wait = prev === null ? 0 : clamp(e.ts - prev) * 1000;
    prev = e.ts;
    timer = setTimeout(() => { reduce(st, e); schedule(); next(); }, wait);
  };
  next();
}

async function start(replay) {
  if (es) { es.close(); es = null; }
  clearTimeout(timer);
  st = emptyState(); rep = null; paint();
  if (EXPORT) { rep = EXPORT.report; replay ? replayLocal(EXPORT.events) : (st = fromEvents(EXPORT.events), paint()); return; }
  if (!runId) return;
  const data = await (await fetch(`/runs/${encodeURIComponent(runId)}`)).json();
  rep = data.report;
  es = new EventSource(`/runs/${encodeURIComponent(runId)}/stream`);
  const types = ["run_started", "stage_started", "stage_finished", "finding_added", "poc_result", "patch_result", "firewall_decision", "input_quarantined", "llm_call", "run_finished"];
  for (const t of types) es.addEventListener(t, (m) => { reduce(st, JSON.parse(m.data)); schedule(); });
  es.addEventListener("end", () => { es.close(); fetch(`/runs/${encodeURIComponent(runId)}`).then((r) => r.json()).then((d) => { rep = d.report; schedule(); }); });
}

async function boot() {
  shell();
  const [h, v] = location.hash.slice(1).split("/");
  if (["live", "report", "firewall"].includes(v)) view = v;
  if (EXPORT) { runId = EXPORT.id; st = fromEvents(EXPORT.events); rep = EXPORT.report; paint(); return; }
  runs = await (await fetch("/runs")).json();
  $("#runsel").innerHTML = runs.map((r) => `<option value="${r.id}">${r.id}${r.scripted ? " (SAMPLE)" : ""} - ${r.status}</option>`).join("");
  runId = runs.find((r) => r.id === h)?.id || runs[0]?.id;
  if (runId) $("#runsel").value = runId;
  if (!runId) { $("#view").innerHTML = `<div class="empty">No runs yet. Run <code>redline audit</code> or <code>python scripts/gen_samples.py</code>.</div>`; return; }
  start(true);
}
boot();
