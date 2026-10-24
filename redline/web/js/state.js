// Pure reducer: events -> view state. The same code runs live (SSE), on replay and in the export.
export const STAGES = ["baseline", "scan", "recon", "research", "exploit", "patch"];

export function emptyState() {
  return {
    run: null, finished: null, t0: null, tNow: null,
    stages: Object.fromEntries(STAGES.map((s) => [s, { status: "pending", runs: [] }])),
    findings: {}, order: [], fw: [], quarantines: [], llm: [],
  };
}

function finding(st, id) {
  if (!st.findings[id]) {
    st.findings[id] = { finding: null, attempts: [], patch: null, citations: [], stage: {} };
    st.order.push(id);
  }
  return st.findings[id];
}

export function reduce(st, e) {
  st.tNow = e.ts;
  if (st.t0 === null) st.t0 = e.ts;
  switch (e.type) {
    case "run_started": st.run = e; break;
    case "stage_started": {
      const s = st.stages[e.stage];
      s.runs.push({ id: e.finding_id, status: "running" });
      if (e.finding_id) finding(st, e.finding_id).stage[e.stage] = "running";
      s.status = "running";
      break;
    }
    case "stage_finished": {
      const s = st.stages[e.stage];
      const r = [...s.runs].reverse().find((x) => x.id === e.finding_id && x.status === "running");
      if (r) Object.assign(r, { status: e.ok ? "ok" : "fail", detail: e.detail, duration_s: e.duration_s });
      s.status = s.runs.some((x) => x.status === "running") ? "running"
        : s.runs.every((x) => x.status === "ok") ? "ok" : "fail";
      if (e.finding_id) {
        const f = finding(st, e.finding_id);
        f.stage[e.stage] = e.ok ? "ok" : "fail";
        if (e.citations?.length) f.citations = e.citations;
      }
      break;
    }
    case "finding_added": finding(st, e.finding.id).finding = e.finding; break;
    case "poc_result": finding(st, e.finding_id).attempts.push(e); break;
    case "patch_result": finding(st, e.finding_id).patch = e; break;
    case "firewall_decision": st.fw.push(e); break;
    case "input_quarantined": st.quarantines.push(e); break;
    case "llm_call": st.llm.push(e); break;
    case "run_finished": st.finished = e; break;
  }
  return st;
}

export function fromEvents(events) {
  const st = emptyState();
  for (const e of events) reduce(st, e);
  return st;
}

export function totals(st) {
  const tok = st.llm.reduce((a, c) => a + c.prompt_tokens + c.completion_tokens, 0);
  const providers = [...new Set(st.llm.map((c) => c.provider).concat(st.run ? [st.run.provider] : []))];
  const confirmed = st.order.filter((id) => st.findings[id].attempts.some((a) => a.confirmed)).length;
  const fixed = st.order.filter((id) => st.findings[id].patch?.applied).length;
  const dur = st.finished ? st.finished.duration_s : (st.tNow && st.t0 ? st.tNow - st.t0 : 0);
  return {
    findings: st.order.filter((id) => st.findings[id].finding).length, confirmed, fixed,
    tokens: tok, calls: st.llm.length, providers, duration_s: dur,
    denies: st.fw.filter((f) => f.verdict === "deny").length, allows: st.fw.filter((f) => f.verdict === "allow").length,
    quarantined: st.quarantines.length,
  };
}

export function latencyByLayer(st) {
  const by = {};
  for (const f of st.fw) (by[f.layer] ||= []).push(f.latency_ms);
  return Object.entries(by).map(([layer, a]) => {
    a.sort((x, y) => x - y);
    const sum = a.reduce((x, y) => x + y, 0);
    return { layer, n: a.length, mean: sum / a.length, p50: a[Math.floor(a.length / 2)], max: a[a.length - 1] };
  }).sort((x, y) => x.layer.localeCompare(y.layer));
}
