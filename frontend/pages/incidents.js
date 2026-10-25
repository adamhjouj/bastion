"use strict";
/* Incidents page — the case file.
   Left: live, filterable incident list (snapshot.incidents, newest-first) with severity
   chips + text search, and "Load older" paging via /incidents?before=&limit=.
   Right: the whole story of one incident (/incidents/{id}): header, the Jev verdict from
   the case's triage records, summary, evidence, triggering requests, then the trace —
   every tool call in order (read-only calls quiet, containment prominent, each expandable
   to its input + result), rollback controls (POST /actions/{id}/rollback, hidden until
   /rollback/capabilities exists), and the alert status.
   Deep links: #/incidents/<id> selects; selection keeps location.hash in sync via replace.
   Orange is reserved for high/critical severity, malicious verdicts and rejected/errored calls. */

import { store, api, post, el, clear, clip, humanize, fmt, fmtScore, hhmmss, anim, reduceMotion } from "../core.js";

const SEVS = ["all", "critical", "high", "medium", "low"];
const PAGE_SIZE = 50;
const MAX_TRIAGE_FETCH = 8;
const EASE = "cubic-bezier(0.22, 1, 0.36, 1)";
const READ_ONLY = new Set(["inspect_target", "get_defenses", "recent_requests", "recent_incidents", "service_status", "list_processes", "list_sessions"]);
const CHEVRON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg>';

const TEMPLATE = `
<div class="inc">
  <section class="panel inc-list" aria-label="Incident log">
    <div class="panel-head"><h2>Incidents</h2><span class="count" data-count>0</span></div>
    <div class="inc-tools">
      <input class="inc-search" data-search type="text" placeholder="Filter type or source" spellcheck="false" autocomplete="off" aria-label="Filter incidents">
      <div class="chips" data-chips role="group" aria-label="Severity filter">
        ${SEVS.map((s) => `<button class="chip${s === "all" ? " on" : ""}" type="button" data-sev="${s}">${s}</button>`).join("")}
      </div>
    </div>
    <div class="panel-body inc-rows" data-rows><div class="empty">Connecting…</div></div>
  </section>
  <section class="panel inc-det" aria-label="Case file">
    <div class="panel-head det-head">
      <div class="det-title"><span class="sev" data-det-sev hidden></span><h2 data-det-type>Case file</h2></div>
      <span class="tag" data-det-case hidden></span>
    </div>
    <div class="panel-body det-body" data-det><div class="empty">Connecting…</div></div>
  </section>
</div>`;

/* ---------- small builders ---------- */
function kv(cap, value, mono, hot) {
  const d = el("div");
  d.appendChild(el("span", "cap", cap));
  d.appendChild(el("span", "v" + (mono ? " mono" : "") + (hot ? " hot" : ""), value || "—"));
  return d;
}
function section(title, count) {
  const s = el("div", "sec");
  if (count == null) { s.appendChild(el("span", "cap", title)); return s; }
  const h = el("div", "sec-head"); h.appendChild(el("span", "cap", title)); h.appendChild(el("span", "count", count)); s.appendChild(h);
  return s;
}
function pretty(v) {
  if (v == null) return "—";
  if (typeof v === "string") return v;
  try { return JSON.stringify(v, null, 2); } catch (_) { return String(v); }
}
function caseIds(caseId) { return String(caseId || "").split(",").map((p) => p.trim()).filter((p) => /^\d+$/.test(p)); }

/* ---------- operator language for tool calls ---------- */
function ipList(inp) { return Array.isArray(inp.ips) ? inp.ips : inp.ip ? [inp.ip] : []; }
function sources(inp) { const ips = ipList(inp); return ips.length === 1 ? ips[0] : ips.length ? fmt(ips.length) + " sources" : "source"; }
const PHRASES = {
  blacklist_ip: (i, ok) => (ok ? "Banned " : "Ban ") + sources(i),
  bulk_blacklist_ip: (i, ok) => (ok ? "Banned " : "Ban ") + sources(i),
  unban_ip: (i, ok) => (ok ? "Unbanned " : "Unban ") + sources(i),
  divert_to_honeypot: (i, ok) => (ok ? "Diverted " : "Divert ") + sources(i) + " to the honeypot",
  undivert: (i, ok) => (ok ? "Stopped diverting " : "Stop diverting ") + sources(i),
  virtual_patch: (i, ok) => (ok ? "Virtual-patched " : "Virtual-patch ") + (i.path || "route") + (i.attack_type ? " against " + humanize(i.attack_type) : ""),
  patch_vuln: (i) => "Set app security level to " + (i.level || "—"),
  quarantine_container: (i, ok) => (ok ? "Quarantined " : "Quarantine ") + (i.target || "container"),
  release_container: (i, ok) => (ok ? "Released " : "Release ") + (i.target || "container"),
  isolate_egress: (i) => "Cut egress for " + (i.target || "container"),
  reconnect_egress: (i, ok) => (ok ? "Reconnected egress for " : "Reconnect egress for ") + (i.target || "container"),
  kill_process: (i, ok) => (ok ? "Killed process " : "Kill process ") + (i.pid != null ? i.pid : "") + (i.target ? " on " + i.target : ""),
  kill_session: (i, ok) => (ok ? "Killed session " : "Kill session ") + (i.session_id || ""),
  rotate_secret: (i, ok) => (ok ? "Rotated secret" : "Rotate secret") + (i.target ? " on " + i.target : ""),
  raise_alert: (i, ok) => (ok ? "Filed this incident" : "File incident") + (i.severity ? " as " + i.severity : "") + " and queued the report",
  inspect_target: (i) => "Inspected " + ((i.method || "GET") + " " + (i.path || "")).trim(),
  get_defenses: () => "Read the active defenses",
  recent_requests: (i) => "Read recent requests" + (i.limit ? " (" + fmt(i.limit) + ")" : ""),
  recent_incidents: () => "Read recent incidents",
  service_status: () => "Checked service status",
  list_processes: (i) => "Listed processes" + (i.target ? " on " + i.target : ""),
  list_sessions: (i) => "Listed sessions" + (i.target ? " on " + i.target : ""),
};
/* a compensating action names what it undid: "Reverted #12: unbanned 203.0.113.9" */
function inversePhrase(inverse, inp) {
  const f = PHRASES[inverse];
  if (f) { const s = f(inp, true); return s.charAt(0).toLowerCase() + s.slice(1); }
  if (inverse === "remove" || inverse === "restore") return (inverse === "remove" ? "removed the virtual patch on " : "restored ") + (inp.path || inp.level || inp.tool || "");
  return "ran " + humanize(inverse || inp.tool || "the inverse");
}
function phrase(a) {
  const inp = a.input || {}, ok = a.outcome === "ok";
  if (a.tool === "rollback") return "Reverted #" + (a.reverts != null ? a.reverts : inp.reverts != null ? inp.reverts : "?") + ": " + inversePhrase(inp.inverse, inp);
  const f = PHRASES[a.tool];
  return f ? f(inp, ok) : humanize(a.tool || "action") || "action";
}
/* what a rollback will do, stated before the operator confirms it */
function effect(a, inverse) {
  const i = a.input || {};
  switch (a.tool) {
    case "blacklist_ip": case "bulk_blacklist_ip": return "Unban " + sources(i) + ": requests from " + (ipList(i).length === 1 ? "this source" : "these sources") + " reach the app again.";
    case "divert_to_honeypot": return "Stop diverting " + sources(i) + ": its requests reach the real app again instead of the decoy.";
    case "virtual_patch": return "Remove the virtual patch on " + (i.path || "this route") + ": the proxy stops blocking the exploit there.";
    case "patch_vuln": return "Restore the previous app security level: the hardened code path is switched off.";
    case "quarantine_container": return "Release " + (i.target || "the container") + " from quarantine.";
    case "isolate_egress": return "Reconnect egress for " + (i.target || "the container") + ".";
    default: return "Run " + humanize(inverse || "the inverse") + " against this action.";
  }
}

export function mount(root, ctx) {
  const page = el("div", "page p-incidents");
  page.innerHTML = TEMPLATE;
  root.appendChild(page);

  const rowsEl = page.querySelector("[data-rows]");
  const countEl = page.querySelector("[data-count]");
  const searchEl = page.querySelector("[data-search]");
  const chipsEl = page.querySelector("[data-chips]");
  const detBody = page.querySelector("[data-det]");
  const detSev = page.querySelector("[data-det-sev]");
  const detType = page.querySelector("[data-det-type]");
  const detCase = page.querySelector("[data-det-case]");

  /* ---------- state ---------- */
  const byId = new Map();     // id -> incident
  const nodeById = new Map(); // id -> row node
  let order = [];             // ids, newest first
  let selectedId = null;
  let sevFilter = "all";
  let query = "";
  let lastTotal = 0;
  let exhausted = false;      // server said no older pages
  let loadingMore = false;
  let firstPaint = true;
  let detToken = 0;
  let alive = true;
  const hashSync = !!ctx;     // only a router that hands us ctx understands #/incidents/<id>
  let rollback = null;        // /rollback/capabilities payload, or null when the backend has not landed
  const rollbackReady = api("/rollback/capabilities").then((d) => { rollback = d && d.inverse ? d : null; }, () => { rollback = null; });

  const moreBtn = el("button", "more", "Load older");
  moreBtn.type = "button";
  moreBtn.addEventListener("click", loadOlder);

  function hasMore() { return !exhausted && lastTotal > byId.size; }
  function reorder() { order = [...byId.keys()].sort((a, b) => b - a); }
  function matches(inc) {
    if (sevFilter !== "all" && inc.severity !== sevFilter) return false;
    if (!query) return true;
    return (humanize(inc.attack_type) + " " + (inc.source_ip || "")).toLowerCase().includes(query);
  }
  function parseSub(sub) { const m = String(sub || "").match(/^(\d+)/); return m ? Number(m[1]) : null; }
  function syncHash(id) {
    if (!hashSync) return;
    const want = "#/incidents/" + id;
    if (location.hash !== want) location.replace(want);
  }

  /* ---------- list ---------- */
  function makeRow(inc) {
    const row = el("button", "row"); row.type = "button";
    const top = el("div", "row-top");
    const sev = el("span", "sev"); sev.dataset.sev = inc.severity || ""; top.appendChild(sev);
    top.appendChild(el("span", "row-type", clip(humanize(inc.attack_type) || "incident", 64)));
    top.appendChild(el("time", "row-time", hhmmss(inc.ts)));
    row.appendChild(top);
    row.appendChild(el("div", "row-sub", inc.source_ip || "unknown source"));
    row.addEventListener("click", () => select(inc.id));
    return row;
  }

  function renderList(animateNew) {
    const frag = document.createDocumentFragment();
    let shown = 0;
    for (const id of order) {
      const inc = byId.get(id);
      if (!matches(inc)) continue;
      let node = nodeById.get(id), fresh = false;
      if (!node) { node = makeRow(inc); nodeById.set(id, node); fresh = true; }
      node.classList.toggle("sel", id === selectedId);
      if (id === selectedId) node.setAttribute("aria-current", "true"); else node.removeAttribute("aria-current");
      frag.appendChild(node); shown++;
      if (fresh && animateNew && !reduceMotion)
        anim(node, [{ opacity: 0, transform: "translateY(6px)" }, { opacity: 1, transform: "none" }], { duration: 220, easing: EASE });
    }
    clear(rowsEl);
    if (shown) {
      rowsEl.appendChild(frag);
      if (hasMore()) { moreBtn.disabled = loadingMore; moreBtn.textContent = loadingMore ? "Loading…" : "Load older"; rowsEl.appendChild(moreBtn); }
    } else {
      rowsEl.appendChild(el("div", "empty", byId.size ? "No matching incidents." : "No incidents filed."));
    }
    countEl.textContent = (sevFilter !== "all" || query) ? fmt(shown) + " / " + fmt(lastTotal) : fmt(lastTotal);
  }

  async function loadOlder() {
    if (loadingMore || !hasMore()) return;
    loadingMore = true; renderList(false);
    const before = order.length ? order[order.length - 1] : "";
    try {
      const d = await api("/incidents?before=" + before + "&limit=" + PAGE_SIZE);
      if (!alive) return;
      const items = (d && d.items) || [];
      for (const it of items) byId.set(it.id, it);
      if (d && d.next_cursor == null) exhausted = true;
      reorder();
    } catch (_) { /* keep button for retry */ }
    if (!alive) return;
    loadingMore = false;
    renderList(false);
  }

  /* ---------- detail ---------- */
  function setDetailHead(inc) {
    if (!inc) { detSev.hidden = true; detCase.hidden = true; detType.textContent = "Case file"; return; }
    detSev.hidden = false; detSev.dataset.sev = inc.severity || "";
    detType.textContent = humanize(inc.attack_type) || "Incident";
    if (inc.id != null) { detCase.hidden = false; detCase.textContent = "case " + inc.id; } else detCase.hidden = true;
  }
  function setDetailEmpty(msg) {
    detToken++;
    setDetailHead(null);
    clear(detBody);
    detBody.appendChild(el("div", "empty", msg));
  }

  function select(id, opts) {
    if (id == null || !isFinite(id)) return;
    if (id === selectedId) { if (!(opts && opts.quiet)) syncHash(id); return; }
    selectedId = id;
    for (const [k, n] of nodeById) {
      const on = k === selectedId;
      n.classList.toggle("sel", on);
      if (on) n.setAttribute("aria-current", "true"); else n.removeAttribute("aria-current");
    }
    if (!(opts && opts.quiet)) syncHash(id);
    loadDetail(id);
  }

  async function loadDetail(id) {
    const tok = ++detToken;
    detBody.classList.add("busy");
    let data = null;
    try { data = await api("/incidents/" + id); } catch (_) {}
    if (!alive || tok !== detToken) return;
    if (data && data.incident) {
      /* triage rows are keyed by event id, not by the (comma-list) case id: fetch the ones missing */
      const have = new Set((data.actions || []).map((a) => a.id));
      const ids = caseIds(data.incident.case_id).filter((i) => i !== String(data.incident.case_id)).slice(0, MAX_TRIAGE_FETCH);
      const pages = await Promise.all(ids.map((i) => api("/actions?case_id=" + i + "&limit=20").catch(() => null)));
      if (!alive || tok !== detToken) return;
      for (const p of pages) for (const a of (p && p.items) || []) if (a.kind === "triage" && !have.has(a.id)) { have.add(a.id); data.actions.push(a); }
    }
    await rollbackReady;
    if (!alive || tok !== detToken) return;
    detBody.classList.remove("busy");
    renderDetail(data);
  }

  function renderDetail(data) {
    const inc = (data && data.incident) || null;
    clear(detBody);
    if (!inc) { setDetailHead(null); detBody.appendChild(el("div", "empty", "Could not load incident.")); return; }
    setDetailHead(inc);

    const hot = inc.severity === "high" || inc.severity === "critical";
    const meta = el("div", "kv");
    meta.appendChild(kv("Severity", inc.severity, false, hot));
    meta.appendChild(kv("Source", inc.source_ip, true));
    meta.appendChild(kv("Filed", hhmmss(inc.ts), true));
    meta.appendChild(kv("Case", inc.case_id, true));
    detBody.appendChild(meta);

    const all = (data.actions || []).slice().sort((a, b) => (a.id || 0) - (b.id || 0));
    detBody.appendChild(renderVerdict(all.filter((a) => a.kind === "triage")));

    if (inc.summary) { const s = section("Summary"); s.appendChild(el("p", "prose", inc.summary)); detBody.appendChild(s); }
    if (inc.evidence) { const s = section("Evidence"); s.appendChild(el("pre", "evidence", inc.evidence)); detBody.appendChild(s); }

    const reqs = data.requests || [];
    if (reqs.length) {
      const s = section("Triggering requests", fmt(reqs.length)); const mini = el("div", "mini");
      for (const r of reqs) {
        const row = el("div", "m-row");
        row.appendChild(el("time", null, hhmmss(r.ts)));
        row.appendChild(el("span", "m-name mono", clip((r.method || "") + " " + (r.path || "") + (r.query ? "?" + r.query : ""), 58)));
        row.appendChild(el("span", "m-out", r.status == null ? "—" : String(r.status)));
        mini.appendChild(row);
      }
      s.appendChild(mini); detBody.appendChild(s);
    }

    detBody.appendChild(renderTrace(all));

    const notes = data.notifications || [];
    const s = section("Report");
    if (!notes.length) s.appendChild(el("div", "det-note", "No report queued for this case."));
    for (const n of notes) {
      const pill = el("div", "status-pill");
      pill.dataset.ok = n.status === "accepted" || n.status === "delivered" ? "1" : "0";
      pill.appendChild(el("span", "d"));
      pill.appendChild(el("span", null, "email " + (n.status || "unknown") + (n.provider ? " · " + n.provider : "") + (n.queued_at ? " · queued " + hhmmss(n.queued_at) : "") + (n.error ? " · " + clip(n.error, 80) : "")));
      s.appendChild(pill);
    }
    detBody.appendChild(s);

    if (reduceMotion) anim(detBody, [{ opacity: 0 }, { opacity: 1 }], { duration: 120, easing: "ease-out" });
    else anim(detBody, [{ opacity: 0, transform: "translateY(4px)" }, { opacity: 1, transform: "none" }], { duration: 180, easing: EASE });
  }

  /* the verdict: the strongest Jev score among the case's triage records */
  function renderVerdict(triage) {
    const s = section("Jev verdict");
    const box = el("div", "verdict");
    if (!triage.length) {
      box.classList.add("none");
      box.appendChild(el("span", "verdict-main", "No triage record on file for this case."));
      s.appendChild(box); return s;
    }
    const lead = triage.reduce((best, t) => ((t.jev || {}).malicious_score || 0) >= ((best.jev || {}).malicious_score || 0) ? t : best, triage[0]);
    const v = lead.jev || {};
    const score = el("span", "verdict-score" + (v.malicious ? " hot" : ""), fmtScore(v.malicious_score));
    box.appendChild(score);
    const txt = el("div", "verdict-text");
    txt.appendChild(el("div", "verdict-main", (v.malicious ? "Malicious · " : "Not malicious · ") + (humanize(v.attack_type) || "unclassified") + (typeof v.type_confidence === "number" ? " · confidence " + fmtScore(v.type_confidence) : "")));
    const esc = triage.filter((t) => t.escalated).length;
    const parts = [fmt(triage.length) + (triage.length === 1 ? " request scored" : " requests scored"), esc ? (esc === triage.length ? "escalated to the agent" : fmt(esc) + " escalated to the agent") : "not escalated"];
    if (v.model) parts.push(v.model);
    txt.appendChild(el("div", "verdict-sub", parts.join(" · ")));
    box.appendChild(txt);
    s.appendChild(box);
    return s;
  }

  /* ---------- the trace: every triage record, tool call and agent error, in order ---------- */
  function renderTrace(all) {
    const items = all.filter((a) => a.kind === "triage" || a.kind === "action" || a.kind === "error");
    const calls = items.filter((a) => a.kind === "action").length;
    const s = section("Trace", calls ? fmt(calls) + (calls === 1 ? " call" : " calls") : "0 calls");
    s.classList.add("trace-sec");
    const box = el("div", "trace");
    if (!items.length) { box.appendChild(el("div", "empty", "The agent has not acted on this case.")); s.appendChild(box); return s; }
    for (const a of items) box.appendChild(traceLine(a));
    s.appendChild(box);
    return s;
  }

  function traceLine(a) {
    const line = el("div", "line tl");
    if (a.id != null) line.dataset.aid = String(a.id);
    line.appendChild(el("time", null, hhmmss(a.ts)));
    const b = el("div", "body");
    line.appendChild(b);

    const head = el("button", "tl-head"); head.type = "button"; head.setAttribute("aria-expanded", "false");
    const title = el("span", "tl-title");
    const out = el("span", "tl-out");
    const chev = el("span", "tl-chev"); chev.innerHTML = CHEVRON;
    head.appendChild(title); head.appendChild(out); head.appendChild(chev);
    b.appendChild(head);

    const detail = el("div", "tl-detail"); detail.hidden = true;
    const metaBits = [];

    if (a.kind === "triage") {
      const v = a.jev || {};
      line.classList.add("quiet");
      title.textContent = "Jev scored " + clip((a.path || "request"), 48) + (v.attack_type ? " as " + humanize(v.attack_type) : "");
      out.textContent = fmtScore(v.malicious_score);
      if (v.malicious) out.classList.add("bad");
      metaBits.push("triage", a.ip, a.escalated ? "escalated" : "not escalated");
      addBlock(detail, "Verdict", pretty(v));
    } else if (a.kind === "error") {
      line.classList.add("bad");
      title.textContent = "Agent error";
      out.textContent = "error"; out.classList.add("bad");
      b.appendChild(el("div", "tl-why", clip(a.error || "agent error", 240)));
      metaBits.push("agent", a.id != null ? "#" + a.id : "");
      addBlock(detail, "Error", a.error || "—");
    } else {
      const ok = a.outcome === "ok", comp = a.tool === "rollback", quiet = READ_ONLY.has(a.tool);
      line.classList.add(quiet ? "quiet" : "act");
      if (comp) line.classList.add("comp");
      if (!ok) line.classList.add("bad");
      if (a.reverted_by != null) line.classList.add("reverted");
      title.textContent = phrase(a);
      out.textContent = a.outcome || "—";
      if (!ok) out.classList.add("bad");
      const inp = a.input || {};
      if (!quiet && inp.reason) b.appendChild(el("div", "tl-why", clip(inp.reason, 260)));
      metaBits.push(a.tool || "action", a.id != null ? "#" + a.id : "");
      addBlock(detail, "Input", pretty(inp));
      addBlock(detail, "Result", pretty(a.result));
    }

    const meta = el("div", "meta");
    for (const bit of metaBits.filter(Boolean)) { if (meta.childNodes.length) meta.appendChild(document.createTextNode(" · ")); meta.appendChild(document.createTextNode(bit)); }
    if (a.kind === "action" && a.reverted_by != null) {
      meta.appendChild(document.createTextNode(" · reverted by "));
      meta.appendChild(linkTo(a.reverted_by));
    } else if (a.kind === "action" && a.tool === "rollback") {
      const target = a.reverts != null ? a.reverts : (a.input || {}).reverts;
      if (target != null) { meta.appendChild(document.createTextNode(" · reverts ")); meta.appendChild(linkTo(target)); }
    }
    b.appendChild(meta);
    b.appendChild(detail);

    head.addEventListener("click", () => setExpanded(line, detail.hidden));
    /* the whole row is a toggle; let real controls and the open detail handle their own clicks */
    line.addEventListener("click", (e) => { if (e.target.closest("a, button, input, .tl-detail")) return; setExpanded(line, detail.hidden); });

    if (a.kind === "action" && rollback && a.reversible && a.reverted_by == null) b.appendChild(revertControls(a));
    return line;
  }
  function addBlock(detail, cap, text) { detail.appendChild(el("span", "cap", cap)); detail.appendChild(el("pre", "evidence", text)); }
  function setExpanded(line, on) {
    const head = line.querySelector(".tl-head"), detail = line.querySelector(".tl-detail");
    detail.hidden = !on; head.setAttribute("aria-expanded", on ? "true" : "false"); line.classList.toggle("open", on);
  }
  function linkTo(id) {
    const btn = el("button", "tl-link", "#" + id); btn.type = "button";
    btn.addEventListener("click", () => {
      const target = detBody.querySelector('.tl[data-aid="' + id + '"]');
      if (!target) return;
      setExpanded(target, true);
      target.scrollIntoView({ block: "center", behavior: reduceMotion ? "auto" : "smooth" });
      if (!reduceMotion) anim(target, [{ background: "var(--raised)" }, { background: "transparent" }], { duration: 700, easing: "ease-out" });
    });
    return btn;
  }

  /* Revert → inline confirm stating the effect → POST rollback → reload the case file */
  function revertControls(a) {
    const wrap = el("div", "tl-revert");
    const btn = el("button", "btn", "Revert"); btn.type = "button";
    const confirm = el("div", "tl-confirm"); confirm.hidden = true;
    const inverse = (rollback.inverse || {})[a.tool];
    confirm.appendChild(el("p", "tl-effect", effect(a, inverse) + " The original stays in the log; a compensating action is recorded" + (inverse ? " (" + humanize(inverse) + ")" : "") + "."));
    const row = el("div", "tl-confirm-row");
    const yes = el("button", "btn danger", "Confirm revert"); yes.type = "button";
    const no = el("button", "btn", "Cancel"); no.type = "button";
    row.appendChild(yes); row.appendChild(no); confirm.appendChild(row);
    const err = el("div", "tl-err"); err.hidden = true; confirm.appendChild(err);
    wrap.appendChild(btn); wrap.appendChild(confirm);

    btn.addEventListener("click", () => { btn.hidden = true; confirm.hidden = false; err.hidden = true; yes.focus(); });
    no.addEventListener("click", () => { confirm.hidden = true; btn.hidden = false; btn.focus(); });
    yes.addEventListener("click", async () => {
      yes.disabled = true; no.disabled = true; yes.textContent = "Reverting…"; err.hidden = true;
      const tok = detToken;
      try {
        await post("/actions/" + a.id + "/rollback", { reason: "operator rollback from the case file" });
        if (!alive || tok !== detToken) return;
        loadDetail(selectedId);
      } catch (e) {
        if (!alive || tok !== detToken) return;
        const m = /\s(\d{3})$/.exec(String(e && e.message || "")), status = m ? m[1] : "";
        err.textContent = status === "409" ? "Not reverted: the action is no longer reversible (already reverted, or it did not succeed)."
          : status === "502" ? "The inverse operation failed downstream. The failed attempt was logged; nothing changed."
          : status === "404" ? "Not reverted: the action was not found."
          : "Not reverted: the request failed" + (status ? " (" + status + ")" : "") + ".";
        err.hidden = false;
        yes.disabled = false; no.disabled = false; yes.textContent = "Confirm revert";
      }
    });
    return wrap;
  }

  /* ---------- filters ---------- */
  searchEl.addEventListener("input", () => { query = searchEl.value.trim().toLowerCase(); renderList(false); });
  chipsEl.addEventListener("click", (e) => {
    const chip = e.target.closest(".chip"); if (!chip || chip.dataset.sev === sevFilter) return;
    sevFilter = chip.dataset.sev;
    chipsEl.querySelectorAll(".chip").forEach((c) => c.classList.toggle("on", c === chip));
    renderList(false);
  });

  /* ---------- deep link ---------- */
  const wanted = parseSub(ctx && ctx.sub);
  if (wanted != null) select(wanted, { quiet: true });

  /* ---------- live data ---------- */
  const unsub = store.subscribe((s) => {
    if (!s || !alive) return;
    lastTotal = s.incidents_total || 0;
    if (lastTotal < byId.size) { /* backend reset */
      byId.clear(); nodeById.clear(); order = []; exhausted = false; selectedId = null; firstPaint = true;
    }
    for (const it of s.incidents || []) byId.set(it.id, it);
    reorder();
    renderList(!firstPaint);
    firstPaint = false;
    if (selectedId == null) {
      if (order.length) select(order[0]);
      else setDetailEmpty("No incidents filed.");
    }
  });

  function unmount() { alive = false; detToken++; unsub(); }
  unmount.navigate = ({ sub } = {}) => {
    const id = parseSub(sub);
    if (id != null) select(id, { quiet: true });
    else if (selectedId != null) syncHash(selectedId);
  };
  return unmount;
}
