"use strict";
/* Incidents page — master–detail incident log.
   Left: live, filterable incident list (snapshot.incidents, newest-first) with severity
   chips + text search, and "Load older" paging via /incidents?before=&limit=.
   Right: full detail pane (/incidents/{id}) — meta, summary, evidence, triggering
   requests, response-action timeline, alert status. Newest incident auto-selected.
   Orange is reserved for high/critical severity and rejected/errored actions. */

import { store, api, el, clear, clip, humanize, fmt, hhmmss, anim, reduceMotion } from "../core.js";

const SEVS = ["all", "critical", "high", "medium", "low"];
const PAGE_SIZE = 50;
const EASE = "cubic-bezier(0.22, 1, 0.36, 1)";

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
  <section class="panel inc-det" aria-label="Incident detail">
    <div class="panel-head det-head">
      <div class="det-title"><span class="sev" data-det-sev hidden></span><h2 data-det-type>Incident</h2></div>
      <span class="tag" data-det-case hidden></span>
    </div>
    <div class="panel-body det-body" data-det><div class="empty">Connecting…</div></div>
  </section>
</div>`;

function kv(cap, value, mono, hot) {
  const d = el("div");
  d.appendChild(el("span", "cap", cap));
  d.appendChild(el("span", "v" + (mono ? " mono" : "") + (hot ? " hot" : ""), value || "—"));
  return d;
}
function section(title) { const s = el("div", "sec"); s.appendChild(el("span", "cap", title)); return s; }

export function mount(root) {
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
    if (!inc) { detSev.hidden = true; detCase.hidden = true; detType.textContent = "Incident"; return; }
    detSev.hidden = false; detSev.dataset.sev = inc.severity || "";
    detType.textContent = humanize(inc.attack_type) || "Incident";
    if (inc.case_id) { detCase.hidden = false; detCase.textContent = "case " + inc.case_id; } else detCase.hidden = true;
  }
  function setDetailEmpty(msg) {
    detToken++;
    setDetailHead(null);
    clear(detBody);
    detBody.appendChild(el("div", "empty", msg));
  }

  function select(id) {
    if (id === selectedId) return;
    selectedId = id;
    for (const [k, n] of nodeById) {
      const on = k === selectedId;
      n.classList.toggle("sel", on);
      if (on) n.setAttribute("aria-current", "true"); else n.removeAttribute("aria-current");
    }
    loadDetail(id);
  }

  async function loadDetail(id) {
    const tok = ++detToken;
    detBody.classList.add("busy");
    let data = null;
    try { data = await api("/incidents/" + id); } catch (_) {}
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

    if (inc.summary) { const s = section("Summary"); s.appendChild(el("p", "prose", inc.summary)); detBody.appendChild(s); }
    if (inc.evidence) { const s = section("Evidence"); s.appendChild(el("pre", "evidence", inc.evidence)); detBody.appendChild(s); }

    const reqs = data.requests || [];
    if (reqs.length) {
      const s = section("Triggering requests"); const mini = el("div", "mini");
      for (const r of reqs) {
        const row = el("div", "m-row");
        row.appendChild(el("time", null, hhmmss(r.ts)));
        row.appendChild(el("span", "m-name mono", clip((r.method || "") + " " + (r.path || "") + (r.query ? "?" + r.query : ""), 58)));
        row.appendChild(el("span", "m-out", r.status == null ? "—" : String(r.status)));
        mini.appendChild(row);
      }
      s.appendChild(mini); detBody.appendChild(s);
    }

    const acts = (data.actions || []).filter((a) => a.kind !== "triage").sort((a, b) => (a.id || 0) - (b.id || 0));
    if (acts.length) {
      const s = section("Response timeline"); const mini = el("div", "mini");
      for (const a of acts) {
        const row = el("div", "m-row");
        row.appendChild(el("time", null, hhmmss(a.ts)));
        row.appendChild(el("span", "m-name", a.kind === "error" ? "error" : humanize(a.tool || a.kind)));
        const bad = a.kind === "error" || (a.outcome && a.outcome !== "ok");
        row.appendChild(el("span", "m-out" + (bad ? " rej" : ""), a.kind === "error" ? clip(a.error || "error", 36) : (a.outcome || "")));
        mini.appendChild(row);
      }
      s.appendChild(mini); detBody.appendChild(s);
    }

    const notes = data.notifications || [];
    if (notes.length) {
      const s = section("Alert");
      for (const n of notes) {
        const pill = el("div", "status-pill");
        pill.dataset.ok = n.status === "accepted" || n.status === "delivered" ? "1" : "0";
        pill.appendChild(el("span", "d"));
        pill.appendChild(el("span", null, (n.status || "unknown") + (n.provider ? " · " + n.provider : "")));
        s.appendChild(pill);
      }
      detBody.appendChild(s);
    }

    if (reduceMotion) anim(detBody, [{ opacity: 0 }, { opacity: 1 }], { duration: 120, easing: "ease-out" });
    else anim(detBody, [{ opacity: 0, transform: "translateY(4px)" }, { opacity: 1, transform: "none" }], { duration: 180, easing: EASE });
  }

  /* ---------- filters ---------- */
  searchEl.addEventListener("input", () => { query = searchEl.value.trim().toLowerCase(); renderList(false); });
  chipsEl.addEventListener("click", (e) => {
    const chip = e.target.closest(".chip"); if (!chip || chip.dataset.sev === sevFilter) return;
    sevFilter = chip.dataset.sev;
    chipsEl.querySelectorAll(".chip").forEach((c) => c.classList.toggle("on", c === chip));
    renderList(false);
  });

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
    if (selectedId == null || !byId.has(selectedId)) {
      if (order.length) select(order[0]);
      else { selectedId = null; setDetailEmpty("No incidents filed."); }
    }
  });

  return function unmount() { alive = false; detToken++; unsub(); };
}
