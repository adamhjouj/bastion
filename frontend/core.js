"use strict";
/* Bastion dashboard — shared core (ES module).
   Helpers, the single live data store (one SSE connection fanned out to every page),
   control-plane wrappers, a reusable log stream, and the shared incident drawer.
   CSP-safe: same-origin only, no inline script/style; dynamic styles via CSSOM. */

export const API = "/__api/v1";
export const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;

/* ---------- DOM + format helpers ---------- */
export function el(tag, cls, text) { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; }
export function clear(n) { while (n && n.firstChild) n.removeChild(n.firstChild); }
export function clip(s, n) { s = String(s == null ? "" : s); return s.length > n ? s.slice(0, n - 1) + "…" : s; }
export function humanize(s) { return String(s || "").replace(/_/g, " "); }
export function fmt(n) { return Number(n || 0).toLocaleString(); }
export function fmtScore(x) { return typeof x === "number" && isFinite(x) ? x.toFixed(2) : "—"; }
export function clamp(v, a, b) { return v < a ? a : v > b ? b : v; }
export function smooth(t) { return t * t * (3 - 2 * t); }
export function hhmmss(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  if (!isNaN(d)) return [d.getHours(), d.getMinutes(), d.getSeconds()].map((x) => String(x).padStart(2, "0")).join(":");
  const m = String(ts).match(/T(\d{2}:\d{2}:\d{2})/); return m ? m[1] : "";
}
export function anim(elm, frames, opts) { if (elm && elm.animate) try { elm.animate(frames, opts); } catch (_) {} }

export async function api(path, opts) {
  const r = await fetch(API + path, Object.assign({ credentials: "same-origin" }, opts || {}));
  if (!r.ok) throw new Error(path + " " + r.status);
  return r.json();
}
export async function post(path, body) {
  return api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
}

/* ---------- incremental "newest on top" list renderer ---------- */
export function makeStream(container, cap, makeNode) {
  const seen = new Set(); let first = true;
  function insertTop(item) { const e = container.querySelector(".empty"); if (e) e.remove(); const node = makeNode(item); node.dataset.k = item.k; if (!first) node.classList.add("enter"); container.insertBefore(node, container.firstChild); seen.add(item.k); }
  function trim() { while (container.children.length > cap) { const l = container.lastChild; if (l.dataset && l.dataset.k != null) seen.delete(l.dataset.k); container.removeChild(l); } first = false; }
  function reset() { clear(container); seen.clear(); first = true; }
  return {
    syncNewestFirst(items) { if (!items.length) return; let common = 0; for (const i of items) if (seen.has(i.k)) common++; if (seen.size && common === 0) reset(); const fresh = items.filter((i) => !seen.has(i.k)); for (let i = fresh.length - 1; i >= 0; i--) insertTop(fresh[i]); trim(); },
    appendAscending(entries, doReset) { if (doReset) reset(); for (const e of entries) if (!seen.has(e.k)) insertTop(e); trim(); },
    reset,
  };
}

/* ---------- live store: one SSE /stream, fanned out to subscribers ---------- */
const subs = new Set(), connSubs = new Set();
let _latest = null, _conn = "connecting", _started = false;
function notify(s) { _latest = s; for (const f of subs) try { f(s); } catch (_) {} }
function setConn(c) { if (c === _conn) { return; } _conn = c; for (const f of connSubs) try { f(c); } catch (_) {} }

export const store = {
  get latest() { return _latest; },
  get conn() { return _conn; },
  /** subscribe(fn): fn(snapshot) on every snapshot; immediately called with the latest if present. returns unsubscribe. */
  subscribe(fn) { subs.add(fn); if (_latest) try { fn(_latest); } catch (_) {} return () => subs.delete(fn); },
  onConn(fn) { connSubs.add(fn); try { fn(_conn); } catch (_) {} return () => connSubs.delete(fn); },
  async start() {
    if (_started) return; _started = true;
    setConn("connecting");
    try { notify(await api("/overview")); } catch (_) {}
    const es = new EventSource(API + "/stream", { withCredentials: true });
    es.addEventListener("snapshot", (ev) => { setConn("live"); try { notify(JSON.parse(ev.data)); } catch (_) {} });
    es.onopen = () => setConn("live");
    es.onerror = () => setConn("offline");
  },
};

/* ---------- control plane ---------- */
export const controls = {
  status: () => api("/control/status"),
  run: (job) => post("/control/run", { job }),
  stop: () => post("/control/stop"),
  reset: () => post("/control/reset"),
};

/* ---------- container-log SSE (e.g. the red agent); returns a close fn ---------- */
export function logStream(source, onPage) {
  const es = new EventSource(API + "/logs/" + source + "/stream", { withCredentials: true });
  es.addEventListener("logs", (ev) => { let p; try { p = JSON.parse(ev.data); } catch (_) { return; } onPage(p); });
  return () => { try { es.close(); } catch (_) {} };
}

/* ---------- shared incident drawer (markup lives in index.html) ---------- */
const drawer = document.querySelector("[data-drawer]");
const scrim = document.querySelector("[data-scrim]");
const drawerBody = document.querySelector("[data-drawer-body]");
let returnFocus = null;
function kv(cap, value, mono) { const d = el("div"); d.appendChild(el("span", "cap", cap)); d.appendChild(el("span", "v" + (mono ? " mono" : ""), value || "—")); return d; }
function section(title) { const s = el("div", "sec"); s.appendChild(el("span", "cap", title)); return s; }

export async function openIncident(id) {
  if (!drawer) return;
  returnFocus = document.activeElement;
  scrim.hidden = false;
  requestAnimationFrame(() => { scrim.classList.add("show"); drawer.classList.add("open"); const cb = document.querySelector("[data-close]"); if (cb) cb.focus(); });
  drawer.setAttribute("aria-hidden", "false");
  clear(drawerBody); drawerBody.appendChild(el("div", "empty", "Loading…"));
  let data; try { data = await api("/incidents/" + id); } catch (_) { clear(drawerBody); drawerBody.appendChild(el("div", "empty", "Could not load incident.")); return; }
  const inc = data.incident || {};
  document.querySelector('[data-d="type"]').textContent = humanize(inc.attack_type) || "Incident";
  document.querySelector('[data-d="sev"]').dataset.sev = inc.severity || "";
  clear(drawerBody);
  const meta = el("div", "kv");
  meta.appendChild(kv("Severity", inc.severity)); meta.appendChild(kv("Source", inc.source_ip, true));
  meta.appendChild(kv("Filed", hhmmss(inc.ts), true)); meta.appendChild(kv("Case", inc.id != null ? "#" + inc.id : "", true));
  drawerBody.appendChild(meta);
  /* the drawer is a quick peek; the full story (trace, rollback) lives on the Incidents page */
  const open = el("button", "btn", "Open case file"); open.type = "button"; open.dataset.openCase = String(id);
  open.addEventListener("click", () => { closeDrawer(); location.hash = "#/incidents/" + id; });
  drawerBody.appendChild(open);
  if (inc.summary) { const s = section("Summary"); s.appendChild(el("p", "prose", inc.summary)); drawerBody.appendChild(s); }
  if (inc.evidence) { const s = section("Evidence"); s.appendChild(el("pre", "evidence", inc.evidence)); drawerBody.appendChild(s); }
  const reqs = data.requests || [];
  if (reqs.length) { const s = section("Triggering requests"); const mini = el("div", "mini"); for (const r of reqs) { const row = el("div", "m-row"); row.appendChild(el("time", null, hhmmss(r.ts))); row.appendChild(el("span", "m-name mono", clip((r.method || "") + " " + (r.path || ""), 40))); row.appendChild(el("span", "m-out", r.status == null ? "—" : String(r.status))); mini.appendChild(row); } s.appendChild(mini); drawerBody.appendChild(s); }
  const acts = (data.actions || []).filter((a) => a.kind !== "triage");
  if (acts.length) { const s = section("Response actions"); const mini = el("div", "mini"); for (const a of acts) { const row = el("div", "m-row"); row.appendChild(el("time", null, hhmmss(a.ts))); row.appendChild(el("span", "m-name", humanize(a.tool || a.kind))); row.appendChild(el("span", "m-out" + (a.outcome && a.outcome !== "ok" ? " rej" : ""), a.outcome || "")); mini.appendChild(row); } s.appendChild(mini); drawerBody.appendChild(s); }
  const notes = data.notifications || [];
  if (notes.length) { const s = section("Alert"); const n = notes[0]; const pill = el("div", "status-pill"); pill.dataset.ok = n.status === "accepted" || n.status === "delivered" ? "1" : "0"; pill.appendChild(el("span", "d")); pill.appendChild(el("span", null, n.status + (n.provider ? " · " + n.provider : ""))); s.appendChild(pill); drawerBody.appendChild(s); }
}
export function closeDrawer() {
  if (!drawer) return;
  drawer.classList.remove("open"); scrim.classList.remove("show"); drawer.setAttribute("aria-hidden", "true");
  const done = () => { scrim.hidden = true; };
  if (reduceMotion) done(); else setTimeout(done, 260);
  if (returnFocus && returnFocus.focus) { try { returnFocus.focus(); } catch (_) {} }
  returnFocus = null;
}
if (drawer) {
  document.querySelector("[data-close]").addEventListener("click", closeDrawer);
  scrim.addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => {
    if (!drawer.classList.contains("open")) return;
    if (e.key === "Escape") { closeDrawer(); return; }
    if (e.key === "Tab") {
      const f = drawer.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (!drawer.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
      else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  });
}
