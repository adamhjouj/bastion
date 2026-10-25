"use strict";
/* Investigator page — the blue defender's mind.
   Triage funnel (evaluated → flagged → escalated → actions), live JEV verdict +
   BASTION reasoning timeline, active defenses (denylist / honeypot / vpatch),
   component health strip, and the raw blue agent log. Pure consumer of the
   shared store snapshots + the blue container-log SSE. */

import { store, el, clear, clip, humanize, fmt, fmtScore, hhmmss, anim, reduceMotion, makeStream, logStream } from "../core.js";

const STAGES = [["evaluated", "Evaluated"], ["flagged", "Flagged"], ["escalated", "Escalated"], ["actions", "Actions"]];
const HEALTH = [["blue", "blue"], ["proxy", "proxy"], ["classifier", "classifier"], ["actuator", "actuator"], ["mail-worker", "mail worker"]];

const TEMPLATE = `
<div class="inv">
  <section class="panel inv-funnel" aria-label="Triage funnel">
    <div class="panel-head"><span class="head-l"><h2>Triage funnel</h2><span class="tag">jev → bastion</span></span><span class="count" data-succ>—</span></div>
    <div class="funnel">
      ${STAGES.map(([k, label], i) =>
        (i ? `<div class="f-sep" aria-hidden="true"><span class="f-pct" data-pct="${i}">—</span></div>` : "") +
        `<div class="f-stage" data-stage="${k}"><span class="f-label">${label}</span><span class="f-val" data-f="${k}">0</span><span class="f-bar"><span class="f-fill" data-fill="${k}"></span></span></div>`
      ).join("")}
    </div>
  </section>
  <div class="inv-main">
    <div class="inv-left">
      <section class="panel inv-mind" aria-label="Reasoning timeline">
        <div class="panel-head"><span class="head-l"><h2>Reasoning</h2><span class="tag">verdicts · actions</span></span><span class="count" data-mind-n>0</span></div>
        <div class="panel-body" data-mind><div class="empty">Waiting for triage.</div></div>
      </section>
      <section class="panel inv-log" aria-label="Blue agent log">
        <div class="panel-head"><span class="head-l"><h2>Agent log</h2><span class="tag">blue</span></span></div>
        <div class="panel-body" data-log><div class="empty">Waiting for log stream.</div></div>
      </section>
    </div>
    <div class="inv-right" aria-label="Active defenses">
      <section class="panel"><div class="panel-head"><span class="head-l"><h2>Denylist</h2></span><span class="count" data-n="deny">0</span></div><div class="panel-body" data-deny></div></section>
      <section class="panel"><div class="panel-head"><span class="head-l"><h2>Honeypot</h2></span><span class="count" data-n="hp">0</span></div><div class="panel-body" data-hp></div></section>
      <section class="panel"><div class="panel-head"><span class="head-l"><h2>Virtual patches</h2></span><span class="count" data-n="vp">0</span></div><div class="panel-body" data-vp></div></section>
    </div>
  </div>
  <div class="inv-health" aria-label="Component health">
    ${HEALTH.map(([k, label]) => `<div class="hs" data-hs="${k}"><span class="hs-dot"></span><span class="hs-name">${label}</span><span class="hs-age">—</span></div>`).join("")}
  </div>
</div>`;

/* ---------- small helpers ---------- */
function setNum(n, v) {
  if (!n || n._v === v) return;
  const prev = n._v; n._v = v; n.textContent = fmt(v);
  if (!reduceMotion && prev != null && v > prev) anim(n, [{ color: "#ff8a4c" }, { color: getComputedStyle(n).color }], { duration: 400 });
}
function fmtAge(x) { x = Math.max(0, Math.round(x)); return x < 60 ? x + "s" : x < 3600 ? Math.round(x / 60) + "m" : Math.round(x / 3600) + "h"; }

/* ---------- funnel ---------- */
function updateFunnel(page, s) {
  const f = s.funnel || {};
  const vals = STAGES.map(([k]) => f[k] || 0);
  const denom = Math.max(vals[0], 1);
  STAGES.forEach(([k], i) => {
    setNum(page.querySelector('[data-f="' + k + '"]'), vals[i]);
    const fill = page.querySelector('[data-fill="' + k + '"]');
    if (fill) fill.style.width = (vals[i] > 0 ? Math.max(2, Math.min(100, (vals[i] / denom) * 100)) : 0).toFixed(1) + "%";
  });
  for (let i = 1; i < vals.length; i++) {
    const n = page.querySelector('[data-pct="' + i + '"]'); if (!n) continue;
    const prev = vals[i - 1], r = prev > 0 ? vals[i] / prev : null;
    n.textContent = r == null ? "—" : r <= 1 ? Math.round(r * 100) + "%" : "×" + (r >= 10 ? String(Math.round(r)) : r.toFixed(1));
  }
  const succ = page.querySelector("[data-succ]");
  if (succ) succ.textContent = (f.succeeded || 0) + "/" + (f.actions || 0) + " ok";
}

/* ---------- reasoning timeline (triage | action | error) ---------- */
function mindItems(s) {
  const out = [];
  for (const a of s.actions || []) {
    if (a.kind !== "triage" && a.kind !== "action" && a.kind !== "error") continue;
    out.push({ k: "a" + (a.id != null ? a.id : (a.ts || "") + "·" + (a.tool || a.kind)), a });
    if (out.length >= 120) break;
  }
  return out;
}
function mindNode(item) {
  const a = item.a;
  const line = el("div", "line");
  line.appendChild(el("time", null, hhmmss(a.ts)));
  const b = el("div", "body");
  if (a.kind === "triage") {
    const v = a.jev || {}, esc = !!a.escalated;
    b.appendChild(el("div", "label" + (esc ? " act" : ""), esc ? "jev · escalated" : "jev · triage"));
    const t = el("div", "text");
    t.appendChild(el("span", null, humanize(v.attack_type) || "scored"));
    t.appendChild(el("span", "jev-score" + (v.malicious ? " hot" : ""), fmtScore(v.malicious_score)));
    b.appendChild(t);
    const meta = [a.ip, a.path].filter(Boolean).join(" · ");
    if (meta) b.appendChild(el("div", "meta", clip(meta, 90)));
  } else if (a.kind === "action") {
    const bad = a.outcome && a.outcome !== "ok";
    b.appendChild(el("div", "label" + (bad ? " act" : ""), humanize(a.tool || "action")));
    const inp = a.input || {};
    if (inp.reason) b.appendChild(el("div", "text", clip(inp.reason, 180)));
    const meta = [a.outcome, a.case_id ? "case " + a.case_id : ""].filter(Boolean).join(" · ");
    if (meta) b.appendChild(el("div", "meta", clip(meta, 90)));
  } else {
    b.appendChild(el("div", "label act", "error"));
    b.appendChild(el("div", "text", clip(a.error || "agent error", 180)));
    if (a.case_id) b.appendChild(el("div", "meta", "case " + a.case_id));
  }
  line.appendChild(b);
  return line;
}

/* ---------- active defenses ---------- */
function renderList(body, rows, sig, makeRow, emptyText) {
  if (!body || body._sig === sig) return;
  body._sig = sig; clear(body);
  if (!rows.length) { body.appendChild(el("div", "empty", emptyText)); return; }
  for (const r of rows) body.appendChild(makeRow(r));
}
function defRow(key, aside, sub, subMono) {
  const row = el("div", "d-row"), top = el("div", "d-top");
  top.appendChild(el("span", "d-key", key || "—"));
  if (aside) top.appendChild(el("span", "d-aside", aside));
  row.appendChild(top);
  if (sub) row.appendChild(el("div", "d-sub" + (subMono ? " mono" : ""), sub));
  return row;
}
function updateDefenses(page, s) {
  const deny = (s.denylist || []).slice().reverse();
  const hp = (s.honeypot || []).slice().reverse();
  const vp = (s.vpatch || []).slice().reverse();
  setNum(page.querySelector('[data-n="deny"]'), deny.length);
  setNum(page.querySelector('[data-n="hp"]'), hp.length);
  setNum(page.querySelector('[data-n="vp"]'), vp.length);
  renderList(page.querySelector("[data-deny]"), deny, deny.map((d) => d.ip + (d.expires || "")).join(","),
    (d) => defRow(d.ip, d.expires ? "until " + hhmmss(d.expires) : "no expiry", d.reason ? clip(d.reason, 150) : ""), "No active bans.");
  renderList(page.querySelector("[data-hp]"), hp, hp.map((d) => d.ip + (d.ts || "")).join(","),
    (d) => defRow(d.ip, hhmmss(d.ts), d.reason ? clip(d.reason, 150) : ""), "No diversions.");
  renderList(page.querySelector("[data-vp]"), vp, vp.map((d) => (d.id != null ? d.id : d.path)).join(","),
    (d) => defRow(d.path, humanize(d.attack_type), d.pattern ? clip(d.pattern, 120) : "", true), "No virtual patches.");
}

/* ---------- component health ---------- */
function updateHealth(page, s) {
  const h = s.health || {};
  for (const [k] of HEALTH) {
    const chip = page.querySelector('[data-hs="' + k + '"]'); if (!chip) continue;
    const e = h[k];
    const ready = !!(e && (e.ready === true || e.available === true));
    const stale = !e || !!e.stale;
    chip.classList.toggle("on", ready && !stale);
    chip.classList.toggle("stale", stale);
    const age = chip.querySelector(".hs-age");
    if (age) age.textContent = e && e.age_seconds != null ? fmtAge(e.age_seconds) : "—";
  }
}

/* ---------- mount ---------- */
export function mount(root) {
  const page = el("div", "page p-investigator");
  page.innerHTML = TEMPLATE;
  root.appendChild(page);

  const mindBody = page.querySelector("[data-mind]");
  const mind = makeStream(mindBody, 120, mindNode);
  let mindHas = false;

  const logBody = page.querySelector("[data-log]");
  const log = makeStream(logBody, 120, (it) => {
    const line = el("div", "line" + (it.stream === "stderr" ? " sys" : ""));
    line.appendChild(el("time", null, hhmmss(it.ts)));
    const b = el("div", "body");
    /* the line already carries a time column — drop the logger's own timestamp prefix */
    b.appendChild(el("div", "text", clip(String(it.text || "").replace(/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[,.]\d+\s*/, ""), 300)));
    line.appendChild(b);
    return line;
  });
  const closeLog = logStream("blue", (p) => {
    const entries = (p.entries || []).map((e) => ({ k: "l" + e.id, ts: e.ts, text: e.text, stream: e.stream }));
    log.appendAscending(entries, !!p.reset);
    if (p.reset && !entries.length) logBody.appendChild(el("div", "empty", "Waiting for log stream."));
  });

  const unsub = store.subscribe((s) => {
    if (!s) return;
    updateFunnel(page, s);
    const items = mindItems(s);
    setNum(page.querySelector("[data-mind-n]"), items.length);
    if (!items.length) {
      if (mindHas) { mind.reset(); mindBody.appendChild(el("div", "empty", "Waiting for triage.")); mindHas = false; }
    } else { mindHas = true; mind.syncNewestFirst(items); }
    updateDefenses(page, s);
    updateHealth(page, s);
  });

  return function unmount() { unsub(); closeLog(); };
}
