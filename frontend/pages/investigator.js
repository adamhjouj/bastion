"use strict";
/* Investigator page — what the agent is doing right now, and the record you can verify.
   Agent feed: one line per triage verdict / tool call, newest first, in operator language;
   read-only calls and benign verdicts stay quiet, containment and remediation read loud.
   Every line that belongs to a filed incident links to its case file (#/incidents/<id>);
   the case file (Incidents page) holds the inputs and results, so nothing is repeated here.
   Audit ledger: the hash-chained action log with the short hash per record, a verify chip
   fed by GET /audit/verify (hidden-gracefully when the backend has not shipped it), and the
   head hash with copy-on-click. Active defenses: denylist / honeypot / virtual patches.
   The raw blue container log is a collapsed disclosure; its stream opens on first expand. */

import { API, store, el, clear, clip, humanize, fmt, fmtScore, hhmmss, anim, reduceMotion, makeStream, logStream } from "../core.js";

const READ_ONLY = new Set(["inspect_target", "get_defenses", "recent_requests", "recent_incidents", "service_status", "list_processes", "list_sessions"]);
const FEED_CAP = 150;
const LEDGER_CAP = 200;
const SHORT_HASH = 8;

const TEMPLATE = `
<div class="inv">
  <div class="inv-left">
    <section class="panel inv-feed" aria-label="Agent feed">
      <div class="panel-head"><h2>Agent feed</h2><span class="count" data-feed-n>0</span></div>
      <div class="panel-body" data-feed><div class="empty">No agent activity yet.</div></div>
    </section>
    <details class="panel inv-log" data-log-box>
      <summary class="panel-head inv-log-head"><span class="inv-log-title"><span class="chev" aria-hidden="true"></span><h2>Raw agent log</h2></span><span class="tag" data-log-n></span></summary>
      <div class="panel-body" data-log><div class="empty">Waiting for log stream.</div></div>
    </details>
  </div>
  <div class="inv-right">
    <section class="panel inv-ledger" aria-label="Audit ledger">
      <div class="panel-head">
        <h2>Audit ledger</h2>
        <span class="lg-tools">
          <span class="lg-chip" data-chip data-state="busy"><span class="d" aria-hidden="true"></span><span data-chip-text>Verifying…</span></span>
          <button class="btn lg-verify" type="button" data-verify disabled>Verify</button>
        </span>
      </div>
      <div class="panel-body" data-ledger><div class="empty">No actions recorded.</div></div>
      <button class="lg-foot" type="button" data-head hidden title="Copy the head hash">
        <span class="cap">Head</span><span class="lg-head mono" data-head-hash></span><span class="lg-copy" data-copy-state>copy</span>
      </button>
    </section>
    <section class="panel inv-def" aria-label="Active defenses">
      <div class="panel-head"><h2>Active defenses</h2><span class="count" data-def-n>0</span></div>
      <div class="panel-body">
        <div class="def-sec"><div class="def-head"><span>Denylist</span><span class="count" data-n="deny">0</span></div><div data-deny></div></div>
        <div class="def-sec"><div class="def-head"><span>Honeypot diversions</span><span class="count" data-n="hp">0</span></div><div data-hp></div></div>
        <div class="def-sec"><div class="def-head"><span>Virtual patches</span><span class="count" data-n="vp">0</span></div><div data-vp></div></div>
      </div>
    </section>
  </div>
</div>`;

/* ---------- small helpers ---------- */
function setNum(n, v) {
  if (!n || n._v === v) return;
  const prev = n._v; n._v = v; n.textContent = fmt(v);
  if (!reduceMotion && prev != null && v > prev) anim(n, [{ color: "#ff8a4c" }, { color: getComputedStyle(n).color }], { duration: 400 });
}
function shortHash(h) { return typeof h === "string" && h.length >= SHORT_HASH ? h.slice(0, SHORT_HASH) : ""; }

/* Operator-language sentence for a tool call, built from its recorded input. */
function describe(a) {
  const t = a.tool || "", inp = a.input || {};
  const target = inp.target ? String(inp.target) : "the target";
  switch (t) {
    case "blacklist_ip": return "Banned " + (inp.ip || "a source");
    case "bulk_blacklist_ip": return "Banned " + fmt((inp.ips || []).length) + " sources";
    case "unban_ip": return "Lifted the ban on " + (inp.ip || "a source");
    case "divert_to_honeypot": return "Diverted " + (inp.ip || "a source") + " to the honeypot";
    case "undivert": return "Routed " + (inp.ip || "a source") + " back to the app";
    case "virtual_patch": return "Virtual-patched " + (inp.path || "a route") + (inp.attack_type ? " against " + humanize(inp.attack_type) : "");
    case "patch_vuln": return "Hardened the app" + (inp.level ? " to security level " + inp.level : "");
    case "raise_alert": return "Filed a " + (inp.severity ? inp.severity + " " : "") + (humanize(inp.attack_type) || "") + " incident" + (inp.source_ip ? " for " + inp.source_ip : "");
    case "quarantine_container": return "Quarantined " + target;
    case "release_container": return "Released " + target + " from quarantine";
    case "isolate_egress": return "Cut outbound network for " + target;
    case "reconnect_egress": return "Restored outbound network for " + target;
    case "kill_process": return "Killed process " + (inp.pid != null ? inp.pid : "") + " in " + target;
    case "kill_session": return "Ended session " + (inp.session_id || "") + " in " + target;
    case "rotate_secret": return "Rotated the compromised credential on " + target;
    case "rollback": return "Rolled back #" + (inp.reverts != null ? inp.reverts : "?") + (inp.tool ? " (" + humanize(inp.tool) + ")" : "");
    case "operator_reset": return "Operator reset the board";
    case "inspect_target": return "Inspected " + [inp.method, inp.path].filter(Boolean).join(" ");
    case "recent_requests": return "Reviewed recent requests";
    case "recent_incidents": return "Reviewed recent incidents";
    case "get_defenses": return "Checked active defenses";
    case "service_status": return "Checked service status";
    case "list_processes": return "Listed processes in " + target;
    case "list_sessions": return "Listed sessions in " + target;
    default: return humanize(t) || "Action";
  }
}

/* case_id → incident id. Incident case_ids may be comma lists of event ids; a triage row
   carries a single event id, so each component is indexed as well as the whole string. */
function caseIndex(incidents) {
  const m = new Map();
  for (const inc of incidents || []) {
    if (inc.id == null || !inc.case_id) continue;
    const key = String(inc.case_id);
    if (!m.has(key)) m.set(key, inc.id);
    for (const part of key.split(",")) { const p = part.trim(); if (p && !m.has(p)) m.set(p, inc.id); }
  }
  return m;
}
function incidentFor(index, caseId) {
  if (!caseId) return null;
  const key = String(caseId);
  if (index.has(key)) return index.get(key);
  for (const part of key.split(",")) { const p = part.trim(); if (index.has(p)) return index.get(p); }
  return null;
}
function caseLink(incidentId) {
  const a = el("a", "case", "Case #" + incidentId);
  a.href = "#/incidents/" + encodeURIComponent(incidentId);
  a.title = "Open the case file";
  return a;
}

/* ---------- agent feed ---------- */
function feedItems(s) {
  const out = [];
  for (const a of s.actions || []) {
    if (a.kind !== "triage" && a.kind !== "action" && a.kind !== "error") continue;
    out.push({ k: "a" + (a.id != null ? a.id : (a.ts || "") + "·" + (a.tool || a.kind)), a });
    if (out.length >= FEED_CAP) break;
  }
  return out;
}
function feedNode(item) {
  const a = item.a;
  const line = el("div", "line");
  line.dataset.case = a.case_id || "";
  line.appendChild(el("time", null, hhmmss(a.ts)));
  const b = el("div", "body");
  if (a.kind === "triage") {
    const v = a.jev || {}, esc = !!a.escalated, hot = !!v.malicious || esc;
    const where = [a.ip, a.path].filter(Boolean).join(" · ");
    if (hot) {
      line.classList.add("verdict");
      b.appendChild(el("div", "label act", esc ? "verdict · escalated" : "verdict · malicious"));
      const t = el("div", "text");
      t.appendChild(el("span", null, humanize(v.attack_type) || "attack"));
      t.appendChild(el("span", "jev-score hot", fmtScore(v.malicious_score)));
      b.appendChild(t);
      if (where) b.appendChild(el("div", "meta", clip(where, 90)));
    } else {
      line.classList.add("quiet");
      const t = el("div", "text");
      t.appendChild(el("span", null, "Screened " + clip(where || "a request", 70)));
      t.appendChild(el("span", "jev-score", (humanize(v.attack_type) || "benign") + " " + fmtScore(v.malicious_score)));
      b.appendChild(t);
    }
  } else if (a.kind === "action") {
    const bad = a.outcome && a.outcome !== "ok";
    if (READ_ONLY.has(a.tool) && !bad) {
      line.classList.add("quiet");
      b.appendChild(el("div", "text", describe(a)));
    } else {
      line.classList.add("act");
      b.appendChild(el("div", "label" + (bad ? " act" : ""), humanize(a.tool || "action") + (bad ? " · " + a.outcome : "")));
      b.appendChild(el("div", "text", (bad ? (a.outcome === "rejected" ? "Refused: " : "Failed: ") : "") + describe(a)));
      const reason = (a.input || {}).reason;
      if (reason) b.appendChild(el("div", "meta", clip(reason, 140)));
    }
  } else {
    line.classList.add("act");
    b.appendChild(el("div", "label act", "error"));
    b.appendChild(el("div", "text", clip(a.error || "Agent error", 180)));
  }
  line.appendChild(b);
  return line;
}
/* Incidents may be filed after their lines were drawn: attach links to any line that has none. */
function linkCases(container, index) {
  for (const line of container.children) {
    if (!line.dataset || !line.dataset.case || line.querySelector(".case")) continue;
    const id = incidentFor(index, line.dataset.case);
    if (id != null) line.appendChild(caseLink(id));
  }
}

/* ---------- audit ledger ---------- */
function ledgerItems(s) {
  const out = [];
  for (const a of s.actions || []) {
    if (a.id == null) continue;
    out.push({ k: "a" + a.id, a });
    if (out.length >= LEDGER_CAP) break;
  }
  return out;
}
function ledgerNode(item) {
  const a = item.a;
  const row = el("div", "lg-row");
  row.appendChild(el("time", null, hhmmss(a.ts)));
  row.appendChild(el("span", "lg-id", "#" + a.id));
  const what = a.kind === "triage" ? "triage" : a.kind === "error" ? "error" : humanize(a.tool || "action");
  row.appendChild(el("span", "lg-tool", what));
  const bad = a.kind === "error" || (a.kind === "action" && !!a.outcome && a.outcome !== "ok");
  row.appendChild(el("span", "lg-out" + (bad ? " bad" : ""), a.kind === "error" ? "error" : (humanize(a.outcome) || "—")));
  const h = shortHash(a.audit && a.audit.hash);
  const hs = el("span", "lg-hash" + (h ? "" : " none"), h || "—");
  if (h) hs.title = a.audit.hash;
  row.appendChild(hs);
  return row;
}

/* ---------- active defenses ---------- */
function renderList(body, rows, sig, makeRow, emptyText) {
  if (!body || body._sig === sig) return;
  body._sig = sig; clear(body);
  if (!rows.length) { body.appendChild(el("div", "def-empty", emptyText)); return; }
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
  setNum(page.querySelector("[data-def-n]"), deny.length + hp.length + vp.length);
  renderList(page.querySelector("[data-deny]"), deny, deny.map((d) => d.ip + (d.expires || "")).join(","),
    (d) => defRow(d.ip, d.expires ? "until " + hhmmss(d.expires) : "no expiry", d.reason ? clip(d.reason, 150) : ""), "No active bans.");
  renderList(page.querySelector("[data-hp]"), hp, hp.map((d) => d.ip + (d.ts || "")).join(","),
    (d) => defRow(d.ip, "since " + hhmmss(d.ts), d.reason ? clip(d.reason, 150) : ""), "No diversions.");
  renderList(page.querySelector("[data-vp]"), vp, vp.map((d) => (d.id != null ? d.id : d.path)).join(","),
    (d) => defRow(d.path, humanize(d.attack_type), d.pattern ? clip(d.pattern, 120) : "", true), "No virtual patches.");
}

/* ---------- mount ---------- */
export function mount(root) {
  const page = el("div", "page p-investigator");
  page.innerHTML = TEMPLATE;
  root.appendChild(page);
  let alive = true;

  /* agent feed */
  const feedBody = page.querySelector("[data-feed]");
  const feed = makeStream(feedBody, FEED_CAP, feedNode);
  let feedHas = false;

  /* audit ledger rows */
  const ledgerBody = page.querySelector("[data-ledger]");
  const ledger = makeStream(ledgerBody, LEDGER_CAP, ledgerNode);
  let ledgerHas = false;

  /* audit verify chip + head hash */
  const chip = page.querySelector("[data-chip]");
  const chipText = page.querySelector("[data-chip-text]");
  const verifyBtn = page.querySelector("[data-verify]");
  const headBtn = page.querySelector("[data-head]");
  const headHash = page.querySelector("[data-head-hash]");
  const copyState = page.querySelector("[data-copy-state]");
  let fullHead = "";
  let copyTimer = null;

  function setChip(state, text) { chip.dataset.state = state; chipText.textContent = text; }
  function setHead(h) {
    fullHead = typeof h === "string" ? h : "";
    headBtn.hidden = !fullHead;
    headHash.textContent = fullHead ? fullHead.slice(0, 12) + "…" + fullHead.slice(-4) : "";
    copyState.textContent = "copy";
  }
  async function verify() {
    if (!alive) return;
    verifyBtn.disabled = true;
    setChip("busy", "Verifying…");
    let r = null, v = null;
    try {
      r = await fetch(API + "/audit/verify", { credentials: "same-origin" });
      if (r.ok) v = await r.json();
    } catch (_) {}
    if (!alive) return;
    if (r && r.status === 404) { /* backend not shipped: show nothing actionable */
      setChip("none", "Verification unavailable"); verifyBtn.hidden = true; setHead(null); return;
    }
    verifyBtn.hidden = false; verifyBtn.disabled = false;
    if (!v) { setChip("none", "Couldn't verify"); return; }
    setHead(v.head);
    if (v.intact) setChip("ok", "Log verified · " + fmt(v.length || 0) + " actions");
    else setChip("broken", "Integrity broken at #" + (v.broken_at != null ? v.broken_at : "?"));
  }
  verifyBtn.addEventListener("click", verify);
  headBtn.addEventListener("click", async () => {
    if (!fullHead) return;
    let ok = false;
    try { await navigator.clipboard.writeText(fullHead); ok = true; } catch (_) {}
    if (!alive) return;
    copyState.textContent = ok ? "copied" : "copy failed";
    clearTimeout(copyTimer);
    copyTimer = setTimeout(() => { if (alive) copyState.textContent = "copy"; }, 1400);
  });
  verify();

  /* raw blue log: stream opens on first expand, closes on unmount */
  const logBox = page.querySelector("[data-log-box]");
  const logBody = page.querySelector("[data-log]");
  const logN = page.querySelector("[data-log-n]");
  const log = makeStream(logBody, 200, (it) => {
    const line = el("div", "line" + (it.stream === "stderr" ? " sys" : ""));
    line.appendChild(el("time", null, hhmmss(it.ts)));
    const b = el("div", "body");
    /* the line already carries a time column — drop the logger's own timestamp prefix */
    b.appendChild(el("div", "text", clip(String(it.text || "").replace(/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[,.]\d+\s*/, ""), 300)));
    line.appendChild(b);
    return line;
  });
  let closeLog = null;
  function openLog() {
    if (closeLog || !alive) return;
    closeLog = logStream("blue", (p) => {
      if (!alive) return;
      const entries = (p.entries || []).map((e) => ({ k: "l" + e.id, ts: e.ts, text: e.text, stream: e.stream }));
      log.appendAscending(entries, !!p.reset);
      const n = logBody.querySelectorAll(".line").length;
      logN.textContent = n ? fmt(n) + " lines" : "";
      if (!n && !logBody.querySelector(".empty")) logBody.appendChild(el("div", "empty", "Waiting for log stream."));
    });
  }
  const onToggle = () => { if (logBox.open) openLog(); };
  logBox.addEventListener("toggle", onToggle);

  /* live snapshots */
  const unsub = store.subscribe((s) => {
    if (!s || !alive) return;
    const index = caseIndex(s.incidents);
    const items = feedItems(s);
    setNum(page.querySelector("[data-feed-n]"), items.length);
    if (!items.length) {
      if (feedHas) { feed.reset(); feedBody.appendChild(el("div", "empty", "No agent activity yet.")); feedHas = false; }
    } else { feedHas = true; feed.syncNewestFirst(items); linkCases(feedBody, index); }
    const rows = ledgerItems(s);
    if (!rows.length) {
      if (ledgerHas) { ledger.reset(); ledgerBody.appendChild(el("div", "empty", "No actions recorded.")); ledgerHas = false; }
    } else { ledgerHas = true; ledger.syncNewestFirst(rows); }
    updateDefenses(page, s);
  });

  return function unmount() {
    alive = false;
    unsub();
    logBox.removeEventListener("toggle", onToggle);
    if (closeLog) { closeLog(); closeLog = null; }
    clearTimeout(copyTimer);
  };
}
