"use strict";
/* Attacker page — the red offense console.
   Owns the campaign control plane (launch / stop / reset of the autonomous red agent)
   plus its LIVE reasoning trace and an attack-context panel scoped to the current
   source IP. Narration, '-> METHOD path' request lines, and '[operator]' system lines
   are styled distinctly; orange is reserved for the active campaign and attack traffic. */

import { el, clear, hhmmss, clip, fmt, humanize, anim, controls, logStream, store, makeStream } from "../core.js";

const JOBS = [["attack-sqli", "SQLi"], ["attack-cmdi", "CMDi"], ["attack-lfi", "LFI"], ["attack-xss", "XSS"]];
const COUNTS = [["requests", "Requests"], ["blocked", "Blocked"], ["incidents", "Incidents"]];
const EMPTY_TRACE = "No campaign running. Launch one above to watch the red agent reason in real time.";
const REQ_METHOD = /^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+(.*)$/;

/* Parse one red-source log line into a styled trace item (or null to skip). */
function parseLine(e) {
  const raw = (e.text || "").trim();
  if (!raw) return null;
  if (raw.startsWith("[operator]")) return { kind: "system", label: "operator", content: raw.replace(/^\[operator\]\s*/, "") };
  const body = raw.startsWith("[red]") ? raw.replace(/^\[red\]\s*/, "") : raw;
  if (body.startsWith("-> ")) {
    const req = body.slice(3).trim();
    const m = req.match(REQ_METHOD);
    if (m) return { kind: "request", label: "request", method: m[1], path: m[2] };
    if (req.startsWith("authenticate")) return { kind: "request", label: "request", method: "AUTH", path: req.replace(/^authenticate/, "") };
    return { kind: "request", label: "request", method: "→", path: req };
  }
  return { kind: "reason", label: "reason", content: body };
}

export function mount(root) {
  const page = el("div", "page p-attacker");
  let attackerIP = null, busy = false;

  /* ---------------- campaign control bar ---------------- */
  const bar = el("div", "atk-bar");
  const barL = el("div", "atk-bar-l");
  barL.appendChild(el("span", "cap", "Campaign"));
  const status = el("div", "atk-status"); status.dataset.state = "idle";
  const statusDot = el("span", "atk-dot");
  const statusText = el("span", "atk-status-text", "Idle");
  status.appendChild(statusDot); status.appendChild(statusText);
  barL.appendChild(status);
  const ipTag = el("span", "atk-ip"); ipTag.hidden = true;
  barL.appendChild(ipTag);
  const llmNote = el("span", "atk-note", "LLM key required"); llmNote.hidden = true;
  barL.appendChild(llmNote);

  const barR = el("div", "atk-bar-r");
  const launch = el("div", "atk-launch");
  const runBtns = JOBS.map(([job, label]) => {
    const b = el("button", "btn", label); b.type = "button"; b.dataset.job = job;
    b.addEventListener("click", () => fire(() => controls.run(job), b));
    launch.appendChild(b); return b;
  });
  const stopBtn = el("button", "btn danger", "Stop"); stopBtn.type = "button"; stopBtn.disabled = true;
  stopBtn.addEventListener("click", () => fire(() => controls.stop(), stopBtn));
  const resetBtn = el("button", "btn", "Reset"); resetBtn.type = "button";
  resetBtn.addEventListener("click", () => fire(() => controls.reset(), resetBtn));
  barR.appendChild(launch); barR.appendChild(stopBtn); barR.appendChild(resetBtn);
  bar.appendChild(barL); bar.appendChild(barR);
  page.appendChild(bar);

  /* ---------------- main split: live trace + attack context ---------------- */
  const mainEl = el("div", "atk-main");

  const trace = el("div", "panel atk-trace");
  const th = el("div", "panel-head");
  th.appendChild(el("h2", null, "Red agent"));
  const thR = el("div", "atk-head-r");
  const liveTag = el("span", "atk-live"); liveTag.dataset.on = "0";
  liveTag.appendChild(el("span", "atk-live-dot")); liveTag.appendChild(el("span", null, "live"));
  const lineCount = el("span", "count", "0");
  thR.appendChild(liveTag); thR.appendChild(lineCount);
  th.appendChild(thR);
  const lines = el("div", "panel-body atk-lines");
  lines.appendChild(el("div", "empty", EMPTY_TRACE));
  trace.appendChild(th); trace.appendChild(lines);
  mainEl.appendChild(trace);

  const ctx = el("div", "panel atk-ctx");
  const ch = el("div", "panel-head"); ch.appendChild(el("h2", null, "Attack context"));
  ctx.appendChild(ch);
  const cbody = el("div", "panel-body atk-ctx-body");
  function field(cap, mono) { const d = el("div"); d.appendChild(el("span", "cap", cap)); const v = el("span", "v" + (mono ? " mono" : ""), "—"); d.appendChild(v); return { d, v }; }
  const fObj = field("Objective"), fIp = field("Source IP", true), fStat = field("Status");
  const sum = el("div", "kv atk-sum"); sum.appendChild(fObj.d); sum.appendChild(fIp.d); sum.appendChild(fStat.d);
  cbody.appendChild(sum);
  const counts = el("div", "atk-counts");
  for (const [k, label] of COUNTS) { const cell = el("div", "kpi"); cell.appendChild(el("span", "kpi-label", label)); const v = el("span", "kpi-val", "0"); v.dataset.k = k; cell.appendChild(v); counts.appendChild(cell); }
  cbody.appendChild(counts);
  const recent = el("div", "atk-recent");
  recent.appendChild(el("span", "cap", "Recent hits from source"));
  const hitsEl = el("div", "mini atk-hits");
  hitsEl.appendChild(el("div", "empty", "No active source."));
  recent.appendChild(hitsEl);
  cbody.appendChild(recent);
  ctx.appendChild(cbody);
  mainEl.appendChild(ctx);

  page.appendChild(mainEl);
  root.appendChild(page);

  /* ---------------- control actions + status polling ---------------- */
  async function fire(action, btn) {
    if (busy) return; busy = true;
    if (btn) btn.disabled = true;
    try { const r = await action(); if (r && typeof r.running === "boolean") apply(r); else await refresh(); }
    catch (_) { await refresh(); }
    finally { busy = false; await refresh(); }
  }

  function apply(s) {
    const running = !!s.running, cur = s.current, last = s.last;
    attackerIP = (cur && cur.attacker_ip) || (last && last.attacker_ip) || null;

    if (running && cur) { status.dataset.state = "running"; statusText.textContent = cur.label || "Running"; }
    else if (last) { status.dataset.state = last.status || "idle"; statusText.textContent = "Last · " + humanize(last.status || "idle"); }
    else { status.dataset.state = "idle"; statusText.textContent = "Idle"; }

    ipTag.textContent = attackerIP || ""; ipTag.hidden = !attackerIP;
    llmNote.hidden = s.llm !== false || running;
    liveTag.dataset.on = running ? "1" : "0";

    stopBtn.disabled = !running || busy;
    for (const b of runBtns) { const on = running && cur && cur.job === b.dataset.job; b.classList.toggle("active", !!on); b.disabled = running || s.llm === false || busy; }

    fObj.v.textContent = (cur && cur.label) || (last && last.label) || "—";
    fIp.v.textContent = attackerIP || "—";
    const st = running ? "running" : (last ? (last.status || "idle") : "idle");
    fStat.v.textContent = st; fStat.v.dataset.state = st;

    renderContext(store.latest);
  }
  async function refresh() { try { apply(await controls.status()); } catch (_) {} }

  /* ---------------- attack context (live counts scoped to the source IP) ---------------- */
  function setCount(k, v) { const n = cbody.querySelector('[data-k="' + k + '"]'); if (!n) return; const prev = n._v; n.textContent = fmt(v); if (prev != null && v > prev) anim(n, [{ color: "#ff8a4c" }, { color: getComputedStyle(n).color }], { duration: 650 }); n._v = v; }

  function renderContext(s) {
    const ev = (s && s.events) || [], inc = (s && s.incidents) || [];
    let reqs = 0, blocked = 0; const hits = [];
    if (attackerIP) for (const e of ev) if (e.ip === attackerIP) { reqs++; if (e.blocked) blocked++; if (hits.length < 8) hits.push(e); }
    const incs = attackerIP ? inc.filter((i) => i.source_ip === attackerIP).length : 0;
    setCount("requests", reqs); setCount("blocked", blocked); setCount("incidents", incs);

    clear(hitsEl);
    if (!hits.length) { hitsEl.appendChild(el("div", "empty", attackerIP ? "No requests from source yet." : "No active source.")); return; }
    for (const e of hits) {
      const row = el("div", "m-row");
      row.appendChild(el("time", null, hhmmss(e.ts)));
      row.appendChild(el("span", "m-name mono", clip((e.method || "") + " " + (e.path || ""), 34)));
      row.appendChild(el("span", "m-out" + (e.blocked ? " rej" : ""), e.blocked ? "blocked" : (e.status == null ? "—" : String(e.status))));
      hitsEl.appendChild(row);
    }
  }

  /* ---------------- live red reasoning trace ---------------- */
  const stream = makeStream(lines, 300, (item) => {
    const line = el("div", "line");
    line.appendChild(el("time", null, hhmmss(item.ts)));
    const b = el("div", "body");
    b.appendChild(el("div", "label" + (item.kind === "request" ? " act" : ""), item.label));
    if (item.kind === "request") {
      line.classList.add("cmd");
      const t = el("div", "text");
      t.appendChild(el("span", "mth", item.method));
      t.appendChild(document.createTextNode(" " + item.path));
      b.appendChild(t);
    } else {
      if (item.kind === "system") line.classList.add("sys");
      b.appendChild(el("div", "text", clip(item.content, 500)));
    }
    line.appendChild(b);
    return line;
  });

  const closeLog = logStream("red", (pg) => {
    if (pg.reset) stream.reset();
    const items = [];
    for (const e of pg.entries || []) { const p = parseLine(e); if (p) items.push(Object.assign({ k: e.id, ts: e.ts }, p)); }
    if (items.length) stream.appendAscending(items, false);
    const n = lines.querySelectorAll(".line").length;
    lineCount.textContent = fmt(n);
    if (!n && !lines.querySelector(".empty")) lines.appendChild(el("div", "empty", EMPTY_TRACE));
  });

  refresh();
  const iv = setInterval(refresh, 2500);
  const unsub = store.subscribe((s) => { if (s) renderContext(s); });

  return function unmount() { clearInterval(iv); closeLog(); unsub(); };
}
