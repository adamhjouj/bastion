"use strict";
/* Overview page — command center.
   KPI band + the hero request-lifecycle graph (counter-delta-gated) + active-defenses
   strip + latest-incident link. The graph animation is a pure consumer of backend
   counter deltas (a dot never advances until that node's counter increments). */

import { store, el, clear, clamp, smooth, anim, hhmmss, humanize, fmt, makeStream, openIncident } from "../core.js";

const ICON = {
  src: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>',
  bastion: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 5 5.6V11c0 4.3 2.9 7.5 7 9 4.1-1.5 7-4.7 7-9V5.6z"/><path d="m9.2 12 2 2 3.6-3.8"/></svg>',
  server: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="7" rx="1.6"/><rect x="3" y="13" width="18" height="7" rx="1.6"/><path d="M7 7.5h.01M7 16.5h.01"/></svg>',
  honeypot: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.5 20 7v10l-8 4.5L4 17V7z"/><circle cx="12" cy="12" r="3"/></svg>',
};
const KPIS = [["events", "Requests"], ["evaluated", "Screened"], ["forwarded", "Forwarded"], ["diverted", "Diverted"], ["blocked", "Blocked"], ["incidents", "Incidents"], ["contained", "Contained"]];

const TEMPLATE = `
<div class="ov">
  <div class="ov-kpis">
    ${KPIS.map(([k, label]) => `<div class="kpi"><span class="kpi-label">${label}</span><span class="kpi-val" data-k="${k}">0</span></div>`).join("")}
  </div>
  <div class="ov-body">
  <section class="stage" data-ui aria-label="Live request lifecycle">
    <canvas data-canvas></canvas>
    <div class="gnode src n-src" data-node="src"><span class="gic">${ICON.src}</span><span class="ntag">internet</span></div>
    <div class="wall n-bastion" data-node="bastion">
      <span class="wall-beam"></span>
      <span class="wall-core"><span class="gic">${ICON.bastion}</span><span class="gmeta"><span class="gname">Bastion</span><span class="gcount" data-c="bastion">0</span></span><span class="ntag">defense</span></span>
    </div>
    <div class="gnode n-server" data-node="server"><span class="gic">${ICON.server}</span><span class="gmeta"><span class="gname">Server</span><span class="gcount" data-c="server">0</span></span><span class="ntag">safe</span></div>
    <div class="gnode n-honeypot" data-node="honeypot"><span class="gic">${ICON.honeypot}</span><span class="gmeta"><span class="gname">Honeypot</span><span class="gcount" data-c="honeypot">0</span></span><span class="ntag">diverted</span></div>
    <div class="legend" aria-hidden="true"><span><i class="d safe"></i>safe</span><span><i class="d threat"></i>suspicious</span></div>
  </section>
  <section class="panel ov-stream" aria-label="Live requests">
    <div class="panel-head"><h2>Live requests</h2><span class="count" data-stream-n>0</span></div>
    <div class="panel-body" data-stream><div class="empty">Waiting for traffic.</div></div>
  </section>
  </div>
  <div class="ov-foot">
    <div class="defenses">
      <div class="def-chip"><span class="def-n" data-def="bans">0</span><span class="def-l">bans</span></div>
      <div class="def-chip"><span class="def-n" data-def="diversions">0</span><span class="def-l">diversions</span></div>
      <div class="def-chip"><span class="def-n" data-def="patches">0</span><span class="def-l">virtual patches</span></div>
    </div>
    <button class="latest" type="button" data-latest><span class="latest-none">No incidents filed</span></button>
  </div>
</div>`;

/* =================== the counter-delta-gated graph ===================
   Choreography: a node's displayed count ticks the moment a dot ENTERS it.
   At the wall the pipeline per dot is strictly sequential:
   enter -> bastion count++ -> visible processing beat -> dispatch onward dot
   (safe->server, diverted->honeypot, blocked absorbed); the destination count
   ticks when that onward dot arrives. Dots still only originate from real
   backend counter deltas. */
function createScene(root) {
  const stage = root.querySelector(".stage");
  const canvas = root.querySelector("[data-canvas]");
  const ctx = canvas.getContext("2d");

  const NODES = {};
  root.querySelectorAll("[data-node]").forEach((n) => {
    NODES[n.dataset.node] = { el: n, core: n.querySelector(".wall-core"), beam: n.querySelector(".wall-beam"), countEl: n.querySelector(".gcount"), x: 0, y: 0, shown: null, target: 0, owed: 0 };
  });
  /* test/instrumentation hooks: displayed counts + per-dot arrival log */
  window.__nodeCounts = {}; window.__arrivalLog = [];
  const CONNS = [["src", "bastion", 0.0, false], ["bastion", "server", -0.14, false], ["bastion", "honeypot", 0.14, true]];
  const CMAP = {};
  for (const c of CONNS) CMAP[c[0] + ">" + c[1]] = { from: c[0], to: c[1], bow: c[2], hot: c[3], energy: 0, geo: null };

  let W = 0, H = 0, DPR = 1, S = 1, particles = [], flares = [], running = false, last = 0, destroyed = false, rafId = 0;
  let base = null, spawnBacklog = 0, wallArrived = 0, outcomes = [], spawnCd = 0, idlePolls = 0;
  let lastSnapAt = 0, snapInterval = 1000, spawnGap = 0; // measured SSE cadence drives dot pacing (no hardcoded gap)

  function centers() { const sr = canvas.getBoundingClientRect(); for (const id in NODES) { const r = NODES[id].el.getBoundingClientRect(); NODES[id].x = r.left + r.width / 2 - sr.left; NODES[id].y = r.top + r.height / 2 - sr.top; } for (const k in CMAP) geo(CMAP[k]); }
  function geo(c) { const a = NODES[c.from], b = NODES[c.to], dx = b.x - a.x, dy = b.y - a.y, L = Math.hypot(dx, dy) || 1, nx = -dy / L, ny = dx / L, k = c.bow * clamp(L * 0.16, 14, 86); c.geo = { a: { x: a.x, y: a.y }, b: { x: b.x, y: b.y }, c1: { x: a.x + dx * 0.3 + nx * k, y: a.y + dy * 0.3 + ny * k }, c2: { x: a.x + dx * 0.7 + nx * k, y: a.y + dy * 0.7 + ny * k }, L }; }
  function bez(g, t) { const u = 1 - t, a = u * u * u, b = 3 * u * u * t, c = 3 * u * t * t, d = t * t * t; return { x: a * g.a.x + b * g.c1.x + c * g.c2.x + d * g.b.x, y: a * g.a.y + b * g.c1.y + c * g.c2.y + d * g.b.y }; }
  const DOT_SPEED = 0.62; // px per ms: constant travel speed; duration is purely distance / speed
  function segDur(c) { return Math.max((c.geo ? c.geo.L : 300) / DOT_SPEED, 140); }

  function layout() {
    if (destroyed) return;
    const r = canvas.getBoundingClientRect();
    DPR = Math.min(window.devicePixelRatio || 1, 2); W = r.width; H = r.height;
    canvas.width = Math.max(1, Math.round(W * DPR)); canvas.height = Math.max(1, Math.round(H * DPR));
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    S = clamp(Math.min(W / 1100, H / 560), 0.72, 1.3);
    centers(); draw();
  }

  /* Only the wall reacts (beam color + pass-through flare). Outcome nodes hold
     still: the counter tick is the arrival acknowledgment. */
  function ping(id, hot) {
    const n = NODES[id]; if (!n || id !== "bastion") return;
    n.el.style.setProperty("--wall-rgb", hot ? "250,93,25" : "255,255,255");
    flares.push({ y: n.y, e: 0, hot: !!hot });
    anim(n.beam, [{ filter: "brightness(1)" }, { filter: "brightness(1.9)" }, { filter: "brightness(1)" }], { duration: 480, easing: "ease-out" });
    wake();
  }

  function spawn(ids, opts) {
    opts = opts || {}; const segs = [];
    for (let i = 0; i < ids.length - 1; i++) { const c = CMAP[ids[i] + ">" + ids[i + 1]]; if (c) segs.push(c); }
    if (!segs.length || !segs[0].geo) return null;
    if (particles.length > 60) { const old = particles.shift(); if (old.onDone) old.onDone(); }
    if (ids[0] === "bastion") ping("bastion", !!opts.mal);
    const p = { segs, ids, i: 0, e: 0, dur: segDur(segs[0]), x: 0, y: 0, mal: !!opts.mal, onDone: opts.onDone || null };
    particles.push(p); wake(); return p;
  }
  function dotArrivedAtWall() { wallArrived++; arrive("bastion"); wake(); }
  function wallReady() { return wallArrived > 0 && outcomes.length > 0; } // an arrived dot releases as soon as its real outcome exists
  function dispatch(o) {
    if (o === "blocked") { ping("bastion", true); return; } // malicious absorbed at the wall
    if (o === "divert") { if (!spawn(["bastion", "honeypot"], { mal: true, onDone: () => arrive("honeypot") })) arrive("honeypot"); }
    else if (!spawn(["bastion", "server"], { mal: false, onDone: () => arrive("server") })) arrive("server");
  }

  function update(s) {
    if (destroyed) return;
    const tNow = performance.now();
    if (lastSnapAt) snapInterval = clamp(tNow - lastSnapAt, 100, 5000); // real gap since the last snapshot
    lastSnapAt = tNow;
    setTargets(s);
    const cur = { events: s.events_total || 0, evaluated: (s.funnel && s.funnel.evaluated) || 0, blocked: s.blocked_total || 0, diverted: s.diverted_total || 0 };
    if (!base) { base = cur; return; }
    if (cur.events < base.events || cur.evaluated < base.evaluated || cur.blocked < base.blocked || cur.diverted < base.diverted) {
      base = cur; spawnBacklog = 0; wallArrived = 0; outcomes.length = 0; particles = []; flares = []; settle(); draw(); return;
    }
    const dE = cur.events - base.events, dB = cur.blocked - base.blocked, dV = cur.evaluated - base.evaluated;
    const dD = Math.max(0, cur.diverted - base.diverted), dF = Math.max(0, dE - dB);
    base = cur;
    if (dE > 0) {
      const visible = Math.min(dE, Math.max(0, 32 - spawnBacklog)); spawnBacklog += visible;
      const overflow = dE - visible;
      for (let i = 0; i < overflow; i++) dotArrivedAtWall(); // overflow skips the visible flight but still "enters" the wall
    }
    spawnGap = spawnBacklog > 0 ? Math.max(16, snapInterval / spawnBacklog) : 0; // emit the batch at the rate it actually arrived
    for (let i = 0; i < dB; i++) outcomes.push("blocked");
    for (let i = 0; i < dD; i++) outcomes.push("divert");
    for (let i = 0; i < Math.max(0, dF - dD); i++) outcomes.push("safe");
    if (dE || dB || dV || dD) idlePolls = 0; else idlePolls++;
    /* Stale-queue reconcile: if the backend has been quiet for several snapshots
       and nothing is visibly in flight, drop leftover queue state and snap the
       ledger to the snapshot so the display can never drift from the backend. */
    if (idlePolls >= 3 && !particles.length && !spawnBacklog) { wallArrived = 0; outcomes.length = 0; settle(); }
    if (spawnBacklog > 0 || wallReady()) wake();
  }

  /* Arrival-ticked counters over snapshot targets: each node displays `shown`,
     converging on the authoritative backend `target`. A dot ENTERING a node
     ticks `shown` by one (never past `target`); ticks that outrun the backend
     bank in `owed` and flush as the target catches up; settle() snaps shown to
     target when the scene is fully idle. The display is therefore 1-by-1 live
     and exactly equal to the backend at rest. Snappiness comes from the
     physics: short flights, tight spawn spacing, brief wall beat.
     Ledger identity: bastion = server + honeypot, exactly.
     bastion  = admitted requests (events - blocked); blocked dots flash and are
                absorbed but never tick (arrival banks in owed; settle clears it)
     server   = admitted - diverted (what actually reached the real app)
     honeypot = diverted_total (diverted REQUESTS, not the decoy IP state) */
  function setTargets(s) {
    const admitted = Math.max(0, (s.events_total || 0) - (s.blocked_total || 0));
    const diverted = s.diverted_total || 0;
    setTarget("bastion", admitted);
    setTarget("server", Math.max(0, admitted - diverted));
    setTarget("honeypot", diverted);
  }
  function setTarget(id, v) {
    const n = NODES[id]; if (!n || !n.countEl) return;
    n.target = v;
    if (n.shown == null || v < n.shown) { n.shown = v; n.owed = 0; render(id); return; } // first snapshot / backend reset: seed instantly
    while (n.owed > 0 && n.shown < n.target) { n.owed--; n.shown++; render(id); }
  }
  function arrive(id) {
    const n = NODES[id]; if (!n || !n.countEl || n.shown == null) return;
    if (n.shown < n.target) { n.shown++; render(id); } else { n.owed++; }
    logEvt("arrive:" + id, { shown: n.shown, owed: n.owed });
  }
  function logEvt(k, extra) { window.__arrivalLog.push(Object.assign({ evt: k, t: Date.now() }, extra || {})); if (window.__arrivalLog.length > 400) window.__arrivalLog.shift(); }
  function render(id) { const n = NODES[id]; n.countEl.textContent = fmt(n.shown); window.__nodeCounts[id] = n.shown; }
  function settle() { for (const id in NODES) { const n = NODES[id]; if (!n.countEl || n.shown == null) continue; n.owed = 0; if (n.shown !== n.target) { n.shown = n.target; render(id); } } }

  function wake() { if (!running && !destroyed) { running = true; last = performance.now(); rafId = requestAnimationFrame(frame); } }
  function frame(now) {
    if (destroyed) { running = false; return; }
    const dt = Math.min(now - last, 60); last = now;
    spawnCd -= dt;
    if (spawnBacklog > 0 && spawnCd <= 0) { spawnBacklog--; spawnCd = spawnGap; if (!spawn(["src", "bastion"], { mal: false, onDone: dotArrivedAtWall })) dotArrivedAtWall(); }
    /* enter -> count -> process -> dispatch: one dot holds the wall at a time.
       Its counter already ticked on arrival (dotArrivedAtWall); here we run the
       visible classify beat, and emit the onward dot only after it completes. */
    if (wallReady()) { wallArrived--; const o = outcomes.shift(); logEvt("wall-dispatch:" + o); dispatch(o); } // release the instant the real outcome exists (incl. diverts)
    for (const k in CMAP) { const c = CMAP[k]; if (c.energy > 0) c.energy = Math.max(0, c.energy - dt / 420); }
    for (const f of flares) f.e += dt; flares = flares.filter((f) => f.e < 480);
    for (const p of particles) {
      p.e += dt; const c = p.segs[p.i], t = smooth(clamp(p.e / p.dur, 0, 1)), pt = bez(c.geo, t);
      p.x = pt.x; p.y = pt.y; c.energy = 1; c.eh = p.mal;
      if (p.e >= p.dur) { ping(p.ids[p.i + 1], p.mal); p.i++; if (p.i < p.segs.length) { p.e = 0; p.dur = segDur(p.segs[p.i]); } else { p.done = true; if (p.onDone) p.onDone(); } }
    }
    particles = particles.filter((p) => !p.done);
    draw();
    let energy = false; for (const k in CMAP) if (CMAP[k].energy > 0.01) { energy = true; break; }
    const pending = spawnBacklog > 0 || wallReady();
    if (particles.length || flares.length || energy || pending) rafId = requestAnimationFrame(frame); else { running = false; if (!spawnBacklog && !wallArrived && !outcomes.length) settle(); draw(); }
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    for (const k in CMAP) {
      const c = CMAP[k]; if (!c.geo) continue; const g = c.geo;
      ctx.beginPath(); ctx.moveTo(g.a.x, g.a.y); ctx.bezierCurveTo(g.c1.x, g.c1.y, g.c2.x, g.c2.y, g.b.x, g.b.y);
      ctx.lineWidth = 1.4; ctx.strokeStyle = "rgba(255,255,255,0.05)"; ctx.stroke();
      if (c.energy > 0.01) { ctx.lineWidth = 1.4 + c.energy; ctx.strokeStyle = c.eh ? "rgba(250,93,25," + (0.12 + c.energy * 0.5).toFixed(3) + ")" : "rgba(255,255,255," + (0.05 + c.energy * 0.28).toFixed(3) + ")"; ctx.stroke(); }
    }
    const jx = NODES.bastion ? NODES.bastion.x : 0;
    for (const f of flares) { const a = 1 - f.e / 480; if (a <= 0) continue; const col = f.hot ? "250,93,25" : "255,255,255", h = (32 + (1 - a) * 50) * S; ctx.globalAlpha = a; ctx.strokeStyle = "rgba(" + col + "," + (a * 0.7).toFixed(3) + ")"; ctx.lineWidth = 2.5 * S; ctx.shadowBlur = 16 * S; ctx.shadowColor = "rgba(" + col + ",0.85)"; ctx.beginPath(); ctx.moveTo(jx, f.y - h); ctx.lineTo(jx, f.y + h); ctx.stroke(); ctx.shadowBlur = 0; ctx.globalAlpha = 1; }
    for (const p of particles) {
      const hot = p.mal;
      ctx.shadowBlur = (hot ? 16 : 8) * S; ctx.shadowColor = hot ? "rgba(250,93,25,0.95)" : "rgba(255,255,255,0.85)";
      ctx.fillStyle = hot ? "#ff8a4c" : "#ffffff"; ctx.beginPath(); ctx.arc(p.x, p.y, (hot ? 3.3 : 2.8) * S, 0, 7); ctx.fill(); ctx.shadowBlur = 0;
    }
  }

  const ro = new ResizeObserver(layout); ro.observe(stage);
  requestAnimationFrame(layout);
  function destroy() { destroyed = true; try { ro.disconnect(); } catch (_) {} if (rafId) cancelAnimationFrame(rafId); }
  return { update, destroy };
}

/* =================== KPI band / defenses / latest incident =================== */
function num(page, key, v) { const n = page.querySelector('[data-k="' + key + '"]'); if (n) n.textContent = fmt(v); }
function updateKpis(page, s) {
  num(page, "events", s.events_total || 0);
  num(page, "evaluated", (s.funnel && s.funnel.evaluated) || 0);
  num(page, "forwarded", Math.max(0, (s.events_total || 0) - (s.blocked_total || 0)));
  num(page, "diverted", s.diverted_total || 0);
  num(page, "blocked", s.blocked_total || 0);
  num(page, "incidents", s.incidents_total || 0);
  num(page, "contained", (s.denylist ? s.denylist.length : 0) + (s.honeypot ? s.honeypot.length : 0) + (s.vpatch ? s.vpatch.length : 0));
}
function updateDefenses(page, s) {
  const set = (k, v) => { const n = page.querySelector('[data-def="' + k + '"]'); if (n) n.textContent = fmt(v); };
  set("bans", s.denylist ? s.denylist.length : 0);
  set("diversions", s.honeypot ? s.honeypot.length : 0);
  set("patches", s.vpatch ? s.vpatch.length : 0);
}
function updateLatest(page, s) {
  const btn = page.querySelector("[data-latest]"); if (!btn) return;
  const inc = (s.incidents && s.incidents[0]) || null;
  clear(btn);
  if (!inc) { btn.disabled = true; btn.appendChild(el("span", "latest-none", "No incidents filed")); btn.dataset.id = ""; return; }
  btn.disabled = false; btn.dataset.id = inc.id;
  const sev = el("span", "sev"); sev.dataset.sev = inc.severity || ""; btn.appendChild(sev);
  btn.appendChild(el("span", "latest-label", "Latest"));
  btn.appendChild(el("span", "latest-type", clip(humanize(inc.attack_type) || "incident", 46)));
  btn.appendChild(el("time", "latest-time", hhmmss(inc.ts)));
  btn.appendChild(el("span", "latest-chev", "\u203a"));
}
function clip(s, n) { s = String(s == null ? "" : s); return s.length > n ? s.slice(0, n - 1) + "…" : s; }

/* live request tape — one line per request, coloured only when the defense acted */
function eventNode(item) {
  const e = item.e;
  const line = el("div", "ev");
  line.appendChild(el("time", null, hhmmss(e.ts)));
  line.appendChild(el("span", "ev-method", e.method || "GET"));
  line.appendChild(el("span", "ev-path", clip((e.path || "/") + (e.query ? "?" + e.query : ""), 48)));
  const mal = !!((e.verdict && e.verdict.malicious) || e.blocked || e.matched === "diverted" || e.matched === "denylist");
  const out = e.blocked ? "blocked" : e.matched === "diverted" ? "diverted" : (e.verdict && e.verdict.malicious) ? "flagged" : (e.status == null ? "\u2014" : String(e.status));
  line.appendChild(el("span", "ev-out" + (mal ? " hot" : ""), out));
  return line;
}

/* =================== mount =================== */
export function mount(root) {
  const wrap = el("div", "page p-overview");
  wrap.innerHTML = TEMPLATE;
  root.appendChild(wrap);
  const page = wrap.querySelector(".ov");
  const scene = createScene(page);
  const latestBtn = page.querySelector("[data-latest]");
  if (latestBtn) latestBtn.addEventListener("click", () => { if (latestBtn.dataset.id) openIncident(latestBtn.dataset.id); });
  const streamBody = page.querySelector("[data-stream]");
  const streamN = page.querySelector("[data-stream-n]");
  const stream = makeStream(streamBody, 60, eventNode);
  let streamHas = false;
  const unsub = store.subscribe((s) => {
    if (!s) return;
    scene.update(s); updateKpis(page, s); updateDefenses(page, s); updateLatest(page, s);
    const evs = (s.events || []).slice().sort((a, b) => (b.id || 0) - (a.id || 0)).slice(0, 60).map((e) => ({ k: "e" + e.id, e }));
    if (streamN) streamN.textContent = fmt(s.events_total || 0);
    if (!evs.length) { if (streamHas) { stream.reset(); streamBody.appendChild(el("div", "empty", "Waiting for traffic.")); streamHas = false; } }
    else { streamHas = true; stream.syncNewestFirst(evs); }
  });
  return function unmount() { unsub(); scene.destroy(); };
}
