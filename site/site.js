/* Bastion marketing page. Vanilla, no dependencies.
   1. reveals  2. the live request demonstration  3. the action switches  4. the revert control  5. the mail form */
(() => {
  'use strict';
  const calm = matchMedia('(prefers-reduced-motion: reduce)');

  /* 1. reveals: once, when the element enters; nothing stays hidden if the observer is missing */
  const revealed = [...document.querySelectorAll('[data-reveal]')];
  if ('IntersectionObserver' in window) {
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) if (e.isIntersecting) { e.target.classList.add('is-in'); io.unobserve(e.target); }
    }, { rootMargin: '0px 0px -10% 0px', threshold: 0.05 });
    revealed.forEach((el) => io.observe(el));
  } else {
    revealed.forEach((el) => el.classList.add('is-in'));
  }

  /* 2. the live request: pick or type a request, it travels Internet -> Bastion -> Server or Decoy.
        The verdict here is computed from a few fixed patterns; the product asks a zero-shot model. */
  const form = document.getElementById('demo-form');
  if (form) {
    const input = document.getElementById('demo-path');
    const chips = [...form.querySelectorAll('[data-req]')];
    const dot = document.getElementById('demo-dot');
    const state = document.getElementById('node-bastion-state');
    const route = document.querySelector('.demo__route');
    const svg = route.querySelector('svg');
    const nodes = {
      internet: document.querySelector('.node--internet'),
      bastion: document.querySelector('.node--bastion'),
      server: document.querySelector('.node--server'),
      decoy: document.querySelector('.node--decoy'),
    };
    const legs = {
      in: document.getElementById('leg-in'),
      server: document.getElementById('leg-server'),
      decoy: document.getElementById('leg-decoy'),
    };
    const out = {
      verdict: document.getElementById('v-verdict'),
      route: document.getElementById('v-route'),
      action: document.getElementById('v-action'),
    };
    const tape = document.getElementById('demo-tape');
    const THRESHOLD = 0.5;
    const RULES = [
      { type: 'sql_injection', score: 0.97, re: /'\s*(or|and)\s*['\d(]|\bor\s+1\s*=\s*1\b|union\s+select|;\s*(drop|delete|insert)\b|'\s*--|sleep\s*\(/i },
      { type: 'command_injection', score: 0.91, re: /[;|`]\s*(id|cat|ls|whoami|uname|curl|wget|nc|bash|sh|ping)\b|\$\(|\|\|/i },
      { type: 'path_traversal', score: 0.94, re: /\.\.[\\/]|\/etc\/(passwd|shadow|hosts)|\/proc\/self|\.\.%2f/i },
      { type: 'xss', score: 0.86, re: /<\s*script|javascript:|\son\w+\s*=|<\s*(svg|img|iframe)\b/i },
    ];
    const decode = (s) => { try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch { return s; } };
    const normalise = (raw) => {
      let p = raw.trim().replace(/^(get|post)\s+/i, '');
      if (!p.startsWith('/')) p = '/' + p;
      return p;
    };
    const benignScore = (p) => {
      let h = 0;
      for (const ch of p) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
      return 0.02 + (h % 12) / 100;
    };
    const judge = (path) => {
      const text = decode(path);
      const hit = RULES.find((r) => r.re.test(text));
      if (hit) return { malicious: true, score: hit.score, type: hit.type };
      return { malicious: false, score: benignScore(text), type: 'benign' };
    };

    /* the legs are drawn from where the nodes really are, so they meet the nodes at any width;
       the paths authored in the HTML are the no-script fallback */
    const P = { source: [96, 75], gate: [250, 75], exit: [342, 75], server: [504, 30], decoy: [504, 120] };
    const GAP = 6;
    const rel = (el) => {
      const box = route.getBoundingClientRect(); const r = el.getBoundingClientRect();
      return { l: r.left - box.left, r: r.right - box.left, cy: (r.top + r.bottom) / 2 - box.top };
    };
    const curve = (a, b) => {
      const x0 = a.r + GAP, x1 = b.l - GAP, dx = (x1 - x0) * 0.5;
      return `M ${x0} ${a.cy} C ${x0 + dx} ${a.cy} ${x1 - dx} ${b.cy} ${x1} ${b.cy}`;
    };
    const layoutRoute = () => {
      const W = route.clientWidth, H = route.clientHeight;
      if (!W || !H) return;
      svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
      const i = rel(nodes.internet), g = rel(nodes.bastion), s = rel(nodes.server), d = rel(nodes.decoy);
      legs.in.setAttribute('d', `M ${i.r + GAP} ${i.cy} L ${g.l - GAP} ${g.cy}`);
      legs.server.setAttribute('d', curve(g, s));
      legs.decoy.setAttribute('d', curve(g, d));
      P.source = [i.r + GAP, i.cy]; P.gate = [g.l - GAP, g.cy]; P.exit = [g.r + GAP, g.cy];
      P.server = [s.l - GAP, s.cy]; P.decoy = [d.l - GAP, d.cy];
    };
    const place = ([x, y]) => { dot.style.transform = `translate(${x}px, ${y}px) translate(-50%, -50%)`; };
    const jump = (to) => { dot.style.transition = 'none'; place(to); void dot.offsetWidth; dot.style.transition = ''; };
    let queued = false;
    addEventListener('resize', () => { if (!queued) { queued = true; requestAnimationFrame(() => { queued = false; layoutRoute(); }); } });
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(layoutRoute);
    layoutRoute();
    const wait = (ms) => new Promise((r) => setTimeout(r, calm.matches ? 0 : ms));
    let run = 0;

    const reset = () => {
      Object.values(nodes).forEach((n) => n.classList.remove('is-on', 'is-heat'));
      Object.values(legs).forEach((l) => l.classList.remove('is-lit', 'is-heat'));
      dot.classList.remove('is-moving', 'is-heat');
      state.textContent = 'screening';
    };

    const show = (path, v) => {
      const pathOnly = path.split('?')[0];
      out.verdict.textContent = v.malicious ? `malicious ${v.score.toFixed(2)} · ${v.type}` : `benign ${v.score.toFixed(2)}`;
      out.verdict.className = v.malicious ? 'heat' : 'pos';
      out.route.textContent = v.malicious ? 'diverted → Decoy' : 'forwarded → Server · 200';
      out.action.textContent = v.malicious ? `divert_to_honeypot · virtual_patch ${pathOnly} · undo: undivert, remove_vpatch` : 'none';
      const li = document.createElement('li');
      const t = document.createElement('span'); t.textContent = 'now';
      const r = document.createElement('code'); r.textContent = 'GET ' + path;
      const s = document.createElement('samp'); s.className = v.malicious ? 'heat' : 'pos'; s.textContent = v.malicious ? 'diverted' : '200';
      li.append(t, r, s);
      const top = tape.firstElementChild;
      if (top && top.firstElementChild.textContent === 'now' && top.querySelector('code').textContent === 'GET ' + path) top.remove();
      tape.querySelectorAll('li').forEach((row, i) => { if (i === 0) row.firstElementChild.textContent = 'earlier'; });
      tape.prepend(li);
      while (tape.children.length > 6) tape.lastElementChild.remove();
    };

    const send = async (path) => {
      const id = ++run;
      const v = judge(path);
      reset();
      state.textContent = 'screening';
      layoutRoute();
      jump(P.source);
      dot.classList.add('is-moving');
      await wait(30);
      place(P.gate);
      await wait(720);
      if (id !== run) return;
      legs.in.classList.add('is-lit');
      nodes.bastion.classList.add(v.malicious ? 'is-heat' : 'is-on');
      state.textContent = v.malicious ? `judged ${v.score.toFixed(2)} · ${v.type}` : `judged ${v.score.toFixed(2)} · benign`;
      layoutRoute();
      if (v.malicious) dot.classList.add('is-heat');
      await wait(420);
      if (id !== run) return;
      place(P.exit);
      await wait(40);
      const target = v.malicious ? 'decoy' : 'server';
      place(P[target]);
      legs[target].classList.add(v.malicious ? 'is-heat' : 'is-lit');
      await wait(720);
      if (id !== run) return;
      nodes[target].classList.add(v.malicious ? 'is-heat' : 'is-on');
      show(path, v);
    };

    chips.forEach((chip) => {
      chip.addEventListener('click', () => {
        chips.forEach((c) => c.setAttribute('aria-pressed', String(c === chip)));
        input.value = chip.dataset.req;
        send(normalise(input.value));
      });
    });
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const path = normalise(input.value);
      input.value = path;
      chips.forEach((c) => c.setAttribute('aria-pressed', String(c.dataset.req === path)));
      send(path);
    });

    /* the first screen shows the default request already judged; animate it once when the stage is in view */
    const first = () => send(normalise(input.value));
    if ('IntersectionObserver' in window) {
      const once = new IntersectionObserver((entries) => {
        if (entries.some((e) => e.isIntersecting)) { once.disconnect(); setTimeout(first, 500); }
      }, { threshold: 0.3 });
      once.observe(form);
    } else {
      first();
    }
  }

  /* 3. the action switches: a band is on when its switch is on */
  document.querySelectorAll('.band .switch').forEach((sw) => {
    sw.addEventListener('click', () => {
      const on = sw.getAttribute('aria-checked') !== 'true';
      sw.setAttribute('aria-checked', String(on));
      sw.closest('.band').dataset.on = String(on);
    });
  });

  /* 4. the revert control: one click writes the compensating record; the original stays */
  const undo = document.getElementById('undo');
  if (undo) {
    const btn = document.getElementById('revert-btn');
    const word = document.getElementById('undo-word');
    const resetBtn = document.getElementById('undo-reset');
    btn.addEventListener('click', () => {
      undo.dataset.reverted = 'true';
      btn.disabled = true;
      btn.textContent = 'Reverted';
      word.textContent = 'undid';
    });
    resetBtn.addEventListener('click', () => {
      undo.dataset.reverted = 'false';
      btn.disabled = false;
      btn.textContent = 'Revert';
      word.textContent = 'undoes';
      btn.focus();
    });
  }

  /* 5. the mail form: opens the visitor's mail client with the subject and body written */
  const cta = document.getElementById('cta-form');
  if (cta) {
    cta.addEventListener('submit', (e) => {
      e.preventDefault();
      const app = document.getElementById('cta-app').value.trim() || 'our app';
      const subject = encodeURIComponent(`Pilot: Bastion in front of ${app}`);
      const body = encodeURIComponent(`Hello,\n\nWe would like to put Bastion in front of ${app}.\n\nStack and hosting:\nRough traffic:\nWho to talk to:\n`);
      location.href = `mailto:hello@bastion.example?subject=${subject}&body=${body}`;
    });
  }
})();
