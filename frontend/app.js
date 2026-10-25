"use strict";
/* Bastion dashboard shell — CSP-safe ES-module SPA.
   Owns the one live store (SSE), a hash router, nav + connection chrome. Each route
   mounts a page module into #view and returns an unmount cleanup. */

import { store, clear } from "./core.js";
import { mount as overview } from "./pages/overview.js";
import { mount as incidents } from "./pages/incidents.js";
import { mount as investigator } from "./pages/investigator.js";
import { mount as attacker } from "./pages/attacker.js";

const ROUTES = {
  "/": { title: "Overview", mount: overview },
  "/incidents": { title: "Incidents", mount: incidents },
  "/investigator": { title: "Investigator", mount: investigator },
  "/attacker": { title: "Attacker", mount: attacker },
};

const view = document.getElementById("view");
let unmount = null;

function routePath() {
  const h = (location.hash || "").replace(/^#/, "");
  const p = "/" + h.replace(/^\/+/, "").split("?")[0];
  return ROUTES[p] ? p : "/";
}
function render() {
  const path = routePath(), route = ROUTES[path];
  if (unmount) { try { unmount(); } catch (_) {} unmount = null; }
  clear(view);
  document.querySelectorAll(".nav-item").forEach((a) => a.classList.toggle("is-active", a.dataset.route === path));
  try { unmount = route.mount(view) || null; } catch (e) { view.appendChild(Object.assign(document.createElement("div"), { className: "empty", textContent: "This view failed to load." })); }
}

window.addEventListener("hashchange", render);
render();

/* sidebar scope — the product's mode and live connection state */
const scope = document.querySelector("[data-scope]");
const scopeText = document.querySelector("[data-scope-text]");
let _mode = "";
function paintScope(conn) {
  if (!scope) return;
  scope.dataset.live = conn === "live" ? "1" : "0";
  if (scopeText) scopeText.textContent = (_mode ? _mode + " \u00b7 " : "") + (conn === "live" ? "live" : conn === "connecting" ? "connecting" : "offline");
}
store.onConn(paintScope);
store.subscribe((s) => { if (s && s.mode && s.mode !== _mode) { _mode = s.mode; paintScope(store.conn); } });

store.start();
