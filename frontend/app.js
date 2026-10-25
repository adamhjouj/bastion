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
const crumb = document.querySelector("[data-crumb]");
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
  if (crumb) crumb.textContent = route.title;
  document.querySelectorAll(".nav-item").forEach((a) => a.classList.toggle("is-active", a.dataset.route === path));
  try { unmount = route.mount(view) || null; } catch (e) { view.appendChild(Object.assign(document.createElement("div"), { className: "empty", textContent: "This view failed to load." })); }
}

window.addEventListener("hashchange", render);
render();
store.start();
