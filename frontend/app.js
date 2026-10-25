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

/* Hash routes: #/<page>[/<sub...>][?query]. The first segment picks the page; the
   remainder is handed to the page as ctx.sub (e.g. #/incidents/123 -> sub "123"). */
function routeInfo() {
  const h = (location.hash || "").replace(/^#/, "");
  const [pathPart, query = ""] = h.split("?");
  const segs = pathPart.replace(/^\/+/, "").split("/").filter(Boolean);
  const path = segs.length ? "/" + segs[0] : "/";
  if (!ROUTES[path]) return { path: "/", sub: "", query };
  return { path, sub: segs.slice(1).map(decodeURIComponent).join("/"), query };
}
let current = { path: null, sub: null };
function render() {
  const info = routeInfo(), route = ROUTES[info.path];
  /* same page, new sub-path: let the page handle it in place if it can */
  if (info.path === current.path && unmount && typeof unmount.navigate === "function") {
    current = { path: info.path, sub: info.sub };
    try { unmount.navigate({ sub: info.sub, query: info.query }); } catch (_) {}
    return;
  }
  if (unmount) { try { unmount(); } catch (_) {} unmount = null; }
  clear(view);
  current = { path: info.path, sub: info.sub };
  document.querySelectorAll(".nav-item").forEach((a) => a.classList.toggle("is-active", a.dataset.route === info.path));
  try { unmount = route.mount(view, { sub: info.sub, query: info.query }) || null; } catch (e) { view.appendChild(Object.assign(document.createElement("div"), { className: "empty", textContent: "This view failed to load." })); }
}

window.addEventListener("hashchange", render);
render();

/* Feed state: say nothing while the live feed is healthy; only a dropped feed is worth
   a word, because stale data would silently mislead the operator. */
const feed = document.querySelector("[data-feed]");
store.onConn((state) => { if (feed) feed.hidden = state !== "offline"; });

store.start();
