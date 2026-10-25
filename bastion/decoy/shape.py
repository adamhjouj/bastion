"""The shape model: per-route response templates + site-wide fingerprints, bounded, persisted as
one JSON file per writer (passive.json by the proxy, crawl.json by the honeypot). docs/DECOY.md §1."""
import difflib
import hashlib
import json
import os
import re
import threading
import time
from collections import Counter

from bastion.privacy import form_view
from bastion.decoy import skeleton

BODY_LIMIT = 32 * 1024
MAX_ROUTES = int(os.getenv("DECOY_MAX_ROUTES", "200"))
MAX_VARIANTS = 3
MAX_ASSETS = 40
MAX_PARAMS = 24
MAX_LINKS = 60

HEADER_SUBSET = ("server", "x-powered-by", "content-type", "cache-control", "pragma", "expires",
                 "vary", "location", "x-frame-options", "content-language", "allow")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
TITLE_SEP_RE = re.compile(r"\s+(?:&ndash;|&mdash;|–|—|\||-|::|·)\s+")
ASSET_RE = re.compile(r"""<(?:link|script)\b[^>]*?(?:href|src)\s*=\s*["']([^"']+)["']""", re.I)
LINK_RE = re.compile(r"""<a\b[^>]*?href\s*=\s*["']([^"'#?]+)[^"']*["'][^>]*>(.*?)</a>""", re.S | re.I)
PASSWORD_INPUT_RE = re.compile(r"""<input\b[^>]*type\s*=\s*["']?password""", re.I)
FORM_RE = re.compile(r"""<form\b[^>]*?(?:action\s*=\s*["']([^"']*)["'])?[^>]*>""", re.I)
ID_SEG_RE = re.compile(r"[0-9a-fA-F]{8,}|[0-9a-fA-F-]{32,}")


def route_pattern(path):
    out = []
    for seg in path.split("/"):
        if seg.isdigit():
            out.append("{n}")
        elif ID_SEG_RE.fullmatch(seg):
            out.append("{id}")
        else:
            out.append(seg)
    return "/".join(out) or "/"


def route_key(method, path):
    return f"{method.upper()} {route_pattern(path)}"


def body_kind(content_type, status):
    ct = (content_type or "").lower()
    if 300 <= status < 400:
        return "redirect"
    if "html" in ct:
        return "html"
    if "json" in ct:
        return "json"
    if ct.startswith("text/") or "javascript" in ct or "xml" in ct or "css" in ct:
        return "asset"
    if not ct:
        return "empty"
    return "binary"


def cookie_names(headers):
    names = []
    for k, v in headers:
        if k.lower() == "set-cookie" and "=" in v:
            name = v.split("=", 1)[0].strip()
            if name and name not in names:
                names.append(name)
    return names


def header_subset(headers):
    out = {}
    for k, v in headers:
        kl = k.lower()
        if kl in HEADER_SUBSET and kl not in out:
            if kl == "location":
                v = _redact_location(v)
            out[kl] = str(v)[:200]
    return out


def _redact_location(location):
    if "?" not in location:
        return location
    base, query = location.split("?", 1)
    pairs = form_view(query)
    from urllib.parse import urlencode
    return base + "?" + urlencode(pairs)


def _ewma(old, new, alpha=0.3):
    if old is None:
        return float(new)
    return round(old * (1 - alpha) + float(new) * alpha, 1)


def _seq_hash(seq):
    return hashlib.sha1("\n".join(seq).encode()).hexdigest()[:16]


class ShapeStore:
    def __init__(self, max_routes=None):
        self.lock = threading.RLock()
        self.max_routes = max_routes or MAX_ROUTES
        self.routes = {}
        self.fingerprint = {"server": None, "powered_by": None, "cookies": [], "assets": [],
                            "title_suffix": None, "titles": {}}
        self.errors = {}
        self.updated = None
        self.samples = 0
        self.dirty = False

    # ---- learning -------------------------------------------------------------------------
    def learn(self, method, path, query="", status=200, headers=(), body=b"", content_type=None,
              latency_ms=None, request_body="", request_content_type=""):
        """Fold one observed (request facts, response) pair into the model. `headers` is an
        iterable of (name, value); cookie values and anything outside HEADER_SUBSET are dropped."""
        if path.startswith("/__"):
            return False
        headers = [(k.decode() if isinstance(k, bytes) else k, v.decode("latin1") if isinstance(v, bytes) else v)
                   for k, v in headers]
        hdr = header_subset(headers)
        content_type = content_type or hdr.get("content-type", "")
        hdr["content-type"] = content_type
        kind = body_kind(content_type, int(status))
        body = bytes(body or b"")[:BODY_LIMIT]
        text = body.decode("utf-8", "replace") if kind in ("html", "json", "asset") else ""
        params = skeleton.redacted_pairs(query, request_body, request_content_type)
        variant = {"status": int(status), "kind": kind, "headers": hdr, "seen": 1,
                   "latency_ms": _ewma(None, latency_ms) if latency_ms is not None else None,
                   "set_cookie": bool(cookie_names(headers)), "truncated": len(body) >= BODY_LIMIT}
        if kind == "html":
            parts, open_tags = skeleton.skeletonize_html(text, params)
            variant.update(parts=parts, open=open_tags, login_form=bool(PASSWORD_INPUT_RE.search(text)),
                           forms=[a or "" for a in FORM_RE.findall(text)][:8],
                           links=[(href, re.sub(r"<[^>]+>", "", label).strip()[:40])
                                  for href, label in LINK_RE.findall(text)][:MAX_LINKS])
            variant["seq"] = _seq_hash(skeleton.tag_sequence(parts))
        elif kind == "json":
            sj = skeleton.skeletonize_json(text)
            if sj is None:
                kind = variant["kind"] = "asset"
                variant["parts"] = skeleton.mask_secrets(text)
            else:
                variant["schema"], variant["example"] = sj
                variant["compact"] = not re.search(r"[,:]\s", text[:4096])
                variant["seq"] = _seq_hash([json.dumps(sj[0], sort_keys=True)])
        elif kind == "asset":
            variant["parts"] = skeleton.mask_secrets(text)
            variant["seq"] = hashlib.sha1(text[:2048].encode()).hexdigest()[:16]
        elif kind == "redirect":
            variant["location"] = hdr.get("location", "/")
            variant["seq"] = variant["location"]
        else:
            variant["seq"] = kind
            variant["length"] = len(body)
        with self.lock:
            self._fingerprint(headers, text if kind == "html" else "", int(status))
            key = route_key(method, path)
            route = self.routes.get(key)
            if route is None:
                if len(self.routes) >= self.max_routes:
                    return False
                route = self.routes[key] = {"method": method.upper(), "pattern": route_pattern(path),
                                            "seen": 0, "variants": [], "params": []}
            route["seen"] += 1
            for name, _ in params:
                if name not in route["params"] and len(route["params"]) < MAX_PARAMS:
                    route["params"].append(name)
            self._add_variant(route, variant)
            if kind == "html" and int(status) >= 400:
                self.errors[str(status)] = variant
            self.samples += 1
            self.updated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self.dirty = True
        return True

    def _add_variant(self, route, variant):
        for existing in route["variants"]:
            if existing["status"] == variant["status"] and existing.get("seq") == variant.get("seq"):
                if "parts" in existing and "parts" in variant:
                    merged = skeleton.merge_parts(existing["parts"], variant["parts"])
                    if merged is not None:
                        existing["parts"] = merged
                existing["seen"] += 1
                if variant.get("latency_ms") is not None:
                    existing["latency_ms"] = _ewma(existing.get("latency_ms"), variant["latency_ms"])
                existing["headers"] = variant["headers"]  # latest observation wins
                return
        if len(route["variants"]) >= MAX_VARIANTS:
            route["variants"].sort(key=lambda v: v["seen"])
            route["variants"].pop(0)
        route["variants"].append(variant)

    def _fingerprint(self, headers, html_text, status):
        fp = self.fingerprint
        for k, v in headers:
            kl = k.lower()
            if kl == "server" and v:
                fp["server"] = v[:80]
            elif kl == "x-powered-by" and v:
                fp["powered_by"] = v[:80]
        for name in cookie_names(headers):
            if name not in fp["cookies"] and len(fp["cookies"]) < 8:
                fp["cookies"].append(name)
        if not html_text:
            return
        for asset in ASSET_RE.findall(html_text):
            if asset.startswith(("http://", "https://", "//")):
                continue
            if asset not in fp["assets"] and len(fp["assets"]) < MAX_ASSETS:
                fp["assets"].append(asset[:200])
        m = TITLE_RE.search(html_text)
        if m and status < 400:
            title = re.sub(r"\s+", " ", m.group(1)).strip()
            pieces = TITLE_SEP_RE.split(title)
            if len(pieces) >= 2:
                suffix = pieces[-1][:80]
                fp["titles"][suffix] = fp["titles"].get(suffix, 0) + 1
                fp["titles"] = dict(Counter(fp["titles"]).most_common(8))
                fp["title_suffix"] = Counter(fp["titles"]).most_common(1)[0][0]
            elif not fp.get("title_suffix") and title:
                fp["title_suffix"] = title[:80]

    # ---- lookup ---------------------------------------------------------------------------
    def lookup(self, method, path):
        with self.lock:
            method = method.upper()
            route = self.routes.get(route_key(method, path))
            if route is None and method == "HEAD":
                route = self.routes.get(route_key("GET", path))
            return route

    def error_variant(self, status=404):
        with self.lock:
            v = self.errors.get(str(status))
            if v is None and status != 404:
                v = self.errors.get("404")
            return v

    def login_routes(self):
        """Routes whose GET page carries a password field → (pattern, form action)."""
        with self.lock:
            out = {}
            for key, route in self.routes.items():
                for v in route["variants"]:
                    if v.get("login_form"):
                        actions = [a for a in v.get("forms", []) if a] or [route["pattern"]]
                        out[route["pattern"]] = actions[0]
            return out

    def nav_links(self):
        with self.lock:
            counts = Counter()
            labels = {}
            for route in self.routes.values():
                for v in route["variants"]:
                    for href, label in v.get("links", []):
                        counts[href] += 1
                        labels.setdefault(href, label)
            return [(href, labels[href]) for href, _ in counts.most_common(12)]

    def summary(self):
        """Compact, prompt-safe description of the learned app (no bodies, no data)."""
        with self.lock:
            return {
                "title_suffix": self.fingerprint.get("title_suffix"),
                "server": self.fingerprint.get("server"),
                "powered_by": self.fingerprint.get("powered_by"),
                "cookies": list(self.fingerprint.get("cookies", [])),
                "assets": list(self.fingerprint.get("assets", []))[:12],
                "nav": self.nav_links(),
                "routes": [{"route": key, "status": sorted({v["status"] for v in r["variants"]}),
                            "kind": r["variants"][0]["kind"] if r["variants"] else None,
                            "params": r["params"][:8], "login_form": any(v.get("login_form") for v in r["variants"])}
                           for key, r in sorted(self.routes.items())][:60],
                "error_pages": sorted(self.errors),
                "samples": self.samples, "updated": self.updated,
            }

    def fingerprint_headers(self):
        fp = self.fingerprint
        out = []
        if fp.get("server"):
            out.append(("server", fp["server"]))
        if fp.get("powered_by"):
            out.append(("x-powered-by", fp["powered_by"]))
        return out

    def closest_route(self, method, path):
        """The learned route most similar to `path` (for LLM context and HEAD/POST fallbacks)."""
        with self.lock:
            best, score = None, 0.0
            pattern = route_pattern(path)
            for key, route in self.routes.items():
                if not any(v["kind"] == "html" and v["status"] < 400 for v in route["variants"]):
                    continue
                s = difflib.SequenceMatcher(None, route["pattern"], pattern).ratio()
                if route["method"] == method.upper():
                    s += 0.1
                if s > score:
                    best, score = route, s
            return best

    # ---- persistence ----------------------------------------------------------------------
    def to_dict(self):
        with self.lock:
            return {"version": 1, "updated": self.updated, "samples": self.samples,
                    "fingerprint": self.fingerprint, "errors": self.errors, "routes": self.routes}

    @classmethod
    def from_dict(cls, data, max_routes=None):
        store = cls(max_routes=max_routes)
        if not isinstance(data, dict) or data.get("version") != 1:
            return store
        store.routes = dict(list(data.get("routes", {}).items())[:store.max_routes])
        store.fingerprint = {**store.fingerprint, **data.get("fingerprint", {})}
        store.errors = data.get("errors", {})
        store.updated = data.get("updated")
        store.samples = int(data.get("samples", 0))
        return store

    def save(self, path):
        path = str(path)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = f"{path}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, path)
        with self.lock:
            self.dirty = False

    @classmethod
    def load(cls, path, max_routes=None):
        try:
            with open(path, encoding="utf-8") as f:
                return cls.from_dict(json.load(f), max_routes=max_routes)
        except (OSError, ValueError):
            return cls(max_routes=max_routes)

    def merge(self, other, prefer_other=False):
        """Union of two models; on a route present in both, `prefer_other` picks the winner."""
        with self.lock, other.lock:
            for key, route in other.routes.items():
                if key not in self.routes or prefer_other:
                    if key not in self.routes and len(self.routes) >= self.max_routes:
                        continue
                    self.routes[key] = route
            for k, v in other.fingerprint.items():
                if isinstance(v, list):
                    for item in v:
                        if item not in self.fingerprint.setdefault(k, []):
                            self.fingerprint[k].append(item)
                elif isinstance(v, dict):
                    for item, n in v.items():
                        self.fingerprint.setdefault(k, {})[item] = self.fingerprint[k].get(item, 0) + n
                elif v and (prefer_other or not self.fingerprint.get(k)):
                    self.fingerprint[k] = v
            if self.fingerprint.get("titles"):
                self.fingerprint["title_suffix"] = Counter(self.fingerprint["titles"]).most_common(1)[0][0]
            for status, v in other.errors.items():
                if status not in self.errors or prefer_other:
                    self.errors[status] = v
            self.samples += other.samples
            self.updated = max(filter(None, [self.updated, other.updated]), default=None)
            return self


class ShapeFiles:
    """Honeypot-side view: merge `passive.json` (proxy) and `crawl.json` (crawler), reloading
    when either file changes; checked at most every `interval` seconds."""

    def __init__(self, directory, interval=2.0):
        self.directory = directory
        self.interval = interval
        self._mtimes = None
        self._checked = 0.0
        self._shape = ShapeStore()
        self.lock = threading.Lock()

    def current(self):
        now = time.monotonic()
        with self.lock:
            if now - self._checked < self.interval:
                return self._shape
            self._checked = now
            paths = [os.path.join(str(self.directory), name) for name in ("passive.json", "crawl.json")]
            mtimes = tuple(_mtime(p) for p in paths)
            if mtimes != self._mtimes:
                merged = ShapeStore.load(paths[1])            # crawl first …
                merged.merge(ShapeStore.load(paths[0]), prefer_other=True)  # … passive wins
                self._shape, self._mtimes = merged, mtimes
            return self._shape


def _mtime(path):
    try:
        return os.stat(path).st_mtime_ns
    except OSError:
        return None
