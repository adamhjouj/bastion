"""Feeding the shape model: the passive learner (bounded queue drained by a daemon thread, fed by
the proxy's observe-hook) and the active crawler (GET-only, same-origin, bounded)."""
import os
import queue
import re
import threading
import time
from urllib.parse import urljoin, urlsplit

import httpx

from bastion.decoy.record import looks_malicious
from bastion.decoy.shape import BODY_LIMIT, ShapeStore

QUEUE_SIZE = 256
FLUSH_SECONDS = 2.0
HREF_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#]+)["']""", re.I)
SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".pdf",
            ".zip", ".mp4", ".webp")


class PassiveLearner:
    """`observe()` → queue (drop on overflow) → thread → ShapeStore → atomic flush every 2 s."""

    def __init__(self, path, store=None, flush_seconds=FLUSH_SECONDS):
        self.path = path
        self.store = store or ShapeStore.load(path)
        self.queue = queue.Queue(maxsize=QUEUE_SIZE)
        self.flush_seconds = flush_seconds
        self.dropped = 0
        self.learned = 0
        self._thread = None
        self._stop = threading.Event()

    def observe(self, sample):
        try:
            self.queue.put_nowait(sample)
        except queue.Full:
            self.dropped += 1
            return False
        self._ensure_thread()
        return True

    def _ensure_thread(self):
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._run, name="decoy-learner", daemon=True)
            self._thread.start()

    def _run(self):
        last_flush = time.monotonic()
        while not self._stop.is_set():
            try:
                sample = self.queue.get(timeout=self.flush_seconds)
            except queue.Empty:
                sample = None
            if sample is not None:
                try:
                    # Attack-shaped requests never teach the model (their responses are not "normal").
                    if not looks_malicious(sample["method"], sample["path"], sample.get("query", ""),
                                           sample.get("request_body", "")) and self.store.learn(**sample):
                        self.learned += 1
                except Exception:
                    pass
            if self.store.dirty and time.monotonic() - last_flush >= self.flush_seconds:
                self.flush()
                last_flush = time.monotonic()

    def flush(self):
        try:
            self.store.save(self.path)
        except OSError:
            pass

    def drain(self, timeout=5.0):
        """Test/shutdown helper: process everything queued and flush."""
        deadline = time.monotonic() + timeout
        while not self.queue.empty() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.flush()

    def stop(self):
        self._stop.set()


def same_origin(base, url):
    b, u = urlsplit(base), urlsplit(url)
    return (u.scheme or b.scheme) == b.scheme and (u.netloc or b.netloc) == b.netloc


class Crawler:
    """Bounded same-origin GET crawl that learns into `store` and (optionally) keeps the real
    bodies in memory for the evaluation harness. Never sends cookies, credentials or non-GET."""

    def __init__(self, base_url, store, max_pages=40, delay=0.2, timeout=5.0, keep_bodies=False,
                 transport=None):
        self.base = base_url.rstrip("/")
        self.store = store
        self.max_pages = max_pages
        self.delay = delay
        self.timeout = timeout
        self.keep_bodies = keep_bodies
        self.transport = transport
        self.pages = []  # (path, status, headers, body) when keep_bodies

    def run(self, start_paths=("/",)):
        seen = set()
        todo = [p for p in start_paths]
        fetched = 0
        with httpx.Client(timeout=self.timeout, follow_redirects=False, transport=self.transport, trust_env=False,
                          headers={"user-agent": "Mozilla/5.0 (compatible; bastion-shape/1.0)"}) as client:
            while todo and fetched < self.max_pages:
                path = todo.pop(0)
                if path in seen:
                    continue
                seen.add(path)
                url = self.base + path
                try:
                    started = time.monotonic()
                    r = client.get(url, headers={"accept-encoding": "identity"})
                    latency = (time.monotonic() - started) * 1000
                except httpx.HTTPError:
                    continue
                client.cookies.clear()  # anonymous every time: never replay the app's session cookie
                fetched += 1
                body = r.content[:BODY_LIMIT]
                headers = [(k, v) for k, v in r.headers.multi_items()]
                query = urlsplit(path).query
                plain = urlsplit(path).path or "/"
                self.store.learn("GET", plain, query, r.status_code, headers, body,
                                 r.headers.get("content-type", ""), latency)
                if self.keep_bodies:
                    self.pages.append((path, r.status_code, headers, body))
                if "html" in r.headers.get("content-type", "").lower():
                    for link in HREF_RE.findall(body.decode("utf-8", "replace")):
                        target = urljoin(url, link)
                        if not same_origin(self.base, target):
                            continue
                        u = urlsplit(target)
                        if u.path.lower().endswith(SKIP_EXT):
                            continue
                        nxt = u.path + ("?" + u.query if u.query else "")
                        if nxt not in seen and nxt not in todo and len(todo) < self.max_pages * 4:
                            todo.append(nxt)
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("location", "")
                    target = urljoin(url, loc)
                    if same_origin(self.base, target):
                        u = urlsplit(target)
                        nxt = u.path + ("?" + u.query if u.query else "")
                        if nxt not in seen:
                            todo.append(nxt)
                if self.delay:
                    time.sleep(self.delay)
            # one probe of the app's own not-found page so error pages are learned early
            if fetched:
                try:
                    r = client.get(self.base + "/bastion-shape-probe-404", headers={"accept-encoding": "identity"})
                    self.store.learn("GET", "/bastion-shape-probe-404", "", r.status_code,
                                     list(r.headers.multi_items()), r.content[:BODY_LIMIT],
                                     r.headers.get("content-type", ""))
                    with self.store.lock:  # keep the error page, not the probe route
                        self.store.routes.pop("GET /bastion-shape-probe-404", None)
                    if self.keep_bodies:
                        self.pages.append(("/bastion-shape-probe-404", r.status_code,
                                           list(r.headers.multi_items()), r.content[:BODY_LIMIT]))
                except httpx.HTTPError:
                    pass
        return fetched


def crawl_forever(base_url, path, max_pages, interval, stop_event=None):
    """Honeypot-side loop: crawl at startup and every `interval` seconds (0 = once)."""
    while True:
        store = ShapeStore()
        try:
            Crawler(base_url, store, max_pages=max_pages).run()
            if store.samples:
                store.save(path)
        except Exception:
            pass
        if not interval or (stop_event is not None and stop_event.wait(interval)):
            return
        if stop_event is None:
            time.sleep(interval)
