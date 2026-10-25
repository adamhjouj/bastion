"""Per-visitor memory for the decoy: identity = ip + user-agent, a seed for consistent fake data,
fake auth state, a bounded response cache and a bounded history. In-process, LRU-bounded."""
import hashlib
import os
import threading
import time
from collections import OrderedDict

MAX_SESSIONS = 500
MAX_HISTORY = 50
MAX_CACHE_ENTRIES = 24
CACHE_BYTES = int(os.getenv("DECOY_CACHE_BYTES", str(32 * 1024 * 1024)))
IDLE_SECONDS = 6 * 3600


def session_id(ip, user_agent):
    return hashlib.sha256(f"{ip}|{user_agent}".encode("utf-8", "replace")).hexdigest()[:16]


class Session:
    def __init__(self, sid, ip, user_agent, salt):
        self.id = sid
        self.ip = ip
        self.user_agent = user_agent[:200]
        self.seed = hashlib.sha256(f"{salt}|{sid}".encode()).hexdigest()
        self.created = time.time()
        self.last = self.created
        self.hits = 0
        self.auth = None  # fake "logged in as" username once a login is granted
        self.login_attempts = 0
        self.grant_after = 2 + int(self.seed[:2], 16) % 4  # 2..5 attempts before a fake grant
        self.cookie_value = self.seed[:32]
        self.history = []
        self.cache = OrderedDict()
        self.cache_bytes = 0

    def remember(self, entry):
        self.history.append(entry)
        if len(self.history) > MAX_HISTORY:
            del self.history[0]

    def cache_key(self, method, path, query, body_digest):
        return f"{method} {path}?{query}#{body_digest}#{'a' if self.auth else '-'}"

    def cache_get(self, key):
        item = self.cache.get(key)
        if item is None:
            return None
        self.cache.move_to_end(key)
        return item[0]

    def cache_put(self, key, item, size):
        if key in self.cache:
            self.cache_bytes -= self.cache[key][1]
            del self.cache[key]
        self.cache[key] = (item, size)
        self.cache_bytes += size
        while len(self.cache) > MAX_CACHE_ENTRIES:
            _, (_, s) = self.cache.popitem(last=False)
            self.cache_bytes -= s

    def memory(self):
        """Prompt-safe recent activity (no bodies)."""
        return {"auth": self.auth, "hits": self.hits, "login_attempts": self.login_attempts,
                "recent": [{"method": h["method"], "path": h["path"], "status": h["status"]}
                           for h in self.history[-12:]]}


class Sessions:
    def __init__(self, salt=None, max_sessions=MAX_SESSIONS, cache_bytes=None):
        self.salt = salt or os.getenv("DECOY_SALT") or os.urandom(16).hex()
        self.max_sessions = max_sessions
        self.cache_bytes = cache_bytes or CACHE_BYTES
        self.lock = threading.Lock()
        self.items = OrderedDict()

    def get(self, ip, user_agent):
        sid = session_id(ip, user_agent or "")
        with self.lock:
            s = self.items.get(sid)
            now = time.time()
            if s is None or now - s.last > IDLE_SECONDS:
                s = Session(sid, ip, user_agent or "", self.salt)
                self.items[sid] = s
            else:
                self.items.move_to_end(sid)
            s.last = now
            self._evict()
            return s

    def _evict(self):
        while len(self.items) > self.max_sessions:
            self.items.popitem(last=False)
        total = sum(s.cache_bytes for s in self.items.values())
        while total > self.cache_bytes and self.items:
            _, s = self.items.popitem(last=False)
            total -= s.cache_bytes

    def __len__(self):
        return len(self.items)
