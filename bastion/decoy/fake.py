"""Deterministic plausible fake data. Everything derives from a seed so one visitor sees the
same user, ids and tokens across pages; nothing here is real application data."""
import hashlib
import html
import random

FIRST = ["ana", "ben", "chloe", "dan", "eva", "farid", "gina", "hugo", "ines", "jonas", "kai",
         "lena", "marc", "nora", "omar", "pia", "quinn", "rosa", "sam", "tara", "uli", "vera"]
LAST = ["adler", "baker", "costa", "dubois", "egan", "fischer", "garcia", "haddad", "ito",
        "jensen", "kowalski", "lindqvist", "moreau", "novak", "okafor", "patel", "quist",
        "rossi", "silva", "tanaka", "ueda", "varga"]
DOMAINS = ["example.net", "corp.internal", "mail.example.org", "intra.local"]
WORDS = ["service", "report", "queue", "ticket", "node", "batch", "region", "policy", "window",
         "archive", "ledger", "export", "review", "status", "release", "backlog", "cluster",
         "invoice", "shift", "summary", "routine", "metric", "profile", "segment", "snapshot"]
PHRASES = [
    "Last sync completed without warnings.", "Pending review by the operations team.",
    "Scheduled maintenance window applies.", "Values refresh every fifteen minutes.",
    "No outstanding items for this period.", "Export available in the archive section.",
    "Changes take effect after the next cycle.", "Contact the service desk for access.",
    "Records older than ninety days are archived.", "Approved under the standard policy.",
]


class Faker:
    def __init__(self, seed):
        self.seed = str(seed)
        base = hashlib.sha256(self.seed.encode()).digest()
        self.rng = random.Random(int.from_bytes(base[:8], "big"))
        self.first = self.rng.choice(FIRST)
        self.last = self.rng.choice(LAST)
        self.domain = self.rng.choice(DOMAINS)

    def _rng(self, index, hint=""):
        digest = hashlib.sha256(f"{self.seed}|{index}|{hint}".encode()).digest()
        return random.Random(int.from_bytes(digest[:8], "big"))

    def username(self):
        return f"{self.first[0]}.{self.last}"

    def email(self):
        return f"{self.first}.{self.last}@{self.domain}"

    def token(self, length=32, index=0, hint=""):
        rng = self._rng(index, "token:" + hint)
        length = max(8, min(int(length) or 32, 128))
        return "".join(rng.choice("0123456789abcdef") for _ in range(length))

    def number(self, length=3, index=0, hint=""):
        rng = self._rng(index, "number:" + hint)
        length = max(1, min(int(length) or 1, 12))
        first = rng.choice("123456789")
        return first + "".join(rng.choice("0123456789") for _ in range(length - 1))

    def ipv4(self, index=0):
        rng = self._rng(index, "ip")
        return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"

    def date(self, length=10, index=0):
        rng = self._rng(index, "date")
        y, m, d = 2024, rng.randint(1, 12), rng.randint(1, 28)
        if length > 10:
            return f"{y}-{m:02d}-{d:02d} {rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}"[:length]
        return f"{y}-{m:02d}-{d:02d}"

    def word(self, index=0, hint=""):
        return self._rng(index, "word:" + hint).choice(WORDS)

    def value(self, length=8, index=0, hint=""):
        rng = self._rng(index, "value:" + hint)
        hint_l = hint.lower()
        if "mail" in hint_l:
            return self.email()
        if any(k in hint_l for k in ("pass", "secret", "phrase", "key", "pin")):
            return f"{rng.choice(WORDS)}-{rng.choice(WORDS)}-{rng.randint(10, 99)}"
        if any(k in hint_l for k in ("user", "login", "name", "operator", "account", "owner", "author", "id")):
            return self.username()
        if any(k in hint_l for k in ("host", "server", "node")):
            return f"{rng.choice(WORDS)}-{rng.randint(1, 24):02d}.{self.domain}"
        if any(k in hint_l for k in ("version", "build", "release")):
            return f"{rng.randint(1, 9)}.{rng.randint(0, 20)}.{rng.randint(0, 40)}"
        length = max(3, min(int(length) or 8, 40))
        if length <= 6:
            return rng.choice(WORDS)[:length]
        return (rng.choice(WORDS) + "-" + rng.choice(WORDS) + "-" + str(rng.randint(10, 99)))[:length]

    def sentence(self, length=60, index=0):
        rng = self._rng(index, "sentence")
        out = rng.choice(PHRASES)
        while len(out) < length - 20:
            out += " " + rng.choice(PHRASES)
        return out

    def paragraph(self, length=400, index=0):
        rng = self._rng(index, "paragraph")
        out = []
        while sum(len(s) + 1 for s in out) < length:
            out.append(rng.choice(PHRASES))
        return " ".join(out)[:max(length, 20)]

    def fill(self, index, slot, params=None, escape=True):
        """Text for one skeleton slot (HTML-escaped unless escape=False)."""
        kind = slot.get("slot", "value")
        length = slot.get("len", 0)
        hint = slot.get("hint", "")
        if kind == "echo":
            text = (params or {}).get(hint, "")
            if not text:
                text = self.value(length, index, hint)
        elif kind == "token":
            text = self.token(length, index, hint)
        elif kind == "number":
            text = self.number(length, index, hint)
        elif kind == "email":
            text = self.email()
        elif kind == "ipv4":
            text = self.ipv4(index)
        elif kind == "date":
            text = self.date(length, index)
        elif kind == "version":
            rng = self._rng(index, "version")
            text = ".".join(str(rng.randint(0, 9 if i else 7)) for i in range(3 if length >= 5 else 2))
        elif kind == "word":
            text = self.word(index, hint)
        elif kind == "sentence":
            text = self.sentence(length, index)
        elif kind == "paragraph":
            text = self.paragraph(length, index)
        else:
            text = self.value(length, index, hint)
        return html.escape(text, quote=True) if escape else text
