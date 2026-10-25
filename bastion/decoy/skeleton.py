"""Turn a real response body into a privacy-safe *skeleton*: the markup kept verbatim, data-like
text and attribute values replaced by typed slots. The skeleton is what the shape model stores and
what the decoy renders (`render`) with fake data. See docs/DECOY.md §1.

A skeleton is a list of parts: `str` (literal) or `{"slot": kind, "len": n, "hint": str}`.
"""
import json
import re

from bastion.privacy import form_view, sensitive

TAG_RE = re.compile(
    r"<!--.*?-->|<!\[CDATA\[.*?\]\]>|<(script|style)\b[^>]*>.*?</\1\s*>|<[^>]+>", re.S | re.I)
TAG_NAME_RE = re.compile(r"<\s*(/?)([a-zA-Z][\w:-]*)")
ATTR_RE = re.compile(r"""([a-zA-Z_:][\w:.-]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'=<>`]+))""")

# Keep text in these: it is the site's chrome, the thing that makes pages look like one app.
CHROME_TAGS = {"title", "h1", "h2", "h3", "h4", "h5", "h6", "a", "button", "label", "th", "nav",
               "option", "legend", "summary", "dt", "footer", "header", "caption", "small"}
VALUE_TAGS = {"td", "pre", "code", "strong", "em", "b", "i", "span", "li", "dd", "var", "kbd",
              "samp", "output", "time", "mark"}
VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
             "source", "track", "wbr"}

EMAIL_RE = re.compile(r"^[\w.+-]+@[\w-]+\.[\w.-]+$")
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
HEX_RE = re.compile(r"^[A-Fa-f0-9]{16,}$")
NUMBER_RE = re.compile(r"^[+-]?[\d][\d,._]*$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?Z?$")
IDENT_RE = re.compile(r"^[\w.@-]{4,64}$")

# Secrets that may sit inside otherwise-kept text (scripts, attributes, prose).
# (regex, group whose span is the secret)
SECRET_RES = [
    (re.compile(r"\b[A-Fa-f0-9]{32,}\b"), 0),
    (re.compile(r"\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b"), 0),
    (re.compile(r"(?i)\bBearer\s+[\w.-]{8,}"), 0),
    (re.compile(r"(?i)\b(AKIA|ASIA)[A-Z0-9]{16}\b"), 0),
    (re.compile(r"(?i)\b(sk|pk|rk)_(live|test)_[\w]{8,}\b"), 0),
    (re.compile(r"""(?i)\b([\w-]*(key|token|secret|password|passwd|session|sig|signature|csrf|nonce)[\w-]*)\s*([:=])\s*(["']?)([^\s"'&;<>]{4,})"""), 5),
]
URL_SECRET_RE = re.compile(r"""(?i)([?&;]([\w-]*(key|token|secret|password|session|sig|signature|csrf|nonce)[\w-]*)=)([^&\s"'<>#]+)""")

# Data-like fragments inside otherwise-kept prose ("opened 2024-01-02 for bob@example.com").
DATA_RES = [
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "email"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "ipv4"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?Z?)?\b"), "date"),
    (re.compile(r"\b[A-Fa-f0-9]{16,}\b"), "token"),
    (re.compile(r"\bv?\d+\.\d+(?:\.\d+)+\b"), "version"),
    (re.compile(r"\b\d{4,}\b"), "number"),
]
VERSION_RE = re.compile(r"^v?\d+\.\d+(?:\.\d+)+$")

MAX_SLOTS = 400


def _slot(kind, length=0, hint=""):
    part = {"slot": kind, "len": int(length)}
    if hint:
        part["hint"] = hint[:40]
    return part


def mask_secrets(text):
    """Replace secret-looking substrings with `[token]` markers; returns parts."""
    parts = []
    pos = 0
    spans = []
    for rx, group in SECRET_RES:
        for m in rx.finditer(text):
            spans.append((m.start(group), m.end(group)))
    for m in URL_SECRET_RE.finditer(text):
        spans.append((m.start(4), m.end(4)))
    return _cut(text, [(s, e, "token") for s, e in spans])


def mask_data(text):
    """mask_secrets + emails/IPs/dates/long numbers/hex ids inside prose."""
    spans = []
    for rx, group in SECRET_RES:
        spans += [(m.start(group), m.end(group), "token") for m in rx.finditer(text)]
    spans += [(m.start(4), m.end(4), "token") for m in URL_SECRET_RE.finditer(text)]
    for rx, kind in DATA_RES:
        spans += [(m.start(), m.end(), kind) for m in rx.finditer(text)]
    return _cut(text, spans)


def _cut(text, spans):
    parts = []
    pos = 0
    for start, end, kind in sorted(spans, key=lambda s: (s[0], -s[1])):  # longest span wins
        if start < pos:
            continue
        parts.append(text[pos:start])
        parts.append(_slot(kind, end - start))
        pos = end
    parts.append(text[pos:])
    return [p for p in parts if p != ""]


def classify_text(text):
    """Kind of a data-like text, or None if it is safe chrome to keep."""
    t = text.strip()
    if not t:
        return None
    if EMAIL_RE.match(t):
        return "email"
    if IPV4_RE.match(t):
        return "ipv4"
    if HEX_RE.match(t):
        return "token"
    if DATE_RE.match(t):
        return "date"
    if VERSION_RE.match(t):
        return "version"
    if NUMBER_RE.match(t) and any(c.isdigit() for c in t):
        return "number"
    return None


def _looks_like_value(t):
    if any(c.isdigit() for c in t):
        return True
    if IDENT_RE.match(t) and (("." in t) or ("@" in t) or ("-" in t) or ("_" in t)):
        return True
    return False


def _text_parts(text, stack, param_values):
    """Decide what to do with one text node given the enclosing tag stack."""
    t = text.strip()
    if not t:
        return [text]
    lead = text[:len(text) - len(text.lstrip())]
    trail = text[len(text.rstrip()):]
    for name, value in param_values:
        if len(value) >= 3 and value in t:
            before, after = t.split(value, 1)
            return [lead + before, _slot("echo", len(value), name), after + trail]
    kind = classify_text(t)
    tag = stack[-1] if stack else ""
    if kind and not (tag in CHROME_TAGS and kind == "number" and len(t) <= 4):
        return [lead, _slot(kind, len(t)), trail]
    if tag in CHROME_TAGS:
        if len(t) <= 80:
            return [lead] + mask_data(t) + [trail]
        return [lead, _slot("sentence", len(t)), trail]
    if tag in VALUE_TAGS and _looks_like_value(t):
        if " " in t:  # "Build 4.2.1", "Ticket 88213": keep the words, slot the data
            return [lead] + mask_data(t) + [trail]
        return [lead, _slot("value", len(t)), trail]
    if len(t) > 400:
        return [lead, _slot("paragraph", len(t)), trail]
    if " " not in t and _looks_like_value(t):
        return [lead, _slot("value", len(t)), trail]
    return [lead] + mask_data(t) + [trail]


def _tag_parts(tag):
    """Hidden-input values, csrf metas and URL tokens inside a start tag become slots."""
    m = TAG_NAME_RE.match(tag)
    if not m or m.group(1):
        return [tag]
    name = m.group(2).lower()
    attrs = {k.lower(): (v3 if v3 is not None else v4 if v4 is not None else v5)
             for k, _, v3, v4, v5 in ATTR_RE.findall(tag)}
    parts = []
    pos = 0
    for am in ATTR_RE.finditer(tag):
        key = am.group(1).lower()
        value = am.group(3) if am.group(3) is not None else am.group(4) if am.group(4) is not None else am.group(5)
        if value is None or value == "":
            continue
        vstart = am.start(3) if am.group(3) is not None else am.start(4) if am.group(4) is not None else am.start(5)
        vend = vstart + len(value)
        replacement = None
        if name == "input" and key == "value":
            itype = attrs.get("type", "text").lower()
            iname = attrs.get("name", "")
            if itype == "hidden":
                if sensitive(iname) or len(value) >= 16 or HEX_RE.match(value) or "sig" in iname.lower() or "csrf" in iname.lower():
                    replacement = _slot("token", len(value), iname)
                elif not value.isdigit() and value.lower() not in {"1", "0", "true", "false", "on", "yes", "no"}:
                    replacement = _slot("value", len(value), iname)
            elif itype not in {"submit", "button", "checkbox", "radio", "reset"}:
                replacement = _slot("value", len(value), iname)
        elif name == "meta" and key == "content" and any(
                k in attrs.get("name", "").lower() for k in ("csrf", "token", "nonce")):
            replacement = _slot("token", len(value), attrs.get("name", ""))
        elif key in {"href", "src", "action", "data-url", "formaction"}:
            if URL_SECRET_RE.search(value):
                sub = []
                vpos = 0
                for um in URL_SECRET_RE.finditer(value):
                    sub.append(value[vpos:um.start(4)])
                    sub.append(_slot("token", um.end(4) - um.start(4), um.group(2)))
                    vpos = um.end(4)
                sub.append(value[vpos:])
                parts.append(tag[pos:vstart])
                parts.extend(p for p in sub if p != "")
                pos = vend
                continue
        elif key in {"value", "content", "data-value", "data-id", "data-token"} and (sensitive(key) or classify_text(value) in {"token", "email"}):
            replacement = _slot(classify_text(value) or "token", len(value), key)
        if replacement is not None:
            parts.append(tag[pos:vstart])
            parts.append(replacement)
            pos = vend
    parts.append(tag[pos:])
    return [p for p in parts if p != ""]


def skeletonize_html(body, param_values=()):
    """Skeleton parts for an HTML body (≤ caller's bound). `param_values` are redacted request
    (name, value) pairs; text equal to a value becomes an `echo` slot (server-side reflection)."""
    parts = []
    stack = []
    pos = 0
    slots = 0
    for m in TAG_RE.finditer(body):
        if m.start() > pos:
            parts.extend(_text_parts(body[pos:m.start()], stack, param_values))
        tag = m.group(0)
        low = tag[:8].lower()
        if low.startswith("<!--") or low.startswith("<![cdata"):
            parts.append(tag)
        elif m.group(1):  # whole script/style block
            parts.extend(mask_secrets(tag))
        else:
            nm = TAG_NAME_RE.match(tag)
            if nm:
                name = nm.group(2).lower()
                if nm.group(1):
                    while stack and stack[-1] != name:
                        stack.pop()
                    if stack:
                        stack.pop()
                else:
                    if name not in VOID_TAGS and not tag.endswith("/>"):
                        stack.append(name)
            parts.extend(_tag_parts(tag))
        pos = m.end()
        slots = sum(1 for p in parts if isinstance(p, dict))
        if slots > MAX_SLOTS:
            break
    if pos < len(body) and slots <= MAX_SLOTS:
        parts.extend(_text_parts(body[pos:], stack, param_values))
    merged = []
    for p in parts:
        if isinstance(p, str) and merged and isinstance(merged[-1], str):
            merged[-1] += p
        elif p != "":
            merged.append(p)
    for i, p in enumerate(merged):  # label unlabelled slots with the words just before them
        if isinstance(p, dict) and not p.get("hint") and i and isinstance(merged[i - 1], str):
            label = re.sub(r"<[^>]+>", " ", merged[i - 1][-160:])
            label = re.sub(r"\s+", " ", label).strip(" :-–—|").strip()
            if label:
                p["hint"] = label[-32:].lower()
    return merged, list(stack)


def skeletonize_json(body):
    """(schema, example) with string values replaced by their kind, sensitive keys redacted."""
    try:
        data = json.loads(body)
    except ValueError:
        return None

    def walk(value, key=""):
        if isinstance(value, dict):
            schema, example = {}, {}
            for k, v in list(value.items())[:64]:
                if sensitive(k):
                    schema[str(k)] = {"type": "string", "kind": "token"}
                    example[str(k)] = _slot("token", 32, str(k))
                else:
                    schema[str(k)], example[str(k)] = walk(v, str(k))
            return {"type": "object", "properties": schema}, example
        if isinstance(value, list):
            if not value:
                return {"type": "array"}, []
            s, e = walk(value[0], key)
            return {"type": "array", "items": s}, [e] + [walk(v, key)[1] for v in value[1:4]]
        if isinstance(value, bool):
            return {"type": "boolean"}, value
        if isinstance(value, (int, float)):
            return {"type": "number"}, _slot("number", len(str(value)), key)
        if value is None:
            return {"type": "null"}, None
        text = str(value)
        kind = classify_text(text) or ("sentence" if " " in text else "value")
        if len(text) > 160:
            kind = "paragraph"
        return {"type": "string", "kind": kind}, _slot(kind, len(text), key)

    return walk(data)


def tag_sequence(parts):
    """Structural signature: tag names + class attrs in order (used to merge samples and to score)."""
    seq = []
    text = "".join(p if isinstance(p, str) else " " for p in parts)
    for m in TAG_RE.finditer(text):
        tag = m.group(0)
        nm = TAG_NAME_RE.match(tag)
        if not nm:
            continue
        name = nm.group(2).lower()
        if nm.group(1):
            seq.append("/" + name)
            continue
        cls = re.search(r"""class\s*=\s*["']([^"']*)["']""", tag)
        seq.append(name + ("." + cls.group(1).strip().replace(" ", ".") if cls else ""))
    return seq


def merge_parts(existing, new):
    """Promote text that differs between two samples of the same structure to slots.
    Returns the merged parts, or None if the structures do not line up."""
    if len(existing) != len(new):
        return None
    merged = []
    for a, b in zip(existing, new):
        if isinstance(a, dict) or isinstance(b, dict):
            merged.append(a if isinstance(a, dict) else b)
        elif a == b:
            merged.append(a)
        else:
            diff = _diff_slot(a, b)
            if diff is None:
                return None
            merged.extend(diff)
    return merged


def _diff_slot(a, b):
    """Common prefix/suffix kept, the differing middle becomes a slot (only for text runs that
    carry the same tags, otherwise the structures differ)."""
    if tag_sequence([a]) != tag_sequence([b]):
        return None
    i = 0
    while i < min(len(a), len(b)) and a[i] == b[i]:
        i += 1
    j = 0
    while j < min(len(a), len(b)) - i and a[-1 - j] == b[-1 - j]:
        j += 1
    mid_a = a[i:len(a) - j]
    mid_b = b[i:len(b) - j]
    if "<" in mid_a or "<" in mid_b:
        return None
    kind = classify_text(mid_a) or classify_text(mid_b) or ("sentence" if " " in mid_a + mid_b else "value")
    return [a[:i], _slot(kind, max(len(mid_a), len(mid_b))), a[len(a) - j:]]


def render(parts, fill):
    """Render parts; `fill(index, slot) -> str` supplies each slot's text (already escaped)."""
    out = []
    index = 0
    for p in parts:
        if isinstance(p, dict):
            out.append(fill(index, p))
            index += 1
        else:
            out.append(p)
    return "".join(out)


def render_json(example, fill, compact=False):
    """Render a JSON example; `fill` must return raw (unescaped) text."""
    counter = [0]

    def walk(value):
        if isinstance(value, dict):
            if "slot" in value and "len" in value and len(value) <= 3:
                text = fill(counter[0], value)
                counter[0] += 1
                if value["slot"] == "number":
                    try:
                        return int(text)
                    except ValueError:
                        return 0
                return text
            return {k: walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v) for v in value]
        return value

    return json.dumps(walk(example), separators=(",", ":") if compact else (", ", ": "))


def close_open_tags(stack):
    return "".join(f"</{name}>" for name in reversed(stack))


def redacted_pairs(query, body="", content_type=""):
    """(name, value) pairs from already-redacted query/body strings, used for echo detection."""
    pairs = [(k, v) for k, v in form_view(query or "") if v and v != "[REDACTED]"]
    if body and "application/x-www-form-urlencoded" in (content_type or ""):
        pairs += [(k, v) for k, v in form_view(body) if v and v != "[REDACTED]"]
    return pairs
