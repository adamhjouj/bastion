"""Authentication, source attribution and policy boundaries; not attack detection."""
import base64
import ipaddress
import re
import secrets

from fastapi import HTTPException


def authorize(request, token):
    header = request.headers.get("authorization", "")
    supplied = ""
    if header.startswith("Bearer "):
        supplied = header[7:]
    elif header.startswith("Basic "):
        try:
            username, supplied = base64.b64decode(header[6:], validate=True).decode().split(":", 1)
            if username != "admin":
                supplied = ""
        except (ValueError, UnicodeError):
            pass
    if len(token) < 32 or not secrets.compare_digest(supplied.encode(), token.encode()):
        raise HTTPException(401, "management authentication required", headers={"WWW-Authenticate": 'Basic realm="Bastion"'})


def source_ip(request, settings):
    peer = request.client.host if request.client else "unknown"
    xff = request.headers.get("x-forwarded-for", "")
    if settings.demo_identity and xff:
        try:
            return str(ipaddress.ip_address(xff.split(",")[0].strip()))
        except ValueError:
            raise HTTPException(400, "invalid demo identity")
    networks = [ipaddress.ip_network(c.strip()) for c in settings.trusted_proxies.split(",") if c.strip()]
    try:
        current = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if not xff or not any(current in n for n in networks):
        return str(current)
    try:
        chain = [ipaddress.ip_address(p.strip()) for p in xff.split(",")]
    except ValueError:
        raise HTTPException(400, "invalid forwarded chain")
    for address in reversed(chain):
        if not any(current in n for n in networks):
            break
        current = address
    return str(current)


DESTRUCTIVE = {"kill_process", "kill_session", "rotate_secret", "quarantine_container",
               "release_container", "isolate_egress", "reconnect_egress", "patch_vuln"}


# Vetted virtual-patch regexes, one per attack class (keyed by Jev's attack_type). Each is
# tested (test_security.py) to block that class's exploit payloads while passing realistic
# legitimate input for the route it protects — so an agent-installed patch never breaks the
# app. Applied case-insensitively (match_vpatch), route-scoped by the rule.
VPATCH_PATTERNS = {
    # reflected/stored XSS: script tags, inline event handlers, javascript: URIs
    "xss": r"(?:<\s*/?\s*script\b|<[^>]*\bon[a-z]+\s*=|javascript\s*:|<\s*svg\b[^>]*\bon[a-z]+)",
    # SQL injection: UNION/boolean/stacked/time-based/comment vectors
    "sql_injection": r"(?:\bunion\b[\s/*]+\bselect\b|\bselect\b.+\bfrom\b|\b(?:or|and)\b\s+['\"\d][^=]*=|'\s*(?:or|and)\b|--|;\s*(?:drop|delete|update|insert)\b|\b(?:sleep|benchmark|pg_sleep)\s*\()",
    # command injection: shell metacharacters / command substitution / common exfil commands
    "command_injection": r"(?:[;|`]|\|\||&&|\$\(|\$\{|\bcat\s+/|\bnc\s|\bcurl\s|\bwget\s|\bwhoami\b|/etc/passwd|>\s*/)",
    # path traversal / LFI: dot-dot sequences (incl. '....//' and encoded), absolute paths, null byte
    "path_traversal": r"(?:\.\.[\\/]|\.\.%2[fF]|%2[eE]%2[eE]|\.\.\.\.[\\/]|^/\w|[?&=]/(?:etc|proc|var|root)\b|%00|\x00)",
}

# Operator-facing aliases the agent might pass -> canonical Jev attack_type keys.
_VPATCH_ALIAS = {"sqli": "sql_injection", "sql": "sql_injection", "cmdi": "command_injection",
                 "command-injection": "command_injection", "rce": "command_injection",
                 "lfi": "path_traversal", "traversal": "path_traversal", "fi": "path_traversal",
                 "cross-site-scripting": "xss", "xss_r": "xss", "xss_s": "xss"}


def canonical_vpatch(attack_type):
    """Resolve an attack-class label to its vetted regex, or None if unknown.
    Tolerant of aliases/case so the agent can pass 'sqli', 'XSS', 'command-injection', etc."""
    if not attack_type:
        return None
    key = str(attack_type).strip().lower()
    key = _VPATCH_ALIAS.get(key, key)
    return VPATCH_PATTERNS.get(key)


def match_vpatch(rules, path, text):
    """Return the first virtual-patch rule that blocks this request, or None.

    A rule = {"path", "pattern", ...}. It applies when its path matches the request path
    (exact, trailing-slash-insensitive; "*" = any route) and its regex is found in `text`
    (the request's decoded query + body). Case-insensitive so case-variation payloads
    (e.g. <IMG onerror>) can't dodge a rule written against <img onerror>. A rule whose
    regex no longer compiles is skipped, never fatal to request handling."""
    norm = "/" + (path or "").strip("/")
    for rule in rules or []:
        rp = rule.get("path") or "*"
        if rp != "*" and "/" + rp.strip("/") != norm:
            continue
        pattern = rule.get("pattern")
        if not pattern:
            continue
        try:
            if re.search(pattern, text, re.IGNORECASE):
                return rule
        except re.error:
            continue
    return None
