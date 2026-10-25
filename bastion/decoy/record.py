"""Technique tagging (regex heuristics, nothing executed) and the hit log, backward compatible
with the original honeypot_hits stream: {ts, ip, method, path, query, body, user_agent} + new keys."""
import re
from urllib.parse import unquote_plus

from bastion import store
from bastion.privacy import form_view, redact

SCANNER_UA_RE = re.compile(r"(?i)(sqlmap|nikto|nmap|masscan|zgrab|nuclei|wpscan|dirbuster|gobuster|"
                           r"ffuf|feroxbuster|acunetix|nessus|openvas|burp|w3af|arachni|python-requests|"
                           r"go-http-client|curl/|wget/|libwww|httpclient|scrapy|zaproxy)")
PATH_PROBE_RE = re.compile(r"(?i)(^|/)(\.git|\.env|\.svn|\.htaccess|wp-admin|wp-login|wp-content|xmlrpc\.php|"
                           r"phpmyadmin|pma|admin(istrator)?|backup|\.bak|\.old|\.sql|\.zip|\.tar|config\.php|"
                           r"web\.config|\.ds_store|actuator|h2-console|jmx-console|cgi-bin|shell|manager/html|"
                           r"\.aws|id_rsa|etc/passwd|server-status)(/|$|\.)")
TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.%2e/|%c0%ae)", re.I)
SQLI_RE = re.compile(r"(?i)('\s*(or|and)\s+[\w']+\s*=\s*[\w']+|union\s+(all\s+)?select|sleep\s*\(|benchmark\s*\(|"
                     r"information_schema|--\s*$|/\*.*\*/|'\s*;|\bor\s+1\s*=\s*1\b|load_file\s*\(|xp_cmdshell)")
CMDI_RE = re.compile(r"(?i)(;|\||&&|`|\$\()\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|ping|dir|type|echo|powershell)\b|"
                     r"\$\{IFS\}|/bin/(ba)?sh|/etc/passwd|/etc/shadow")
XSS_RE = re.compile(r"(?i)(<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img[^>]+on\w+\s*=|<\s*svg|alert\s*\(|document\.cookie)")
SSTI_RE = re.compile(r"(\{\{.*?\}\}|\$\{.*?\}|<%.*?%>|#\{.*?\})")
LOGIN_FIELD_RE = re.compile(r"(?i)^(password|passwd|pwd|pass|credential|passphrase|secret|pin)$")


def _decoded(*texts):
    out = []
    for t in texts:
        if not t:
            continue
        t = str(t)
        out.append(t)
        try:
            out.append(unquote_plus(t))
            out.append(unquote_plus(unquote_plus(t)))
        except Exception:
            pass
    return "\n".join(out)


def tag_request(method, path, query, body_text, user_agent, form_pairs=None, session=None):
    """Heuristic technique tags for one request. Inputs are untrusted strings: regex only."""
    tags = []
    if SCANNER_UA_RE.search(user_agent or ""):
        tags.append("scanner_ua")
    if PATH_PROBE_RE.search(path or ""):
        tags.append("path_probe")
    payload = _decoded(path, query, body_text)
    if TRAVERSAL_RE.search(payload):
        tags.append("traversal")
    if SQLI_RE.search(payload):
        tags.append("sqli_like")
    if CMDI_RE.search(payload):
        tags.append("cmdi_like")
    if XSS_RE.search(payload):
        tags.append("xss_like")
    if SSTI_RE.search(payload):
        tags.append("ssti_like")
    if method.upper() in {"PUT", "DELETE", "PATCH", "TRACE", "OPTIONS", "PROPFIND"}:
        tags.append("method_probe")
    if method.upper() == "POST" and any(LOGIN_FIELD_RE.match(k) for k, _ in (form_pairs or [])):
        tags.append("login_attempt")
        if session is not None and session.login_attempts >= 3:
            tags.append("credential_stuffing")
    return tags


def looks_malicious(method, path, query, body_text, user_agent=""):
    """Used by the learner side to refuse learning from attack-shaped traffic."""
    tags = tag_request(method, path, query, body_text, user_agent)
    return any(t in tags for t in ("traversal", "sqli_like", "cmdi_like", "xss_like", "ssti_like"))


def log_hit(ip, method, path, query, body_bytes, content_type, user_agent, session=None,
            status=None, source=None, tags=()):
    """Append a hit record. Keeps the original keys and value shapes; new keys are additive."""
    body_text = (body_bytes or b"").decode("utf-8", "ignore")[:2000]
    if "application/x-www-form-urlencoded" in (content_type or ""):
        body_text = str(form_view(body_text))
    record = {
        "ts": store.now(), "ip": ip, "method": method, "path": path, "query": query,
        "body": body_text, "user_agent": (user_agent or "")[:300],
    }
    if session is not None:
        record["visitor"] = session.id  # ("session" is a redacted key name in bastion.privacy)
        record["auth"] = bool(session.auth)
    if status is not None:
        record["status"] = int(status)
    if source:
        record["source"] = source
    record["tags"] = list(tags)
    return store.append_jsonl(store.DATA / "honeypot_hits.jsonl", redact(record))
