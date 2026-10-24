"""Bounded, structured redaction at every persistence/model boundary.

Unknown free-text secrets cannot be identified reliably; do not submit sensitive
production payloads without a deployment-specific data-handling policy.
"""
from urllib.parse import parse_qsl, urlencode

SENSITIVE = {"password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
             "authorization", "cookie", "set-cookie", "user_token", "access_token",
             "refresh_token", "session", "session_id", "phpsessid"}


def sensitive(key):
    key = str(key).lower().replace("-", "_")
    return key in SENSITIVE or key.endswith(("_password", "_secret", "_token", "_key"))


def redact(value):
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if sensitive(k) else redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return value[:8192]
    return value


def form_view(text):
    return [(k, "[REDACTED]" if sensitive(k) else v) for k, v in parse_qsl(text, keep_blank_values=True)]


def request_view(method, path, query, body, content_type=""):
    """Keep duplicate params and decode exactly once; never persist headers/cookies."""
    import json
    query_pairs = form_view(query)
    if "application/x-www-form-urlencoded" in content_type:
        body_view = form_view(body)
        body_text = urlencode(body_view)
    elif "application/json" in content_type:
        try:
            body_view = redact(json.loads(body))
            body_text = json.dumps(body_view)
        except ValueError:
            body_view, body_text = None, "[unparseable JSON omitted]"
    elif not body:
        body_view, body_text = None, ""
    elif any(b > 127 for b in (body.encode("latin1") if isinstance(body, str) else body)):
        body_view, body_text = None, "[binary body omitted]"
    else:
        # Unstructured text or multipart bodies are not sent to external providers by default.
        body_view, body_text = None, "[unstructured body omitted]"
    return {"method": method, "path": path, "query": urlencode(query_pairs),
            "query_params": query_pairs, "body": body_text, "body_view": body_view,
            "content_type": content_type, "redacted": True}
