"""Authentication, source attribution and policy boundaries; not attack detection."""
import base64
import ipaddress
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
               "release_container", "isolate_egress", "patch_vuln"}
