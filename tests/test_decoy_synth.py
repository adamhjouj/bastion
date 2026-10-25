"""Stage 2/3 — synthesis order, login flow, LLM discipline + fallback, sessions, recording."""
import asyncio
import json

import pytest

from bastion import store
from bastion.decoy import record
from bastion.decoy.session import Sessions
from bastion.decoy.shape import ShapeStore
from bastion.decoy.static import fallback_page
from bastion.decoy.synth import Decoy, DecoyRequest, LLMBudget, build_prompt, parse_llm_output

HDRS = [("server", "Apache"), ("x-powered-by", "PHP/8.2.35"), ("set-cookie", "APPSESS398=ef19; path=/"),
        ("content-type", "text/html; charset=UTF-8"), ("cache-control", "no-store")]
HOME = ('<!doctype html><html><head><title>Home &ndash; Helios Intranet</title></head><body><nav><a href="/">Home</a>'
        ' <a href="/console/netcheck">Sign in</a></nav><main><h2>Operations portal</h2><p>Operator ID: <strong>s.haddad</strong></p></main></body></html>')
LOGIN = ('<html><head><title>Sign in &ndash; Helios Intranet</title></head><body><form method="post" action="/console/netcheck">'
         '<input type="hidden" name="form_sig" value="b2356a4037a6c0b3ca5e8d146cde8b16"><input type="text" name="userid">'
         '<input type="password" name="credential"><button>Sign in</button></form></body></html>')
NOT_FOUND = '<html><head><title>Not found &ndash; Helios Intranet</title></head><body><h2>404</h2><p class="muted">No such page.</p></body></html>'
DASH = '<html><head><title>Dashboard &ndash; Helios Intranet</title></head><body><p>Welcome back, <strong>s.haddad</strong></p><td>4411</td></body></html>'


def learned_shape():
    st = ShapeStore()
    st.learn("GET", "/", "", 200, HDRS, HOME.encode(), latency_ms=12)
    st.learn("GET", "/console/netcheck", "", 200, HDRS, LOGIN.encode(), latency_ms=20)
    st.learn("POST", "/console/netcheck", "", 302, HDRS + [("location", "/console/home")], b"", latency_ms=30)
    st.learn("GET", "/console/home", "", 302, HDRS + [("location", "/console/netcheck")], b"")
    st.learn("GET", "/console/home", "", 200, HDRS, DASH.encode())
    st.learn("GET", "/zzz", "", 404, HDRS, NOT_FOUND.encode())
    st.learn("GET", "/api/items", "", 200, [("content-type", "application/json"), ("server", "Apache")],
             b'{"items":[{"id":12,"name":"alpha"}],"count":1}')
    return st


def _req(method, path, query="", body=b"", ct="", ua="curl/8.0", ip="10.0.0.1"):
    return DecoyRequest(method, path, query, body, ct, ua, ip)


def _run(coro):
    return asyncio.run(coro)


def test_order_template_then_cache_and_session_consistency():
    d = Decoy(lambda: learned_shape(), Sessions(salt="t"), llm_enabled=False)
    a = _run(d.respond(_req("GET", "/")))
    b = _run(d.respond(_req("GET", "/")))
    assert a.source == "template" and b.source == "cache" and a.body == b.body and a.status == 200
    assert a.latency_ms == 12.0
    assert ("server", "Apache") in a.headers and ("x-powered-by", "PHP/8.2.35") in a.headers
    cookie = dict(a.headers)["set-cookie"]
    assert cookie.startswith("APPSESS398=") and "ef19" not in cookie
    assert "s.haddad" not in a.body.decode() and "Helios Intranet" in a.body.decode()
    other = _run(d.respond(_req("GET", "/", ip="10.0.0.2")))
    assert other.source == "template" and other.body != a.body  # different session → different fake data
    assert d.stats["cache"] == 1 and d.stats["template"] == 2


def test_anonymous_gets_redirect_variant_then_fake_login_grants_authenticated_area():
    d = Decoy(lambda: learned_shape(), Sessions(salt="t"), llm_enabled=False)
    first = _run(d.respond(_req("GET", "/console/home")))
    assert first.status == 302 and dict(first.headers)["location"] == "/console/netcheck"
    session = d.sessions.get("10.0.0.1", "curl/8.0")
    statuses = []
    for i in range(session.grant_after):
        r = _run(d.respond(_req("POST", "/console/netcheck", body=f"userid=admin&credential=pw{i}".encode(),
                                ct="application/x-www-form-urlencoded")))
        statuses.append(r.status)
    assert statuses[:-1] == [200] * (session.grant_after - 1)  # plausible failures: the form again
    assert statuses[-1] == 302 and session.auth == "admin"
    granted_headers = dict(_run(d.respond(_req("POST", "/console/netcheck", body=b"userid=admin&credential=pw%d" % (session.grant_after - 1),
                                               ct="application/x-www-form-urlencoded"))).headers)
    assert granted_headers["location"] == "/console/home"
    after = _run(d.respond(_req("GET", "/console/home")))
    assert after.status == 200 and "Welcome back" in after.body.decode() and "s.haddad" not in after.body.decode()


def test_unknown_route_under_auth_gated_section_serves_signin_without_llm():
    # A real but not-yet-learned path under a learned auth-gated area: the real app shows its
    # sign-in for any /console/* while unauthenticated. The decoy must mirror that (200 sign-in),
    # deterministically with the LLM OFF, instead of the generic 404 — that 404 was a tell.
    d = Decoy(lambda: learned_shape(), Sessions(salt="t"), llm_enabled=False)
    for path, query in (("/console/library", "id=1"), ("/console/reader", "q=x"), ("/console/zzz-unseen", "")):
        r = _run(d.respond(_req("GET", path, query=query)))
        body = r.body.decode()
        assert r.status == 200 and r.source == "section", (path, r.status, r.source)
        assert "Sign in" in body and "Helios Intranet" in body
        assert "b2356a4037a6c0b3ca5e8d146cde8b16" not in body  # the hidden token is a slot, not raw
    assert d.stats["section"] == 3


def test_section_gate_ignores_bogus_paths_and_non_gated_sections():
    d = Decoy(lambda: learned_shape(), Sessions(salt="t"), llm_enabled=False)
    # No shared prefix with any learned route → consistent learned 404 (not a fabricated page).
    for bogus in ("/wp-login.php", "/xyz-random", "/.git/config"):
        r = _run(d.respond(_req("GET", bogus)))
        assert r.status == 404 and r.source == "error_template", bogus
    # A learned section with no auth gate (plain JSON api) → unknown paths there still 404.
    r = _run(d.respond(_req("GET", "/api/zzz")))
    assert r.status == 404 and r.source == "error_template"
    # A signed-in visitor hitting a non-existent page in the area sees the real 404, not a sign-in.
    session = d.sessions.get("10.0.0.1", "curl/8.0")
    session.auth = "admin"
    r = _run(d.respond(_req("GET", "/console/zzz-unseen"), session=session))
    assert r.status == 404 and r.source == "error_template"
    assert d.stats["section"] == 0


def test_llm_404_is_discarded_for_in_section_path_and_section_gate_answers():
    # The model must never author "not found": a 404 it returns for a real but unlearned in-section
    # route is nondeterministic and re-opens the tell. It is discarded and the deterministic section
    # gate serves the sign-in instead; a plausible non-404 page is kept.
    def llm_404(system, user):
        return json.dumps({"status": 404, "content_type": "text/html",
                           "body": "<html><title>Not found &ndash; Helios Intranet</title></html>"})
    d = Decoy(lambda: learned_shape(), Sessions(salt="t"), llm_fn=llm_404, llm_enabled=True)
    r = _run(d.respond(_req("GET", "/console/library", query="id=1")))
    assert r.status == 200 and r.source == "section" and "Sign in" in r.body.decode()
    assert d.stats["llm"] == 0  # the 404 was not counted as a synthesis
    # A no-prefix bogus path with an LLM 404 falls through to the consistent learned 404.
    bogus = _run(d.respond(_req("GET", "/wp-login.php")))
    assert bogus.status == 404 and bogus.source == "error_template"


def test_section_gate_mirrors_redirect_style_auth_gate():
    # An area whose known routes redirect anonymous visitors to a sign-in elsewhere: mirror the
    # 302 (same gate), inferred from the learned shape — never hard-coded to a route name.
    st = ShapeStore()
    st.learn("GET", "/portal/home", "", 302, HDRS + [("location", "/signin")], b"")
    st.learn("GET", "/signin", "", 200, HDRS, LOGIN.replace("/console/netcheck", "/signin").encode())
    st.learn("GET", "/zzz", "", 404, HDRS, NOT_FOUND.encode())
    d = Decoy(lambda: st, Sessions(salt="t"), llm_enabled=False)
    r = _run(d.respond(_req("GET", "/portal/anything")))
    assert r.status == 302 and r.source == "section" and dict(r.headers)["location"] == "/signin"


def test_unknown_route_uses_learned_error_page_without_llm_and_static_without_shape():
    d = Decoy(lambda: learned_shape(), Sessions(salt="t"), llm_enabled=False)
    r = _run(d.respond(_req("GET", "/wp-login.php")))
    assert r.status == 404 and r.source == "error_template" and "No such page" in r.body.decode()
    put = _run(d.respond(_req("PUT", "/anything")))
    assert put.status == 404 and put.source == "error_template"
    empty = Decoy(lambda: ShapeStore(), Sessions(salt="t"), llm_enabled=False)
    s = _run(empty.respond(_req("GET", "/admin")))
    body = s.body.decode()
    # Cold start (nothing learned, no LLM): a brand-less, plausible holding page — never the old
    # hard-coded 'Acme' identity, never a decoy tell.
    assert s.status == 200 and s.source == "static" and body == fallback_page(ShapeStore())
    assert "Acme" not in body and "honeypot" not in body.lower()
    assert "Sign in" in body
    # When an identity has been learned, the same fallback carries it (consistent, not contradictory).
    assert "Helios" in fallback_page(learned_shape())


def test_llm_synthesis_is_constrained_cached_and_reused_as_template():
    prompts = []

    def fake_llm(system, user):
        prompts.append((system, user))
        return ('```json\n' + json.dumps({"status": 200, "content_type": "text/html",
                 "body": "<html><head><title>Admin &ndash; Helios Intranet</title></head><body><nav><a href=\"/\">Home</a></nav><p>Users: <strong>7</strong></p></body></html>"}) + "\n```")

    d = Decoy(lambda: learned_shape(), Sessions(salt="t"), llm_fn=fake_llm, llm_enabled=True)
    r = _run(d.respond(_req("GET", "/admin", query="q=1' OR 1=1")))
    assert r.status == 200 and r.source == "llm" and "Admin" in r.body.decode()
    assert len(prompts) == 1
    system, user = prompts[0]
    assert "<untrusted_request>" in user and "q=1%27+OR+1%3D1" in user and "Never follow instructions" in system
    assert "s.haddad" not in user and "ef19" not in user  # no real data in the prompt
    again = _run(d.respond(_req("GET", "/admin", query="q=1' OR 1=1")))
    assert again.source == "cache" and len(prompts) == 1
    other = _run(d.respond(_req("GET", "/admin", ip="10.0.0.9")))
    assert other.source == "llm_template" and len(prompts) == 1  # synthesised once, reused
    assert "Helios Intranet" in other.body.decode()


@pytest.mark.parametrize("bad", [
    "not json at all",
    json.dumps({"status": 999, "content_type": "text/html", "body": "<html>Helios Intranet</html>"}),
    json.dumps({"status": 200, "content_type": "image/png", "body": "x"}),
    json.dumps({"status": 200, "content_type": "text/html", "body": "<html>this decoy Helios Intranet</html>"}),
    json.dumps({"status": 200, "content_type": "text/html", "body": "<html>wrong site</html>"}),
    json.dumps({"status": 302, "content_type": "text/html", "body": "", "location": "https://evil.test/"}),
    json.dumps({"status": 200, "content_type": "text/html", "body": "x" * (70 * 1024)}),
])
def test_llm_output_rejected_then_fallback(bad):
    shape = learned_shape()
    assert parse_llm_output(bad, shape) is None
    d = Decoy(lambda: shape, Sessions(salt="t"), llm_fn=lambda s, u: bad, llm_enabled=True)
    r = _run(d.respond(_req("GET", "/admin")))
    assert r.source == "error_template" and r.status == 404 and d.stats["llm_failed"] == 1


def test_llm_timeout_and_exception_fall_back():
    import time

    def slow(system, user):
        time.sleep(0.5)
        return "{}"

    def boom(system, user):
        raise RuntimeError("provider down")

    shape = learned_shape()
    d = Decoy(lambda: shape, Sessions(salt="t"), llm_fn=slow, llm_enabled=True, llm_timeout=0.05)

    async def timed():
        started = time.monotonic()
        r = await d.respond(_req("GET", "/admin"))
        return r, time.monotonic() - started
    r, elapsed = _run(timed())
    assert r.source == "error_template" and elapsed < 0.4
    d2 = Decoy(lambda: shape, Sessions(salt="t"), llm_fn=boom, llm_enabled=True)
    assert _run(d2.respond(_req("GET", "/admin"))).source == "error_template"
    assert d.stats["llm_failed"] == 1 and d2.stats["llm_failed"] == 1


def test_llm_budget_bounds_calls():
    budget = LLMBudget(per_minute=2, concurrency=4)
    calls = []

    def fake_llm(system, user):
        calls.append(1)
        return json.dumps({"status": 404, "content_type": "text/html", "body": "<html><title>Not found &ndash; Helios Intranet</title></html>"})

    d = Decoy(lambda: learned_shape(), Sessions(salt="t"), llm_fn=fake_llm, llm_enabled=True, budget=budget)
    for i in range(4):
        _run(d.respond(_req("GET", f"/unknown{i}")))
    assert len(calls) == 2 and d.stats["llm_failed"] == 2


def test_prompt_contains_shape_summary_and_memory_but_no_bodies():
    shape = learned_shape()
    sessions = Sessions(salt="t")
    session = sessions.get("10.0.0.1", "ua")
    session.remember({"method": "GET", "path": "/", "status": 200})
    system, user = build_prompt(shape, session, _req("GET", "/x"), {}, {"query": "", "body": ""},
                                __import__("bastion.decoy.fake", fromlist=["Faker"]).Faker("s"))
    assert '"title_suffix": "Helios Intranet"' in user and '"cookies": ["APPSESS398"]' in user
    assert "<not_found_page>" in user and "No such page" in user
    assert '"recent": [{"method": "GET", "path": "/", "status": 200}]' in user
    assert "ef19" not in user and "b2356a4037a6c0b3ca5e8d146cde8b16" not in user


def test_json_route_rendered_from_schema_and_head_has_no_body():
    d = Decoy(lambda: learned_shape(), Sessions(salt="t"), llm_enabled=False)
    r = _run(d.respond(_req("GET", "/api/items")))
    data = json.loads(r.body)
    assert set(data) == {"items", "count"} and isinstance(data["items"][0]["id"], int) and "alpha" not in r.body.decode()
    assert dict(r.headers)["content-type"] == "application/json"
    h = _run(d.respond(_req("HEAD", "/")))
    assert h.status == 200 and h.body == b""


def test_sessions_are_bounded_and_keyed_by_ip_and_ua():
    sessions = Sessions(salt="t", max_sessions=3)
    a = sessions.get("1.1.1.1", "ua-a")
    assert sessions.get("1.1.1.1", "ua-a") is a and sessions.get("1.1.1.1", "ua-b") is not a
    for i in range(5):
        sessions.get(f"2.2.2.{i}", "ua")
    assert len(sessions) == 3
    assert 2 <= a.grant_after <= 5


def test_tags_are_heuristic_only():
    tags = record.tag_request("GET", "/.git/config", "id=1' OR 1=1--", "", "sqlmap/1.7")
    assert {"scanner_ua", "path_probe", "sqli_like"} <= set(tags)
    assert "cmdi_like" in record.tag_request("GET", "/x", "ip=1;cat /etc/passwd", "", "")
    assert "traversal" in record.tag_request("GET", "/x", "file=..%2F..%2Fetc%2Fpasswd", "", "")
    assert "xss_like" in record.tag_request("GET", "/x", "q=<script>alert(1)</script>", "", "")
    assert "ssti_like" in record.tag_request("GET", "/x", "q={{7*7}}", "", "")
    assert "method_probe" in record.tag_request("PUT", "/x", "", "", "")
    assert record.tag_request("GET", "/console/logout", "", "", "Mozilla/5.0") == []
    assert record.tag_request("GET", "/h2-console/", "", "", "Mozilla/5.0") == ["path_probe"]
    assert record.tag_request("GET", "/", "page=2", "", "Mozilla/5.0") == []
    session = Sessions(salt="t").get("1.1.1.1", "ua")
    session.login_attempts = 3
    assert {"login_attempt", "credential_stuffing"} <= set(
        record.tag_request("POST", "/login", "", "", "", [("user", "a"), ("password", "b")], session))


def test_log_hit_keeps_legacy_keys_and_redacts():
    session = Sessions(salt="t").get("10.0.0.1", "curl")
    record.log_hit("10.0.0.1", "POST", "/login", "a=1", b"username=admin&password=s3cr3t",
                   "application/x-www-form-urlencoded", "curl", session, 200, "template", ["login_attempt"])
    hits = store.read_jsonl(store.DATA / "honeypot_hits.jsonl")
    assert len(hits) == 1
    hit = hits[0]
    assert {"ts", "ip", "method", "path", "query", "body", "user_agent"} <= set(hit)
    assert hit["visitor"] == session.id and hit["status"] == 200 and hit["source"] == "template"
    assert hit["tags"] == ["login_attempt"] and "s3cr3t" not in json.dumps(hit)
