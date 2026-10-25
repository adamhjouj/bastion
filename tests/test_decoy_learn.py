"""Stage 1 — learning the shape model: skeletons, privacy, bounds, persistence, crawler."""
import json

import httpx

from bastion.decoy import skeleton
from bastion.decoy.fake import Faker
from bastion.decoy.learn import Crawler, PassiveLearner
from bastion.decoy.shape import ShapeFiles, ShapeStore, route_key, route_pattern

HDRS = [("server", "Apache"), ("x-powered-by", "PHP/8.2.35"),
        ("set-cookie", "APPSESS398=ef1942d60f0d255624e6516c0eff917d; path=/"),
        ("content-type", "text/html; charset=UTF-8"), ("cache-control", "no-store"),
        ("authorization", "Basic c2VjcmV0"), ("x-request-id", "abc")]
HOME = ('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Home &ndash; Helios Intranet</title>'
        '<link rel="stylesheet" href="/static/app.css"><script src="/static/app.js?v=3"></script></head><body>'
        '<header><h1>Helios Intranet</h1></header><nav><a href="/">Home</a> &middot; <a href="/console/netcheck">Sign in</a></nav>'
        '<main><div class="card"><h2>Operator handbook</h2><p class="muted">Evaluation build.</p>'
        '<p>Operator ID: <strong>s.haddad</strong><br>Passphrase: <strong>copper-copper-84</strong></p>'
        '<p>Session 1234567 opened 2024-01-02 10:00:00 for bob@example.com from 10.1.2.3</p></div></main></body></html>')
LOGIN = ('<html><head><title>Sign in &ndash; Helios Intranet</title><meta name="csrf-token" content="deadbeefcafe1234"></head>'
         '<body><form method="post" action="/console/netcheck"><input type="hidden" name="form_sig" value="b2356a4037a6c0b3ca5e8d146cde8b16">'
         '<label>Operator ID</label><input type="text" name="userid" value="prefilled"><input type="password" name="credential">'
         '<input type="hidden" name="send" value="1"><button type="submit">Sign in</button></form>'
         '<script>var apiKey = "sk_live_abcdefghijklmnop"; var x = 1;</script></body></html>')
SECRETS = ["s.haddad", "copper-copper-84", "1234567", "2024-01-02", "bob@example.com", "10.1.2.3",
           "deadbeefcafe1234", "b2356a4037a6c0b3ca5e8d146cde8b16", "prefilled", "sk_live_abcdefghijklmnop",
           "ef1942d60f0d255624e6516c0eff917d", "c2VjcmV0"]


def _learned():
    st = ShapeStore()
    assert st.learn("GET", "/console/logout", "", 200, HDRS, HOME.encode(), latency_ms=12)
    assert st.learn("GET", "/console/netcheck", "", 200, HDRS, LOGIN.encode(), latency_ms=20)
    return st


def test_skeleton_keeps_markup_and_chrome_but_slots_data():
    parts, _ = skeleton.skeletonize_html(HOME)
    literal = "".join(p for p in parts if isinstance(p, str))
    assert "Helios Intranet" in literal and "Operator handbook" in literal and '<div class="card">' in literal
    kinds = [p["slot"] for p in parts if isinstance(p, dict)]
    assert {"value", "number", "date", "email", "ipv4"} <= set(kinds)
    for secret in ("s.haddad", "copper-copper-84", "bob@example.com", "10.1.2.3", "1234567"):
        assert secret not in literal


def test_skeleton_slots_hidden_inputs_csrf_meta_and_script_secrets():
    parts, _ = skeleton.skeletonize_html(LOGIN)
    literal = "".join(p for p in parts if isinstance(p, str))
    for secret in ("b2356a4037a6c0b3ca5e8d146cde8b16", "deadbeefcafe1234", "sk_live_abcdefghijklmnop", "prefilled"):
        assert secret not in literal
    assert 'name="send" value="1"' in literal  # benign hidden flag kept
    hints = [p.get("hint") for p in parts if isinstance(p, dict)]
    assert "form_sig" in hints and "csrf-token" in hints


def test_shape_store_never_persists_secrets_cookies_or_auth_headers():
    st = _learned()
    dumped = json.dumps(st.to_dict())
    for secret in SECRETS:
        assert secret not in dumped, secret
    assert "authorization" not in dumped and "x-request-id" not in dumped
    assert st.fingerprint["cookies"] == ["APPSESS398"]  # names only
    assert st.fingerprint["server"] == "Apache" and st.fingerprint["title_suffix"] == "Helios Intranet"
    assert st.fingerprint["assets"] == ["/static/app.css", "/static/app.js?v=3"]


def test_render_fills_slots_deterministically_per_seed():
    st = _learned()
    v = st.lookup("GET", "/console/netcheck")["variants"][0]
    a = skeleton.render(v["parts"], lambda i, s: Faker("s1").fill(i, s))
    b = skeleton.render(v["parts"], lambda i, s: Faker("s1").fill(i, s))
    c = skeleton.render(v["parts"], lambda i, s: Faker("s2").fill(i, s))
    assert a == b and a != c
    assert 'name="form_sig" value="' in a and "b2356a4037a6c0b3ca5e8d146cde8b16" not in a
    assert '<input type="password" name="credential">' in a
    assert "Sign in &ndash; Helios Intranet" in a


def test_differing_text_between_samples_becomes_slot_and_echo_detected():
    st = ShapeStore()
    page = '<html><head><title>Search &ndash; H</title></head><body><p>Results for {q}</p><td>{n}</td><p>Static copy.</p></body></html>'
    st.learn("GET", "/search", "q=hello", 200, HDRS, page.format(q="hello", n="42").encode())
    st.learn("GET", "/search", "q=world", 200, HDRS, page.format(q="world", n="7").encode())
    route = st.lookup("GET", "/search")
    assert len(route["variants"]) == 1 and route["variants"][0]["seen"] == 2
    slots = [p for p in route["variants"][0]["parts"] if isinstance(p, dict)]
    assert slots[0]["slot"] == "echo" and slots[0]["hint"] == "q"
    assert route["params"] == ["q"]
    out = skeleton.render(route["variants"][0]["parts"], lambda i, s: Faker("x").fill(i, s, {"q": "<b>x</b>"}))
    assert "Results for &lt;b&gt;x&lt;/b&gt;" in out and "Static copy." in out


def test_json_schema_with_redacted_keys_and_compact_rendering():
    st = ShapeStore()
    body = b'{"items":[{"id":12,"name":"alpha","api_key":"ZZZ"}],"count":1,"when":"2024-05-06"}'
    st.learn("GET", "/api/items", "", 200, [("content-type", "application/json")], body)
    v = st.lookup("GET", "/api/items")["variants"][0]
    assert v["kind"] == "json" and v["compact"] is True
    assert v["schema"]["properties"]["items"]["items"]["properties"]["api_key"]["kind"] == "token"
    assert "ZZZ" not in json.dumps(v) and "alpha" not in json.dumps(v)
    out = json.loads(skeleton.render_json(v["example"], lambda i, s: Faker("k").fill(i, s, escape=False), compact=True))
    assert isinstance(out["items"][0]["id"], int) and len(out["items"][0]["api_key"]) == 3 or len(out["items"][0]["api_key"]) >= 8


def test_route_patterns_redirects_and_error_pages():
    assert route_pattern("/users/42/edit") == "/users/{n}/edit"
    assert route_pattern("/t/0123456789abcdef") == "/t/{id}"
    assert route_key("head", "/") == "HEAD /"
    st = ShapeStore()
    st.learn("GET", "/console/home", "", 302, HDRS + [("location", "/console/netcheck?token=abc123&next=/x")], b"")
    st.learn("GET", "/missing", "", 404, HDRS, b'<html><title>Not found &ndash; Helios Intranet</title><body>404</body></html>')
    v = st.lookup("GET", "/console/home")["variants"][0]
    assert v["kind"] == "redirect" and "abc123" not in v["location"] and "next=%2Fx" in v["location"]
    assert st.error_variant(404)["status"] == 404 and st.error_variant(405)["status"] == 404
    assert st.lookup("HEAD", "/console/home") is not None


def test_bounds_routes_variants_and_body_limit():
    st = ShapeStore(max_routes=3)
    for i in range(5):
        st.learn("GET", f"/p{i}", "", 200, HDRS, b"<html><body>x</body></html>")
    assert len(st.routes) == 3
    for i in range(5):  # distinct structures for one route → at most 3 variants, least-seen evicted
        st.learn("GET", "/p0", "", 200, HDRS, ("<html><body>" + "<i>z</i>" * (i + 1) + "</body></html>").encode())
    assert len(st.lookup("GET", "/p0")["variants"]) == 3
    big = b"<html><body>" + b"<p>a</p>" * 20000
    st = ShapeStore()
    assert st.learn("GET", "/big", "", 200, HDRS, big)
    v = st.lookup("GET", "/big")["variants"][0]
    assert v["truncated"] and len(json.dumps(v["parts"])) <= 40 * 1024
    assert not st.learn("GET", "/__api/v1/x", "", 200, HDRS, b"{}")


def test_persistence_roundtrip_and_merge(tmp_path):
    st = _learned()
    st.save(tmp_path / "shape.json")
    loaded = ShapeStore.load(tmp_path / "shape.json")
    assert set(loaded.routes) == set(st.routes) and loaded.fingerprint["server"] == "Apache"
    assert ShapeStore.load(tmp_path / "nope.json").routes == {}
    (tmp_path / "bad.json").write_text("{not json")
    assert ShapeStore.load(tmp_path / "bad.json").routes == {}
    other = ShapeStore()
    other.learn("GET", "/extra", "", 200, [("server", "nginx"), ("content-type", "text/html")], b"<html><body>e</body></html>")
    merged = ShapeStore.load(tmp_path / "shape.json").merge(other)
    assert "GET /extra" in merged.routes and merged.fingerprint["server"] == "Apache"  # ours kept


def test_passive_learner_queue_is_bounded_and_flushes(tmp_path):
    pl = PassiveLearner(tmp_path / "passive.json", flush_seconds=0.05)
    for i in range(300):
        pl.observe({"method": "GET", "path": f"/r{i % 5}", "query": "", "status": 200, "headers": HDRS,
                    "body": HOME.encode(), "latency_ms": 5})
    pl.drain()
    assert pl.dropped >= 0 and pl.learned + pl.dropped == 300
    assert (tmp_path / "passive.json").exists()
    assert set(ShapeStore.load(tmp_path / "passive.json").routes) <= {f"GET /r{i}" for i in range(5)}
    pl.stop()


def test_passive_learner_refuses_attack_shaped_requests(tmp_path):
    pl = PassiveLearner(tmp_path / "passive.json", flush_seconds=0.05)
    pl.observe({"method": "GET", "path": "/lookup", "query": "id=1' OR 1=1--", "status": 200,
                "headers": HDRS, "body": b"<html><body>dump</body></html>"})
    pl.observe({"method": "GET", "path": "/lookup", "query": "id=1", "status": 200,
                "headers": HDRS, "body": b"<html><body>ok</body></html>"})
    pl.drain()
    route = pl.store.lookup("GET", "/lookup")
    assert route and route["seen"] == 1 and pl.learned == 1
    pl.stop()


def test_crawler_is_get_only_same_origin_and_bounded():
    seen = []

    def app(req):
        seen.append((req.method, req.url.path, req.headers.get("cookie")))
        if req.url.path == "/":
            return httpx.Response(200, headers=[("content-type", "text/html"), ("set-cookie", "SID=abc; path=/")],
                                  text='<html><title>A &ndash; S</title><a href="/b">b</a><a href="http://evil.test/x">x</a>'
                                       '<a href="/img.png">i</a><form action="/login"></form><a href="/go">g</a></html>')
        if req.url.path == "/go":
            return httpx.Response(302, headers={"location": "/b"})
        if req.url.path.startswith("/bastion-shape-probe"):
            return httpx.Response(404, headers={"content-type": "text/html"}, text="<html><title>NF &ndash; S</title></html>")
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<html><title>B &ndash; S</title></html>")

    st = ShapeStore()
    crawler = Crawler("http://app.test", st, max_pages=3, delay=0, transport=httpx.MockTransport(app), keep_bodies=True)
    fetched = crawler.run()
    assert fetched == 3 and all(m == "GET" and c is None for m, _, c in seen)
    assert all(not p.startswith("/img") for _, p, _ in seen)
    assert "GET /b" in st.routes and st.error_variant(404) is not None
    assert "GET /bastion-shape-probe-404" not in st.routes
    assert len(crawler.pages) == 4


def test_shape_files_merges_passive_over_crawl_and_reloads(tmp_path):
    crawl = ShapeStore()
    crawl.learn("GET", "/", "", 200, [("server", "nginx"), ("content-type", "text/html")], b"<html><body>crawl</body></html>")
    crawl.save(tmp_path / "crawl.json")
    files = ShapeFiles(tmp_path, interval=0)
    assert files.current().fingerprint["server"] == "nginx"
    passive = ShapeStore()
    passive.learn("GET", "/", "", 200, [("server", "Apache"), ("content-type", "text/html")], b"<html><body><b>live</b></body></html>")
    passive.learn("GET", "/p", "", 200, [("server", "Apache"), ("content-type", "text/html")], b"<html><body>p</body></html>")
    passive.save(tmp_path / "passive.json")
    cur = files.current()
    assert cur.fingerprint["server"] == "Apache" and "GET /p" in cur.routes
    assert "<b>" in "".join(p for p in cur.lookup("GET", "/")["variants"][0]["parts"] if isinstance(p, str))
