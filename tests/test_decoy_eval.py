"""Stage 4 — the indistinguishability harness: scoring, hold-out and the judge plumbing."""
import httpx

from bastion.decoy import eval as harness
from bastion.decoy.shape import ShapeStore

SITE = {
    "/": (200, '<html><head><title>Home &ndash; Helios</title></head><body><nav><a href="/a">A</a><a href="/b">B</a><a href="/j">J</a></nav>'
               '<div class="card"><h2>Home</h2><p>Ref <strong>1234</strong></p></div></body></html>'),
    "/a": (200, '<html><head><title>A &ndash; Helios</title></head><body><nav><a href="/a">A</a></nav><div class="card"><h2>A</h2><td>9</td></div></body></html>'),
    "/b": (200, '<html><head><title>B &ndash; Helios</title></head><body><nav><a href="/b">B</a></nav><div class="card"><h2>B</h2><p>Since 2024-01-01</p></div></body></html>'),
}


def _app(req):
    if req.url.path == "/j":
        return httpx.Response(200, headers={"content-type": "application/json", "server": "Apache"},
                              text='{"ok":true,"items":[{"id":1,"name":"x"}]}')
    if req.url.path in SITE:
        status, body = SITE[req.url.path]
        return httpx.Response(status, headers={"content-type": "text/html; charset=UTF-8", "server": "Apache"}, text=body)
    return httpx.Response(404, headers={"content-type": "text/html; charset=UTF-8", "server": "Apache"},
                          text='<html><head><title>Not found &ndash; Helios</title></head><body><div class="card"><h2>404</h2></div></body></html>')


def test_structural_similarity_scores_identity_high_and_mismatch_low():
    real_h = [("content-type", "text/html"), ("server", "Apache")]
    body = SITE["/"][1]
    score, parts = harness.structural_similarity(200, real_h, body, 200, real_h, body)
    assert score == 1.0
    score, parts = harness.structural_similarity(200, real_h, body, 404, [("content-type", "text/plain")], "nope")
    assert score < 0.3 and parts["status"] == 0.0 and parts["content_type"] == 0.0
    close = body.replace("1234", "5678")
    score, _ = harness.structural_similarity(200, real_h, body, 200, real_h, close)
    assert score == 1.0


def test_harness_learned_routes_score_high_and_holdout_falls_back(monkeypatch):
    monkeypatch.setattr(harness, "Crawler", lambda target, store, **kw: _MockCrawler(target, store, **kw))
    report = harness.run("http://site.test", pages=6, holdout=True)
    assert report["fetched"] == 4 and report["n"] == 5
    assert report["structural"] >= 0.95, report
    assert all(r["source"] == ("error_template" if r["real_status"] == 404 else "template") for r in report["routes"])
    held = report["holdout"]
    assert held["n"] >= 1 and all(r["source"] in ("error_template", "template") for r in held["routes"])
    assert 0.0 <= held["structural"] <= 1.0


def test_judge_counts_accuracy_and_tolerates_failures():
    pages = [("/", 200, [("content-type", "text/html")], SITE["/"][1].encode())] * 4
    class R:
        status, headers, body = 200, [("content-type", "text/html")], SITE["/"][1].encode()
    responses = [("/", R())] * 4
    answers = iter(["A", "B", "zzz", RuntimeError("down")])

    def ask(prompt):
        a = next(answers)
        if isinstance(a, Exception):
            raise a
        assert "=== Response A ===" in prompt and "Answer (A or B)" in prompt
        return a
    out = harness.judge(pages, responses, ask)
    assert out["judged"] == 3 and 0.0 <= out["judge_accuracy"] <= 1.0 and out["judge_shift"] is not None
    assert any("error" in r for r in out["rows"])


def test_judge_fn_is_none_without_keys(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert harness.judge_fn() is None


class _MockCrawler(harness.Crawler):
    def __init__(self, target, store, **kw):
        kw["transport"] = httpx.MockTransport(_app)
        kw["delay"] = 0
        super().__init__(target, store, **kw)


def test_judge_rounds_pool_across_fresh_sessions():
    st = ShapeStore()
    for path, (status, body) in SITE.items():
        st.learn("GET", path, "", status, [("content-type", "text/html"), ("server", "Apache")], body.encode())
    pages = [(p, s, [("content-type", "text/html"), ("server", "Apache")], b.encode()) for p, (s, b) in SITE.items()]
    out = harness.judge_rounds(st, pages, lambda prompt: "A", rounds=2)
    assert out["judged"] == 6 and len(out["rounds"]) == 2 and 0.0 <= out["judge_accuracy"] <= 1.0
