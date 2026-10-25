"""Indistinguishability harness: crawl the real app into a fresh shape model, ask the decoy for
the same routes under a fresh session, and score (a) structural similarity, (b) optionally an LLM
judge's accuracy at spotting the decoy (chance = 0.5 is the goal). docs/DECOY.md §4.

    python -m bastion.decoy.eval --target http://dvwa:80 [--pages 20] [--judge] [--json]
"""
import argparse
import asyncio
import difflib
import json
import os
import random
import re

from bastion import llm
from bastion.decoy import skeleton
from bastion.decoy.learn import Crawler
from bastion.decoy.session import Sessions
from bastion.decoy.shape import TITLE_RE, TITLE_SEP_RE, ShapeStore, header_subset
from bastion.decoy.synth import Decoy, DecoyRequest

WEIGHTS = {"status": 0.25, "content_type": 0.15, "structure": 0.35, "title": 0.15, "headers": 0.10}


def _title_suffix(body):
    m = TITLE_RE.search(body)
    if not m:
        return ""
    pieces = TITLE_SEP_RE.split(re.sub(r"\s+", " ", m.group(1)).strip())
    return pieces[-1] if pieces else ""


def structural_similarity(real_status, real_headers, real_body, decoy_status, decoy_headers, decoy_body):
    """0..1 similarity between a real response and the decoy's for the same request."""
    real_h = header_subset([(k, v) for k, v in real_headers])
    decoy_h = header_subset([(k, v) for k, v in decoy_headers])
    status = 1.0 if int(real_status) == int(decoy_status) else 0.0
    rct = real_h.get("content-type", "").split(";")[0].strip().lower()
    dct = decoy_h.get("content-type", "").split(";")[0].strip().lower()
    content_type = 1.0 if rct == dct else 0.0
    real_text = real_body.decode("utf-8", "replace") if isinstance(real_body, bytes) else real_body
    decoy_text = decoy_body.decode("utf-8", "replace") if isinstance(decoy_body, bytes) else decoy_body
    if "html" in rct:
        rs, ds = skeleton.tag_sequence([real_text]), skeleton.tag_sequence([decoy_text])
        structure = difflib.SequenceMatcher(None, rs, ds).ratio() if rs or ds else 1.0
        title = 1.0 if _title_suffix(real_text) == _title_suffix(decoy_text) else 0.0
    elif "json" in rct:
        try:
            rsch = json.dumps(skeleton.skeletonize_json(real_text)[0], sort_keys=True)
            dsch = json.dumps(skeleton.skeletonize_json(decoy_text)[0], sort_keys=True)
            structure = 1.0 if rsch == dsch else difflib.SequenceMatcher(None, rsch, dsch).ratio()
        except (TypeError, ValueError):
            structure = 0.0
        title = 1.0
    else:
        structure = difflib.SequenceMatcher(None, real_text[:2000], decoy_text[:2000]).ratio()
        title = 1.0
    keys = [k for k in real_h if k not in ("content-type",)]
    headers = (sum(1 for k in keys if decoy_h.get(k) == real_h[k]) / len(keys)) if keys else 1.0
    parts = {"status": status, "content_type": content_type, "structure": structure, "title": title, "headers": headers}
    score = sum(WEIGHTS[k] * v for k, v in parts.items())
    return round(score, 4), parts


async def decoy_responses(shape, pages, ip="198.51.100.7", ua="Mozilla/5.0 (eval)", use_llm=False):
    """One fresh session, one decoy response per crawled page."""
    decoy = Decoy(lambda: shape, Sessions(salt="eval"), llm_enabled=use_llm)
    out = []
    for path, status, headers, body in pages:
        plain, _, query = path.partition("?")
        resp = await decoy.respond(DecoyRequest("GET", plain, query, b"", "", ua, ip))
        out.append((path, resp))
    return out, decoy.stats


def score_pages(pages, responses):
    rows = []
    for (path, status, headers, body), (_, resp) in zip(pages, responses):
        score, parts = structural_similarity(status, headers, body, resp.status, resp.headers, resp.body)
        rows.append({"path": path, "real_status": status, "decoy_status": resp.status,
                     "source": resp.source, "score": score, **{k: round(v, 3) for k, v in parts.items()}})
    mean = round(sum(r["score"] for r in rows) / len(rows), 4) if rows else 0.0
    return {"structural": mean, "n": len(rows), "routes": rows}


def judge_fn():
    """LLM judge (same provider selection as the rest of Bastion), or None without a key."""
    client, kwargs = llm.make_client()
    if client is None:
        return None
    model = llm.model_for(os.getenv("DECOY_MODEL"), "claude-sonnet-4-5")

    def ask(prompt):
        api = client.with_options(timeout=30, max_retries=0)
        resp = api.messages.create(model=model, max_tokens=8, messages=[{"role": "user", "content": prompt}], **kwargs)
        return "".join(getattr(b, "text", "") for b in resp.content)
    return ask


JUDGE_PROMPT = """Two HTTP responses were captured for the same request `GET {path}`. Exactly one was served by
the real application and the other by an imitation that has never seen the application's source code.
Decide which one is the imitation. Answer with a single letter: A or B.

=== Response A ===
{a}

=== Response B ===
{b}

Answer (A or B):"""


def _fmt(status, headers, body, limit=6000):
    hs = header_subset([(k, v) for k, v in headers])
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    return f"HTTP {status}\n" + "\n".join(f"{k}: {v}" for k, v in sorted(hs.items())) + "\n\n" + text[:limit]


def judge(pages, responses, ask, seed=7):
    rng = random.Random(seed)
    correct = 0
    rows = []
    for (path, status, headers, body), (_, resp) in zip(pages, responses):
        real = _fmt(status, headers, body)
        fake = _fmt(resp.status, resp.headers, resp.body)
        decoy_is_a = rng.random() < 0.5
        a, b = (fake, real) if decoy_is_a else (real, fake)
        try:
            answer = ask(JUDGE_PROMPT.format(path=path, a=a, b=b)).strip().upper()[:1]
        except Exception as exc:  # judge failure is not a decoy failure
            rows.append({"path": path, "error": str(exc)[:120]})
            continue
        hit = (answer == "A") == decoy_is_a
        correct += hit
        rows.append({"path": path, "decoy_was": "A" if decoy_is_a else "B", "answer": answer, "spotted": hit})
    n = sum(1 for r in rows if "spotted" in r)
    acc = round(correct / n, 4) if n else None
    return {"judge_accuracy": acc, "judge_shift": round(abs(acc - 0.5), 4) if acc is not None else None,
            "judged": n, "rows": rows}


def holdout_shape(pages):
    """Learn from every other crawled page so odd pages exercise the unknown-route path."""
    shape = ShapeStore()
    for i, (path, status, headers, body) in enumerate(pages):
        plain, _, query = path.partition("?")
        if i % 2 == 0 or status >= 400:
            shape.learn("GET", plain, query, status, headers, body)
    return shape


def judge_rounds(shape, pages, ask, rounds=3):
    """Repeat the judge over `rounds` fresh sessions (new fake data, new A/B order) and pool."""
    pooled = {"judge_accuracy": None, "judge_shift": None, "judged": 0, "spotted": 0, "rounds": []}
    for i in range(rounds):
        responses, _ = asyncio.run(decoy_responses(shape, pages, ip=f"198.51.100.{10 + i}", ua=f"Mozilla/5.0 (eval r{i})"))
        out = judge(pages, responses, ask, seed=7 + i)
        pooled["judged"] += out["judged"]
        pooled["spotted"] += sum(1 for r in out["rows"] if r.get("spotted"))
        pooled["rounds"].append({"judge_accuracy": out["judge_accuracy"], "judged": out["judged"],
                                 "spotted": [r["path"] for r in out["rows"] if r.get("spotted")]})
    if pooled["judged"]:
        pooled["judge_accuracy"] = round(pooled["spotted"] / pooled["judged"], 4)
        pooled["judge_shift"] = round(abs(pooled["judge_accuracy"] - 0.5), 4)
    return pooled


def run(target, pages=20, with_judge=False, delay=0.1, holdout=False, use_llm=False, rounds=3):
    shape = ShapeStore()
    crawler = Crawler(target, shape, max_pages=pages, delay=delay, keep_bodies=True)
    fetched = crawler.run()
    responses, stats = asyncio.run(decoy_responses(shape, crawler.pages))
    report = {"target": target, "fetched": fetched, "learned_routes": len(shape.routes),
              "decoy_sources": stats, **score_pages(crawler.pages, responses)}
    if holdout:
        hshape = holdout_shape(crawler.pages)
        held = [p for i, p in enumerate(crawler.pages) if i % 2 == 1 and p[1] < 400]
        hresp, hstats = asyncio.run(decoy_responses(hshape, held, use_llm=use_llm))
        report["holdout"] = {"learned_routes": len(hshape.routes), "decoy_sources": hstats,
                             **score_pages(held, hresp)}
    if with_judge:
        ask = judge_fn()
        report["judge"] = judge_rounds(shape, crawler.pages, ask, rounds) if ask else {"judge_accuracy": None, "error": "no LLM key"}
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--target", default=os.getenv("DECOY_CRAWL_URL") or os.getenv("DVWA_URL", "http://dvwa:80"))
    ap.add_argument("--pages", type=int, default=20)
    ap.add_argument("--judge", action="store_true")
    ap.add_argument("--json", action="store_true", help="print the full report as JSON")
    ap.add_argument("--holdout", action="store_true", help="also score routes the model never saw")
    ap.add_argument("--llm", action="store_true", help="let the held-out routes use LLM synthesis")
    ap.add_argument("--rounds", type=int, default=3, help="judge rounds (fresh session + A/B order each)")
    args = ap.parse_args(argv)
    report = run(args.target, args.pages, args.judge, holdout=args.holdout, use_llm=args.llm, rounds=args.rounds)
    if args.json:
        print(json.dumps(report, indent=1))
        return
    print(f"target={report['target']} fetched={report['fetched']} routes={report['learned_routes']} "
          f"structural={report['structural']} sources={report['decoy_sources']}")
    for r in report["routes"]:
        print(f"  {r['score']:.3f}  {r['real_status']}->{r['decoy_status']} {r['source']:<15} {r['path']}  "
              f"struct={r['structure']} hdr={r['headers']}")
    if "holdout" in report:
        h = report["holdout"]
        print(f"holdout: routes={h['learned_routes']} structural={h['structural']} n={h['n']} sources={h['decoy_sources']}")
        for r in h["routes"]:
            print(f"  {r['score']:.3f}  {r['real_status']}->{r['decoy_status']} {r['source']:<15} {r['path']}  "
                  f"struct={r['structure']} title={r['title']}")
    if "judge" in report:
        j = report["judge"]
        print(f"judge_accuracy={j.get('judge_accuracy')} judged={j.get('judged')} shift={j.get('judge_shift')} "
              f"(chance=0.5) {j.get('error', '')}")
        for r in j.get("rounds", []):
            print(f"  round: accuracy={r['judge_accuracy']} spotted={r['spotted']}")


if __name__ == "__main__":
    main()
