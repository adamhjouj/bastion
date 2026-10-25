"""Live Jev discrimination proof: benign traffic + attacks through the real proxy,
then score the persisted verdicts into a confusion matrix.

Runs benign traffic BEFORE, DURING, and AFTER an attack to show three things:
  before  - Jev's false-positive rate on pure benign traffic (baseline)
  during  - Jev flags the attack WHILE concurrent benign users stay clean
  after   - bans/limits from the attack don't bleed onto benign users afterward

Ground truth is by source IP: the benign generator sends from TEST-NET-2
(198.51.100.0/24), the replayed attacks from 203.0.113.7, the live red agent from
10.13.37.7. Jev never sees the source IP, so grouping verdicts by IP is sound.

Verdicts are read back over the authenticated management API because the live DB lives
in a named Docker volume the host cannot open. The in-process scorer (`score`) takes
plain rows, so it is unit-tested against a temp DB via `read_verdicts_db`.

Usage (stack up with DEMO_IDENTITY=1, BASTION_MODE=classifier-contain, real TYPESAFE_API_KEY):
    python eval_live.py --before 20 --during 40 --after 20
    python eval_live.py --attack agent --before 20 --during 60 --after 20
"""
import argparse
import json
import os
import subprocess
import sys
import threading
import time

import httpx

import benign_agent
import classifier
import store
from eval_waf import confusion, precision_recall, wilson

PROXY = os.getenv("PROXY_URL", "http://localhost:8080")
BENIGN_POOL = os.getenv("BENIGN_POOL", "198.51.100")
ATTACKER_IP = os.getenv("ATTACKER_IP", "203.0.113.7")
RED_AGENT_IP = "10.13.37.7"
DATASET = os.getenv("EVAL_DATASET", "eval_dataset.jsonl")


def label_for(ip):
    """Ground-truth label by source pool, or None for an unrecognized source (excluded)."""
    if ip and ip.startswith(BENIGN_POOL + "."):
        return "benign"
    if ip in (ATTACKER_IP, RED_AGENT_IP):
        return "malicious"
    return None


# --- attack side: replay the labeled malicious corpus live -------------------------

def load_attacks(dataset=DATASET, label="malicious"):
    rows = [json.loads(line) for line in open(dataset) if line.strip()]
    return [r for r in rows if r.get("label") == label]


def _fire(client, method, path, query, body):
    url = f"{path}?{query}" if query else path
    headers = {"Content-Type": "application/x-www-form-urlencoded"} if body else {}
    try:
        client.request(method, url, content=body or None, headers=headers)
        return 1
    except Exception:
        return 0


def replay(rows, proxy=PROXY, ip=ATTACKER_IP, delay=0.2):
    """Replay dataset attack rows through the proxy from the attacker IP."""
    sent = 0
    with httpx.Client(base_url=proxy, headers={"X-Forwarded-For": ip},
                      follow_redirects=True, timeout=10) as client:
        for r in rows:
            sent += _fire(client, r["method"], r["path"], r["query"], r["body"])
            time.sleep(delay)
    return sent


def _run_red_agent(during):
    env = dict(os.environ, PROXY_URL=PROXY, ATTACKER_IP=RED_AGENT_IP)
    try:
        subprocess.run([sys.executable, "red_agent.py", "sqli"], env=env,
                       timeout=during, capture_output=True)
    except subprocess.TimeoutExpired:
        pass  # the campaign ran for the whole window; that is fine


# --- scoring -----------------------------------------------------------------------

def _row(ip, path, malicious, score):
    return {"ip": ip, "path": path, "malicious": malicious, "score": score}


def read_verdicts_db(start_ts, end_ts):
    """Read persisted per-request verdicts directly from the store (in-container / tests).
    Triage action rows cover classifier-contain/agent; inline stamps the event row."""
    with store.connection() as db:
        rows = db.execute(
            "SELECT json_extract(data,'$.ip') ip, json_extract(data,'$.path') path, "
            "json_extract(data,'$.jev.malicious') malicious, "
            "json_extract(data,'$.jev.malicious_score') score "
            "FROM records WHERE kind='actions' AND json_extract(data,'$.kind')='triage' "
            "AND ts BETWEEN ? AND ?", (start_ts, end_ts)).fetchall()
        if not rows:
            rows = db.execute(
                "SELECT json_extract(data,'$.ip') ip, json_extract(data,'$.path') path, "
                "json_extract(data,'$.verdict.malicious') malicious, "
                "json_extract(data,'$.verdict.malicious_score') score "
                "FROM records WHERE kind='events' AND json_extract(data,'$.verdict') IS NOT NULL "
                "AND ts BETWEEN ? AND ?", (start_ts, end_ts)).fetchall()
        return [_row(r["ip"], r["path"], r["malicious"], r["score"]) for r in rows]


def _api_pages(base_url, token, kind, start_ts):
    headers = {"Authorization": f"Bearer {token}"}
    before = None
    with httpx.Client(base_url=base_url, headers=headers, timeout=10) as client:
        while True:
            params = {"limit": 200}
            if before is not None:
                params["before"] = before
            resp = client.get(f"/__api/v1/{kind}", params=params)
            resp.raise_for_status()
            page = resp.json()
            items = page.get("items", [])
            if not items:
                return
            for item in items:
                yield item
            before = page.get("next_cursor")
            if before is None or all(i.get("ts", "") < start_ts for i in items):
                return


def read_verdicts_api(start_ts, end_ts, base_url=PROXY, token=None):
    """Read verdicts over the management API (host-run against the live stack)."""
    token = token or os.getenv("MANAGEMENT_TOKEN", "")
    rows = []
    for item in _api_pages(base_url, token, "actions", start_ts):
        if item.get("kind") != "triage" or not (start_ts <= item.get("ts", "") <= end_ts):
            continue
        jev = item.get("jev") or {}
        rows.append(_row(item.get("ip"), item.get("path"),
                         jev.get("malicious"), jev.get("malicious_score")))
    if rows:
        return rows
    for item in _api_pages(base_url, token, "requests", start_ts):  # inline mode fallback
        verdict = item.get("verdict")
        if not verdict or not (start_ts <= item.get("ts", "") <= end_ts):
            continue
        rows.append(_row(item.get("ip"), item.get("path"),
                         verdict.get("malicious"), verdict.get("malicious_score")))
    return rows


def score(rows, thr=None):
    """Confusion matrix from verdict rows. Ground truth by source IP; prediction is the
    persisted boolean, falling back to score>=threshold when only a score is present."""
    thr = classifier.THRESHOLD if thr is None else thr
    items = []
    for r in rows:
        truth = label_for(r["ip"])
        if truth is None:
            continue
        if r["malicious"] is not None:
            pred = bool(r["malicious"])
        elif r["score"] is not None:
            pred = r["score"] >= thr
        else:
            continue  # classifier was unavailable for this request; nothing to score
        items.append({**r, "truth": truth == "malicious", "pred": pred})
    TP, FP, TN, FN = confusion(items, lambda x: x["pred"])
    tp, fp, tn, fn = len(TP), len(FP), len(TN), len(FN)
    prec, rec = precision_recall(tp, fp, fn)
    fp_rate = fp / (fp + tn) if fp + tn else 0.0
    return {"n": len(items), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": prec, "recall": rec, "fp_rate": fp_rate,
            "precision_ci": wilson(tp, tp + fp), "recall_ci": wilson(tp, tp + fn),
            "false_positives": FP, "false_negatives": FN}


def print_report(name, m):
    print(f"\n=== {name} === (n={m['n']})")
    print(f"  TP={m['tp']}  FP={m['fp']}  FN={m['fn']}  TN={m['tn']}")
    print(f"  Precision {m['precision']:.1%} CI[{m['precision_ci'][0]:.1%},{m['precision_ci'][1]:.1%}]"
          f"   Recall {m['recall']:.1%} CI[{m['recall_ci'][0]:.1%},{m['recall_ci'][1]:.1%}]"
          f"   benign FP-rate {m['fp_rate']:.1%}")
    for f in m["false_positives"]:
        print(f"  FALSE POSITIVE  benign {f['ip']} {f['path']} scored {f['score']}")
    for f in m["false_negatives"]:
        print(f"  FALSE NEGATIVE  attack {f['ip']} {f['path']} scored {f['score']}")


# --- orchestration -----------------------------------------------------------------

def preflight(base_url=PROXY, token=None):
    token = token or os.getenv("MANAGEMENT_TOKEN", "")
    sentinel = f"{BENIGN_POOL}.250"
    try:
        httpx.get(f"{base_url}/index.php", headers={"X-Forwarded-For": sentinel},
                  follow_redirects=True, timeout=10)
    except Exception as exc:
        raise SystemExit(f"cannot reach proxy at {base_url}: {exc}")
    for _ in range(10):
        try:
            resp = httpx.get(f"{base_url}/__api/v1/requests", params={"limit": 50},
                             headers={"Authorization": f"Bearer {token}"}, timeout=10)
            if resp.status_code == 200 and any(i.get("ip") == sentinel for i in resp.json().get("items", [])):
                return
        except Exception:
            pass
        time.sleep(0.3)
    raise SystemExit("source IP did not propagate — start the proxy with DEMO_IDENTITY=1 "
                     "and check MANAGEMENT_TOKEN")


def run_scenario(before, during, after, attack="replay", proxy=PROXY):
    """Flow benign traffic across all three phases; fire the attack during the middle.
    Returns {phase: (start_ts, end_ts)} boundaries for scoring."""
    stop = threading.Event()
    total = before + during + after
    traffic = threading.Thread(target=benign_agent.run,
                               kwargs={"duration": total, "proxy": proxy, "stop": stop}, daemon=True)
    phases = {}
    t0 = store.now()
    traffic.start()
    time.sleep(before)
    phases["before"] = (t0, store.now())

    d0 = store.now()
    if attack == "agent":
        _run_red_agent(during)
    else:
        replay(load_attacks(), proxy=proxy)
        time.sleep(max(0, during - 1))  # let async classification catch up
    phases["during"] = (d0, store.now())

    a0 = store.now()
    time.sleep(after)
    phases["after"] = (a0, store.now())
    stop.set()
    traffic.join(timeout=5)
    time.sleep(2)  # drain trailing async verdicts before scoring
    phases["overall"] = (t0, store.now())
    return phases


def main():
    parser = argparse.ArgumentParser(description="Live Jev discrimination proof")
    parser.add_argument("--before", type=float, default=20)
    parser.add_argument("--during", type=float, default=40)
    parser.add_argument("--after", type=float, default=20)
    parser.add_argument("--attack", choices=["replay", "agent"], default="replay")
    parser.add_argument("--proxy", default=PROXY)
    args = parser.parse_args()

    preflight(args.proxy)
    phases = run_scenario(args.before, args.during, args.after, args.attack, args.proxy)
    for name in ("before", "during", "after", "overall"):
        start, end = phases[name]
        print_report(name, score(read_verdicts_api(start, end, args.proxy)))


if __name__ == "__main__":
    main()
