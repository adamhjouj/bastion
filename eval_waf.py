"""Measure the Jev WAF's false positives / false negatives against a labeled set
— with the rigor needed to NOT misread the result as fact.

Beyond raw precision/recall it reports:
  - 95% Wilson confidence intervals (N is small; the point estimate is noisy)
  - run provenance (dataset hash, git sha, model, threshold, time) + raw dump,
    so any run is reproducible and comparable
  - --repeat N: classify each case N times to measure Jev's run-to-run variance
    and flag threshold-unstable cases (the "benign-or-malicious-depending" ones)
  - a label-leakage probe (does the verdict follow the payload, or just the path?)
  - a base-rate warning: precision on a balanced test set != production precision

Usage:  TYPESAFE_API_KEY=... .venv/bin/python eval_waf.py [dataset.jsonl] [--repeat N]
"""
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import time

import classifier
from blue_agent import is_suspicious  # the regex pre-gate (what reaches Jev)


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    centre = p + z * z / (2 * n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((centre - half) / d, (centre + half) / d)


def sha256_file(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()[:16]


def git_sha():
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


def classify_scores(row, repeat):
    """Return list of malicious_scores (len repeat) + the modal attack_type."""
    scores, types = [], []
    for _ in range(repeat):
        v = classifier.classify_request(row)
        if v.get("error"):
            return None, v["error"]
        scores.append(v["malicious_score"])
        types.append(v["attack_type"])
    return (scores, max(set(types), key=types.count))


def parse_args():
    args = sys.argv[1:]
    repeat = 1
    if "--repeat" in args:
        i = args.index("--repeat")
        repeat = int(args[i + 1])
        del args[i:i + 2]
    return (args[0] if args else "eval_dataset.jsonl"), repeat


def main():
    if not classifier.API_KEY:
        sys.exit("set TYPESAFE_API_KEY first")
    dataset, repeat = parse_args()
    rows = [json.loads(l) for l in open(dataset) if l.strip()]
    thr = classifier.THRESHOLD

    print("=" * 64)
    print("RUN PROVENANCE (record this with any quoted number)")
    print(f"  dataset        : {dataset}  sha256:{sha256_file(dataset)}  n={len(rows)}")
    print(f"  git commit     : {git_sha()}")
    print(f"  model          : {classifier.MODEL}   endpoint: {classifier.JEV_URL if hasattr(classifier,'JEV_URL') else classifier.URL}")
    print(f"  threshold      : {thr}   repeat: {repeat}")
    print(f"  timestamp(UTC) : {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print(f"  python         : {platform.python_version()}")
    print("=" * 64 + "\n")

    results = []
    for r in rows:
        scores, info = classify_scores(r, repeat)
        if scores is None:
            print(f"  API error on {r['path']}: {info}")
            continue
        results.append({"row": r, "truth": r["label"] == "malicious",
                        "scores": scores, "mean": statistics.mean(scores),
                        "std": statistics.pstdev(scores) if len(scores) > 1 else 0.0,
                        "ptype": info, "regex": is_suspicious(r)})

    def pred(x, t=thr):
        return x["mean"] >= t

    TP = [x for x in results if x["truth"] and pred(x)]
    FP = [x for x in results if not x["truth"] and pred(x)]
    TN = [x for x in results if not x["truth"] and not pred(x)]
    FN = [x for x in results if x["truth"] and not pred(x)]
    tp, fp, tn, fn = len(TP), len(FP), len(TN), len(FN)

    print("CONFUSION MATRIX (positive = malicious)")
    print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}\n")

    prec, rec = (tp / (tp + fp) if tp + fp else 0), (tp / (tp + fn) if tp + fn else 0)
    pl, ph = wilson(tp, tp + fp)
    rl, rh = wilson(tp, tp + fn)
    print("METRICS  (95% Wilson CI — the honest interval at this N)")
    print(f"  Precision : {prec:.1%}   CI [{pl:.1%}, {ph:.1%}]")
    print(f"  Recall    : {rec:.1%}   CI [{rl:.1%}, {rh:.1%}]   <- note the LOWER bound")
    print(f"  N attacks={tp+fn}  N benign={fp+tn}   (balanced test set — NOT prod base rate)\n")

    # Variance / stability — the "ambiguous depending on run/context" cases
    if repeat > 1:
        unstable = [x for x in results
                    if min(x["scores"]) < thr <= max(x["scores"])]
        noisy = sorted(results, key=lambda x: -x["std"])[:5]
        print(f"RUN-TO-RUN VARIANCE (repeat={repeat})")
        print(f"  threshold-unstable cases (verdict flips across runs): {len(unstable)}")
        for x in unstable:
            print(f"    {x['row']['note']}: scores={[round(s,2) for s in x['scores']]}")
        print("  noisiest scores (highest std):")
        for x in noisy:
            print(f"    std={x['std']:.2f} mean={x['mean']:.2f}  {x['row']['note']}")
        print()

    if FP:
        print(f"FALSE POSITIVES ({fp}):")
        for x in FP:
            print(f"  mean={x['mean']:.2f} std={x['std']:.2f} as {x['ptype']:15} | "
                  f"{x['row']['note']}: {(x['row']['query'] or x['row']['body'])[:45]}")
    if FN:
        print(f"FALSE NEGATIVES ({fn}):")
        for x in FN:
            print(f"  mean={x['mean']:.2f} | {x['row']['type']} / {x['row']['note']} "
                  f"(regex_pregate={x['regex']})")
    if not FP and not FN:
        print("No FP/FN at this threshold (on this set).")
    print()

    # Label-leakage probe: is the verdict driven by the PAYLOAD or just the PATH?
    print("LABEL-LEAKAGE PROBE (does Jev read the payload, or cheat on the path?)")
    probes = [
        ("attack payload on NEUTRAL path", {"method": "GET", "path": "/search.php",
         "query": "q=1' UNION SELECT user,password FROM users", "body": "", "ip": "p"}),
        ("benign id on a VULN path", {"method": "GET", "path": "/vulnerabilities/sqli/",
         "query": "id=42", "body": "", "ip": "p"}),
    ]
    for label, p in probes:
        s, t = classify_scores(p, 1)
        print(f"  {label:34} -> score={s[0]:.2f} ({t})")
    print("  (want: attack scores HIGH off its usual path, benign LOW on a vuln path)\n")

    print("HOW TO READ THIS — scope conditions ARE the result:")
    print(f"  * {prec:.0%}/{rec:.0%} is on {len(rows)} AI-authored, AI-labeled, textbook cases,")
    print(f"    one dataset, {classifier.MODEL} on this date. NOT 'Jev is {prec:.0%} accurate.'")
    print("  * BASE-RATE TRAP: prod is ~99.9% benign. A 5% FP RATE on benign traffic")
    print("    means thousands of false blocks per million requests — production")
    print("    precision will be far below a balanced-set number.")
    print("  * Fix before trusting: larger set, INDEPENDENT labels (not mine), real")
    print("    traffic/attack corpora, and re-run on each model change (jev-latest moves).")

    # reproducibility dump
    os.makedirs("data/eval_runs", exist_ok=True)
    out = f"data/eval_runs/eval_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"
    json.dump({"dataset": dataset, "dataset_sha256": sha256_file(dataset),
               "git": git_sha(), "model": classifier.MODEL, "threshold": thr,
               "repeat": repeat, "precision": prec, "recall": rec,
               "precision_ci": [pl, ph], "recall_ci": [rl, rh],
               "rows": [{"note": x["row"]["note"], "truth": x["truth"],
                         "scores": x["scores"], "ptype": x["ptype"]} for x in results]},
              open(out, "w"), indent=2)
    print(f"\nraw per-sample results saved -> {out}  (reproducible evidence)")


if __name__ == "__main__":
    main()
