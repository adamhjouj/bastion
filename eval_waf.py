"""Measure the Jev WAF's false positives / false negatives against a labeled set.

Runs each labeled request through the real Jev classifier, compares to ground
truth, and prints a confusion matrix, precision/recall/F1, per-type accuracy,
the actual FP/FN cases, and a threshold sweep (so you can tune MALICIOUS_THRESHOLD
without re-calling the API).

Usage:  TYPESAFE_API_KEY=... .venv/bin/python eval_waf.py [eval_dataset.jsonl]
"""
import json
import sys

import classifier
from blue_agent import is_suspicious  # the regex pre-gate (what reaches Jev in the pipeline)

DATASET = sys.argv[1] if len(sys.argv) > 1 else "eval_dataset.jsonl"


def load(path):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def main():
    if not classifier.API_KEY:
        sys.exit("set TYPESAFE_API_KEY first")
    rows = load(DATASET)
    print(f"Evaluating {len(rows)} labeled requests against Jev "
          f"(model={classifier.MODEL}, threshold={classifier.THRESHOLD})\n")

    results = []
    for r in rows:
        truth_mal = r["label"] == "malicious"
        v = classifier.classify_request(r)
        if v.get("error"):
            print(f"  API error on {r['path']}: {v['error']}")
            score, ptype = None, None
        else:
            score, ptype = v["malicious_score"], v["attack_type"]
        results.append({"row": r, "truth": truth_mal, "score": score, "ptype": ptype,
                        "regex": is_suspicious(r)})

    scored = [x for x in results if x["score"] is not None]
    thr = classifier.THRESHOLD

    def pred(x, t=thr):
        return x["score"] >= t

    TP = [x for x in scored if x["truth"] and pred(x)]
    FP = [x for x in scored if not x["truth"] and pred(x)]
    TN = [x for x in scored if not x["truth"] and not pred(x)]
    FN = [x for x in scored if x["truth"] and not pred(x)]
    tp, fp, tn, fn = len(TP), len(FP), len(TN), len(FN)

    def rate(n, d):
        return f"{n/d:.1%}" if d else "n/a"

    print("CONFUSION MATRIX (positive = malicious)")
    print(f"                 pred malicious   pred benign")
    print(f"  actual mal   |      {tp:>3} (TP)      {fn:>3} (FN)")
    print(f"  actual benign|      {fp:>3} (FP)      {tn:>3} (TN)\n")

    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    print("METRICS")
    print(f"  Precision (of flagged, how many real) : {prec:.1%}")
    print(f"  Recall    (of attacks, how many caught): {rec:.1%}")
    print(f"  F1                                     : {f1:.2f}")
    print(f"  Accuracy                               : {rate(tp+tn, tp+fp+tn+fn)}")
    print(f"  False-positive rate (benign flagged)   : {rate(fp, fp+tn)}")
    print(f"  False-negative rate (attacks missed)   : {rate(fn, fn+tp)}\n")

    # attack-type accuracy among correctly-detected attacks
    typed = [x for x in TP if x["row"].get("type") not in (None, "benign")]
    type_ok = [x for x in typed if x["ptype"] == x["row"]["type"]]
    print(f"ATTACK-TYPE ACCURACY (among {len(typed)} detected attacks): "
          f"{rate(len(type_ok), len(typed))}")
    for x in typed:
        if x["ptype"] != x["row"]["type"]:
            print(f"  mis-typed: {x['row']['type']} -> {x['ptype']}  ({x['row']['note']})")
    print()

    if FP:
        print(f"FALSE POSITIVES ({fp}) — benign flagged as attack:")
        for x in FP:
            r = x["row"]
            print(f"  score={x['score']:.2f} as {x['ptype']:16} | {r['note']}: "
                  f"{(r['query'] or r['body'])[:50]}")
    else:
        print("FALSE POSITIVES: none")
    print()
    if FN:
        print(f"FALSE NEGATIVES ({fn}) — attacks missed:")
        for x in FN:
            r = x["row"]
            print(f"  score={x['score']:.2f} | {r['type']} / {r['note']}: "
                  f"{(r['query'] or r['body'])[:50]}  (regex_pregate={x['regex']})")
    else:
        print("FALSE NEGATIVES: none")
    print()

    # pipeline note: in default mode the regex pre-gate runs BEFORE Jev, so a
    # malicious request the regex doesn't flag never reaches Jev (pipeline FN).
    missed_by_regex = [x for x in scored if x["truth"] and not x["regex"]]
    print(f"PIPELINE NOTE: {len(missed_by_regex)} attack(s) would NOT reach Jev under the "
          f"default regex pre-gate (USE_REGEX_PREGATE=1) — set it to 0 to send all "
          f"traffic to Jev.")
    for x in missed_by_regex:
        print(f"  regex-missed: {x['row']['type']} / {x['row']['note']}")
    print()

    print("THRESHOLD SWEEP (reuses stored scores — no extra API calls)")
    print("  thr   FP   FN   precision   recall")
    for t in (0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9):
        p = [x for x in scored if pred(x, t)]
        tpi = sum(1 for x in p if x["truth"]); fpi = sum(1 for x in p if not x["truth"])
        fni = sum(1 for x in scored if x["truth"] and not pred(x, t))
        pr = tpi / (tpi + fpi) if tpi + fpi else 0
        rc = tpi / (tpi + fni) if tpi + fni else 0
        print(f"  {t:.1f}   {fpi:>2}   {fni:>2}     {pr:>6.1%}    {rc:>6.1%}")


if __name__ == "__main__":
    main()
