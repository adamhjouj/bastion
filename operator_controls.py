"""Operator-initiated demo controls: reset the board and launch allow-listed attack runs.

Security model, identical in spirit to the actuator: every command is a FIXED argv chosen
from the registry below. No value from an HTTP request is ever interpolated into a command;
a request only selects a job key. The one per-run value we inject, a fresh attacker IP, is
generated here, never supplied by the caller. All callers already sit behind the proxy's
MANAGEMENT_TOKEN boundary (every /__ path is authenticated). This is a local-lab control
plane for the demo, not a production feature.
"""
import hashlib
import ipaddress
import json
import os
import random
import subprocess
import sys
import threading
import time
from pathlib import Path

import log_store
import store

ROOT = Path(__file__).resolve().parent

# Fixed command registry. `attacker_ip: True` means a fresh documentation-range IP is
# generated per run (so repeated demos start from a clean, un-banned source). `needs`
# marks a prerequisite the run cannot satisfy on its own.
JOBS = {
    "attack-sqli": {"label": "SQL injection attack", "argv": [sys.executable, "-u", "red_agent.py", "sqli"],
                    "source": "red", "timeout": 240, "attacker_ip": True, "needs": "llm"},
    "attack-cmdi": {"label": "Command injection attack", "argv": [sys.executable, "-u", "red_agent.py", "cmdi"],
                    "source": "red", "timeout": 240, "attacker_ip": True, "needs": "llm"},
    "attack-lfi": {"label": "Path traversal attack", "argv": [sys.executable, "-u", "red_agent.py", "lfi"],
                   "source": "red", "timeout": 240, "attacker_ip": True, "needs": "llm"},
    "attack-xss": {"label": "Reflected XSS attack", "argv": [sys.executable, "-u", "red_agent.py", "xss"],
                   "source": "red", "timeout": 240, "attacker_ip": True, "needs": "llm"},
}


class Busy(Exception):
    """Another job is already running."""


class Unknown(Exception):
    """No such job key."""


class Unavailable(Exception):
    """A prerequisite (e.g. an LLM key) is missing."""


_lock = threading.RLock()   # reentrant: snapshot() may be called while the lock is held
_current = None   # {"job","label","started","proc","stopped","attacker_ip"} while running
_last = None      # {"job","label","status","finished","attacker_ip"} after a run
_occ = 0          # monotonic log occurrence; keeps otherwise-identical lines distinct


def _have_llm():
    return bool(os.getenv("DEEPSEEK_API_KEY") or os.getenv("ANTHROPIC_API_KEY"))


def _emit(source, text):
    """Append one synthetic console line to a real log source (redacted on the way in)."""
    global _occ
    _occ += 1
    try:
        log_store.append(source, [{"container_id": "operator", "ts": store.now(), "stream": "stdout",
                                    "text": text, "digest": hashlib.sha256(text.encode()).hexdigest(),
                                    "occurrence": _occ, "truncated": False}])
    except Exception:
        pass  # a logging failure must never take down the job


def _random_attacker_ip():
    # TEST-NET-3 (203.0.113.0/24), reserved for documentation; safe, routable-looking, disjoint
    # from the benign TEST-NET-2 pool the eval harness uses.
    return "203.0.113." + str(random.randint(2, 254))


def _pump(job, proc):
    """Read the child's output into its console source, then finalize status."""
    global _current, _last
    for raw in proc.stdout:
        _emit(job["source"], raw.rstrip("\n"))
    proc.wait()
    with _lock:
        stopped = bool(_current and _current.get("stopped"))
        attacker_ip = _current.get("attacker_ip") if _current else None
        status = "stopped" if stopped else ("ok" if proc.returncode == 0 else "error")
        _emit(job["source"], f"[operator] {job['label']} {status} (exit {proc.returncode})")
        _last = {"job": _current["job"] if _current else None, "label": job["label"],
                 "status": status, "finished": store.now(), "attacker_ip": attacker_ip}
        _current = None


def _deadline(proc, timeout):
    """Terminate a run that overstays its timeout."""
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return
        time.sleep(0.5)
    _terminate(proc)


def _terminate(proc):
    try:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
    except Exception:
        pass


def start(job_key):
    """Launch a job by key. Raises Busy / Unknown / Unavailable."""
    job = JOBS.get(job_key)
    if job is None:
        raise Unknown(job_key)
    if job.get("needs") == "llm" and not _have_llm():
        raise Unavailable("agent mode needs an LLM key (DEEPSEEK_API_KEY or ANTHROPIC_API_KEY)")
    global _current
    with _lock:
        if _current is not None:
            raise Busy(f"{_current['label']} is already running")
        env = dict(os.environ, PROXY_URL="http://localhost:8080")
        attacker_ip = None
        if job.get("attacker_ip"):
            attacker_ip = _random_attacker_ip()
            env["ATTACKER_IP"] = attacker_ip
        # argv is fixed from the registry; env carries only generated/internal values.
        proc = subprocess.Popen(job["argv"], cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
        _current = {"job": job_key, "label": job["label"], "started": store.now(),
                    "proc": proc, "stopped": False, "attacker_ip": attacker_ip}
    _emit(job["source"], f"[operator] started {job['label']}"
                         + (f" from {attacker_ip}" if attacker_ip else ""))
    threading.Thread(target=_pump, args=(job, proc), daemon=True).start()
    threading.Thread(target=_deadline, args=(proc, job["timeout"]), daemon=True).start()
    return snapshot()


def stop():
    """Stop the running job, if any."""
    with _lock:
        cur = _current
        if cur is None:
            return snapshot()
        cur["stopped"] = True
        proc = cur["proc"]
    _terminate(proc)
    return snapshot()


def _restore_target():
    """Ask the actuator (the only side with the Docker socket) to put the target back to its
    exploitable default. Never raises: a failure is reported, and the board is still cleared."""
    token = os.getenv("ACTUATOR_TOKEN", "")
    if len(token) < 32:
        return {"ok": False, "error": "actuator credential unavailable"}
    try:
        import httpx
        r = httpx.post(os.getenv("ACTUATOR_URL", "http://actuator:9010") + "/lab/restore",
                       headers={"Authorization": f"Bearer {token}"}, timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        return {"ok": False, "error": f"actuator unavailable ({type(exc).__name__})"}


def reset():
    """Fully reset the lab. The target is restored first (unfrozen, egress reconnected, app
    level back to medium), then the board is cleared: all requests, actions, incidents, logs,
    queued mail, and live defenses (bans, honeypot diversions, virtual patches). Component
    health is left untouched."""
    target = _restore_target()
    with store.connection(write=True) as db:
        cleared = {k: db.execute("SELECT COUNT(*) FROM records WHERE kind=?", (k,)).fetchone()[0]
                   for k in ("events", "actions", "incidents")}
        cleared["logs"] = db.execute("SELECT COUNT(*) FROM service_logs").fetchone()[0]
        db.execute("DELETE FROM records")
        db.execute("DELETE FROM service_logs")
        db.execute("DELETE FROM outbox")
        db.execute("DELETE FROM mail_receipts")
        db.execute("DELETE FROM budgets")
        db.execute("UPDATE state SET data=? WHERE id=1", (json.dumps(store.DEFAULT_STATE),))
    # One audit line so the cleared board still shows that an operator reset it.
    store.append_jsonl(store.ACTIONS_FILE, {"ts": store.now(), "kind": "action", "tool": "operator_reset",
                                            "input": {}, "outcome": "ok" if target.get("ok") else "error",
                                            "result": "Board reset: "
                                            + ", ".join(f"{v} {k}" for k, v in cleared.items())
                                            + ("; target restored to " + str(target.get("level")) if target.get("ok")
                                               else "; target NOT restored: " + str(target.get("error") or target.get("steps")))})
    return {"cleared": cleared, "target": target}


def snapshot():
    """Current control state for the dashboard: what is running and what can be run."""
    with _lock:
        running = _current is not None
        current = None if not running else {"job": _current["job"], "label": _current["label"],
                                            "started": _current["started"], "attacker_ip": _current["attacker_ip"]}
        last = dict(_last) if _last else None
    llm = _have_llm()
    jobs = [{"id": k, "label": j["label"], "available": llm if j.get("needs") == "llm" else True,
             "needs": j.get("needs")} for k, j in JOBS.items()]
    return {"running": running, "current": current, "last": last, "jobs": jobs, "llm": llm}
