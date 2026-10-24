"""Shared flat-file state: denylist + WAF rules (state.json), request log
(events.jsonl), incidents (incidents.jsonl). No DB — demo scale.
# ponytail: atomic replace + whole-file reads; swap for a real event store at volume."""
import json
import os
import threading
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
DATA.mkdir(exist_ok=True)

STATE_FILE = DATA / "state.json"
EVENTS_FILE = DATA / "events.jsonl"
INCIDENTS_FILE = DATA / "incidents.jsonl"
ACTIONS_FILE = DATA / "actions.jsonl"  # unified agent timeline: triage verdicts + tool actions

# Raw stdout/stderr from the container and the processes, tailed into the
# dashboard as a live console. run.sh redirects each stream into one of these.
LOGS = DATA / "logs"
LOGS.mkdir(exist_ok=True)
DVWA_LOG = LOGS / "dvwa.log"      # docker compose logs -f (DVWA + MailHog)
PROXY_LOG = LOGS / "proxy.log"    # the reverse proxy / uvicorn
BLUE_LOG = LOGS / "blue.log"      # the blue-team agent
RED_LOG = LOGS / "red.log"        # the red-team agent (when run via run.sh helper)

DEFAULT_STATE = {"denylist": [], "rules": [], "seen_ips": {}}
_lock = threading.Lock()


def load_state():
    try:
        return json.loads(STATE_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return json.loads(json.dumps(DEFAULT_STATE))  # fresh deep copy


def save_state(state):
    tmp = STATE_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2))
    os.replace(tmp, STATE_FILE)  # atomic — readers never see a partial file


def append_jsonl(path, obj):
    with _lock:
        with open(path, "a") as f:
            f.write(json.dumps(obj) + "\n")


def read_jsonl(path, limit=None):
    p = Path(path)
    if not p.exists():
        return []
    lines = p.read_text().splitlines()
    if limit:
        lines = lines[-limit:]
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            pass
    return out


def count_lines(path):
    p = Path(path)
    if not p.exists():
        return 0
    try:
        with open(p, "rb") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def tail_lines(path, n=120):
    p = Path(path)
    if not p.exists():
        return []
    try:
        return p.read_text(errors="ignore").splitlines()[-n:]
    except OSError:
        return []


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
