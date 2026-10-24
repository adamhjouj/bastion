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


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
