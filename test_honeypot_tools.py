"""Self-test for honeypot_tools. Redirects store's state file to a tempdir BEFORE
any divert call so the real data/state.json is never touched.
Run: .venv/bin/python test_honeypot_tools.py"""
import tempfile
from pathlib import Path

import store

tmp = Path(tempfile.mkdtemp())
store.DATA = tmp
store.STATE_FILE = tmp / "state.json"

import honeypot_tools as hp

IP = "10.1.2.3"

# idempotent: divert twice -> exactly one entry
hp.divert_to_honeypot(IP, "sqli confirmed")
hp.divert_to_honeypot(IP, "sqli confirmed")
st = store.load_state()
assert isinstance(st["honeypot"], list), "honeypot must be a list"
entries = [d for d in st["honeypot"] if d["ip"] == IP]
assert len(entries) == 1, f"expected 1 entry, got {len(entries)}"
assert set(entries[0]) == {"ip", "reason", "ts"}, f"bad keys: {entries[0]}"

# undivert removes it
hp.undivert(IP)
assert len(store.load_state()["honeypot"]) == 0, "undivert should remove the entry"

# dispatch wrapper returns a non-empty string, never raises
out = hp.do_divert_to_honeypot(IP, "xss")
assert isinstance(out, str) and out, "do_divert_to_honeypot must return a non-empty string"
assert isinstance(hp.do_undivert(IP), str), "do_undivert must return a string"

# REGISTER is a list of {"name","schema","fn"} dicts; names match their schemas
assert isinstance(hp.REGISTER, list), "REGISTER must be a list"
names = set()
for reg in hp.REGISTER:
    assert set(reg) == {"name", "schema", "fn"}, f"bad register entry keys: {reg}"
    assert reg["name"] == reg["schema"]["name"], f"name/schema mismatch: {reg}"
    assert callable(reg["fn"]), f"fn not callable: {reg}"
    names.add(reg["name"])
assert names == {"divert_to_honeypot", "undivert"}, f"unexpected tool names: {names}"

print("honeypot_tools test: ALL PASSED")
