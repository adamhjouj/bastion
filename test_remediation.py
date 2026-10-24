"""Runnable check for remediation_tools (no network needed).
Run: .venv/bin/python test_remediation.py"""
import remediation_tools as rt

# level read-back parses DVWA's security.php "currently" line
html = "<p>Security Level is currently: <em>impossible</em>.</p>"
assert rt._read_level(html) == "impossible", rt._read_level(html)
assert rt._read_level("<em>low</em> Security Level is currently: <em>high</em>") == "high"
assert rt._read_level("no level here") is None

# invalid level is rejected before any network call
r = rt.patch_vuln("banana")
assert r["ok"] is False and "invalid level" in r["error"], r

# tool schema + dispatch wiring shape is intact for blue_agent registration
assert rt.PATCH_VULN_TOOL["name"] == "patch_vuln"
assert rt.PATCH_VULN_TOOL["input_schema"]["properties"]["level"]["enum"] == list(rt.LEVELS)
assert rt.REGISTER["fn"] is rt.do_patch_vuln

# dispatch wrapper turns a failed patch into a readable string, never raises
msg = rt.do_patch_vuln("banana")
assert "failed" in msg, msg

# enforced_security contract (pure): raising records the level for the proxy to
# pin; 'low' is the vulnerable baseline so it CLEARS enforcement (reset).
assert rt._apply_enforcement({}, "impossible")["enforced_security"] == "impossible"
assert rt._apply_enforcement({"denylist": []}, "high")["enforced_security"] == "high"
assert "enforced_security" not in rt._apply_enforcement({"enforced_security": "high"}, "low")

print("remediation test: ALL PASSED")
