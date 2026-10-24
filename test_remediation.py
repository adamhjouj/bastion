"""Remediation: level parsing, invalid input, enforcement state contract."""
import remediation_tools as rt


def test_level_parse():
    assert rt._read_level("<em>impossible</em> Security Level is currently: <em>high</em>") == "high"
    assert rt._read_level("Security Level is currently: <em>low</em>") == "low"
    assert rt._read_level("no level here") is None


def test_invalid_level_rejected():
    r = rt.patch_vuln("banana")
    assert not r["ok"] and "invalid level" in r["error"]


def test_enforcement_recorded_on_raise():
    state = {}
    rt._apply_enforcement(state, "impossible")
    assert state["enforced_security"] == "impossible"


def test_enforcement_cleared_on_low():
    state = {"enforced_security": "high"}
    rt._apply_enforcement(state, "low")
    assert "enforced_security" not in state


def test_do_patch_vuln_error_string():
    msg = rt.do_patch_vuln("banana")
    assert msg.startswith("ERROR:")


def test_tool_schema_shape():
    assert rt.PATCH_VULN_TOOL["name"] == "patch_vuln"
    assert rt.REGISTER["fn"] is rt.do_patch_vuln
    assert set(rt.REGISTER) == {"name", "schema", "fn"}


def test_levels_complete():
    assert set(rt.LEVELS) == {"low", "medium", "high", "impossible"}
