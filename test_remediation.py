"""Remediation: level validation, enforcement state, and the instance.php patch path."""
import actuator
import remediation_tools as rt
import store


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


def test_set_level_php_inlines_validated_level():
    # level is injected as a literal; it must be a validated enum value (see patch_vuln).
    php = rt._set_level_php("impossible")
    assert "$c['level'] = 'impossible';" in php and "instance.php" in php


def test_patch_vuln_success(monkeypatch):
    """Happy path without Docker: resolve -> set-level exec -> read-back -> verified,
    and the pinned level is recorded in shared state for the SOC view."""
    monkeypatch.setattr(actuator, "_resolve", lambda t: "cid123")
    monkeypatch.setattr(actuator, "_docker", lambda *a: (0, "impossible", ""))
    r = rt.patch_vuln("impossible")
    assert r["ok"] and r["verified"] and r["level"] == "impossible"
    assert store.load_state().get("enforced_security") == "impossible"


def test_patch_vuln_exec_failure(monkeypatch):
    monkeypatch.setattr(actuator, "_resolve", lambda t: "cid")
    monkeypatch.setattr(actuator, "_docker", lambda *a: (1, "", "boom"))
    r = rt.patch_vuln("impossible")
    assert not r["ok"] and "boom" in r["error"]


def test_patch_vuln_readback_mismatch_unverified(monkeypatch):
    """set-level succeeds but read-back returns a different level -> not verified."""
    monkeypatch.setattr(actuator, "_resolve", lambda t: "cid")
    seq = iter([(0, "impossible", ""), (0, "medium", "")])
    monkeypatch.setattr(actuator, "_docker", lambda *a: next(seq))
    r = rt.patch_vuln("impossible")
    assert not r["ok"] and not r["verified"] and r["level"] == "medium"
