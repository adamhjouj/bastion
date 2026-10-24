"""Privileged action layer for the blue-team agent — the agent's "hands inside
the infrastructure" that a WAF structurally lacks (session kill, egress cut,
process kill, quarantine), WITHOUT giving the LLM a shell.

Safety model (this is the whole point of the file):
  * The LLM never emits a command string. It calls a named tool with scalar
    params; this module maps each tool to ONE fixed, arg-list subprocess call.
    No shell=True, ever — the model's input can never become a command.
  * Every target is a LOGICAL service name validated against ALLOWED_TARGETS
    ({"dvwa"}). The agent cannot act on the proxy, on itself, on MailHog, or on
    any container outside this compose project. This is the hard boundary.
  * kill_process can only kill a PID that is (a) a positive int, (b) currently
    running in the target, and (c) NOT in the boot-time baseline. So apache /
    mysqld / init are structurally unkillable — only attacker-spawned procs die.
  * Session ids / network names are charset-validated before they touch a path.
  * run_tool() never raises into the agent loop; it returns a string and audits
    every attempt (ok / rejected / error) to data/actions.jsonl.

Integration (no edits to blue_agent.py needed — avoids colliding with other
sessions):  `import actuator; actuator.register(TOOLS, DISPATCH)` adds the
tools + handlers to the existing Claude tool-use loop in one line.

# ponytail: uses the `docker` CLI over the socket (no new dep vs the docker SDK).
# Reaching Docker requires /var/run/docker.sock mounted into the blue container
# (a one-line compose change, owned by the infra session). docker.sock == host
# root — acceptable on a local demo box; split into an actuator sidecar if this
# ever leaves the demo so the LLM container holds no socket.
"""
import os
import re
import subprocess
import sys

import store

PROJECT = os.environ.get("BASTION_PROJECT", "breach-agent")
ALLOWED_TARGETS = set(
    t.strip() for t in os.environ.get("BASTION_TARGETS", "dvwa").split(",") if t.strip()
)
SESS_DIR = os.environ.get("DVWA_SESSION_DIR", "/var/lib/php/sessions")
DOCKER = os.environ.get("DOCKER_BIN", "docker")
ACTIONS_FILE = store.DATA / "actions.jsonl"

_SESSION_ID = re.compile(r"[A-Za-z0-9,._-]{1,128}")   # php session id charset
_NET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")

_BASELINE = {}   # target -> frozenset(pid) captured at boot (before any attack)


class Rejected(Exception):
    """A validation/safety refusal — distinct from an execution error."""


# ---- subprocess boundary (the only place a command runs) -------------------

def _runner(args):
    """Run an argv list; return (rc, stdout, stderr). Swappable in tests."""
    try:
        p = subprocess.run([DOCKER, *args], capture_output=True, text=True, timeout=20)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "docker CLI not found (socket not mounted?)"
    except subprocess.TimeoutExpired:
        return 124, "", "docker command timed out"


_RUNNER = _runner   # tests replace this


def _docker(*args):
    return _RUNNER(list(args))


# ---- validation helpers ----------------------------------------------------

def _resolve(target):
    """Logical service name -> running container id, gated by ALLOWED_TARGETS."""
    if target not in ALLOWED_TARGETS:
        raise Rejected(f"target {target!r} not allowed (allowed: {sorted(ALLOWED_TARGETS)})")
    rc, out, err = _docker(
        "ps", "-q",
        "--filter", f"label=com.docker.compose.project={PROJECT}",
        "--filter", f"label=com.docker.compose.service={target}",
    )
    if rc != 0:
        raise Rejected(f"docker ps failed: {err.strip() or rc}")
    ids = out.split()
    if not ids:
        raise Rejected(f"no running container for service {target!r}")
    return ids[0]


def _pos_int(v):
    if isinstance(v, bool) or not isinstance(v, (int, str)):
        raise Rejected(f"pid must be an integer, got {v!r}")
    s = str(v)
    if not s.isdigit() or int(s) <= 0:
        raise Rejected(f"pid must be a positive integer, got {v!r}")
    return int(s)


def _pids(cid):
    """[(pid:int, cmd:str)] for the container. Parses `docker top` (cols:
    UID PID PPID C STIME TTY TIME CMD; CMD may contain spaces)."""
    rc, out, err = _docker("top", cid)
    if rc != 0:
        raise Rejected(f"docker top failed: {err.strip() or rc}")
    lines = out.splitlines()
    if not lines:
        return []
    hdr = lines[0].split()
    try:
        pi, ci = hdr.index("PID"), hdr.index("CMD")
    except ValueError:
        pi, ci = 1, len(hdr) - 1
    rows = []
    for ln in lines[1:]:
        cols = ln.split(None, len(hdr) - 1)
        if len(cols) <= max(pi, ci) or not cols[pi].isdigit():
            continue
        rows.append((int(cols[pi]), cols[ci]))
    return rows


def _nets(cid):
    rc, out, _ = _docker(
        "inspect", "-f",
        "{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}", cid)
    return set(out.split()) if rc == 0 else set()


def capture_baseline():
    """Snapshot each target's process set. Called at import (= agent boot) so
    the attacker's later processes are NOT in the baseline and stay killable."""
    for t in ALLOWED_TARGETS:
        try:
            _BASELINE[t] = frozenset(p for p, _ in _pids(_resolve(t)))
        except Exception:
            pass  # docker not reachable yet (e.g. socket not mounted) — skip


# ---- actions (grounding reads first, then the privileged verbs) ------------

def list_processes(target):
    procs = _pids(_resolve(target))
    base = _BASELINE.get(target, frozenset())
    lines = [f"pid={p} {'[baseline]' if p in base else '[NEW]'} {cmd}" for p, cmd in procs]
    return "processes in {}:\n{}".format(target, "\n".join(lines) or "(none)")


def list_sessions(target):
    cid = _resolve(target)
    rc, out, err = _docker("exec", cid, "sh", "-c", f"ls -1 {SESS_DIR} 2>/dev/null")
    if rc != 0:
        raise Rejected(f"could not list sessions: {err.strip() or rc}")
    ids = [ln[5:] for ln in out.split() if ln.startswith("sess_")]
    return "active sessions in {}: {}".format(target, ", ".join(ids) or "(none)")


def kill_process(target, pid):
    cid = _resolve(target)
    pid = _pos_int(pid)
    base = _BASELINE.get(target)
    if base is None:
        raise Rejected("no boot baseline captured — refusing to kill (cannot tell "
                       "attacker procs from system procs)")
    live = {p for p, _ in _pids(cid)}
    if pid not in live:
        raise Rejected(f"pid {pid} not running in {target}")
    if pid in base:
        raise Rejected(f"pid {pid} is a baseline/system process — protected")
    rc, _, err = _docker("exec", cid, "kill", "-9", str(pid))
    if rc != 0:
        raise Rejected(f"kill failed: {err.strip() or rc}")
    return f"killed non-baseline pid {pid} in {target}"


def kill_session(target, session_id):
    cid = _resolve(target)
    if not _SESSION_ID.fullmatch(str(session_id)):
        raise Rejected(f"invalid session id {session_id!r}")
    rc, _, err = _docker("exec", cid, "rm", "-f", f"{SESS_DIR}/sess_{session_id}")
    if rc != 0:
        raise Rejected(f"could not remove session: {err.strip() or rc}")
    return f"invalidated session {session_id} in {target} (attacker force-logged-out)"


def isolate_egress(target):
    """Disconnect the target from every network it does NOT share with the proxy,
    so proxy<->app survives but the app loses outbound (C2 / exfil / 2nd stage)."""
    cid = _resolve(target)
    keep = set()
    rc, out, _ = _docker(
        "ps", "-q", "--filter", f"label=com.docker.compose.project={PROJECT}",
        "--filter", "label=com.docker.compose.service=proxy")
    if rc == 0 and out.split():
        keep = _nets(out.split()[0])
    drop = _nets(cid) - keep
    if not drop:
        return ("no separate egress network to cut — app shares its only network "
                "with the proxy. Add a second (egress) network in compose to enable "
                "true egress lockdown. # ponytail: single-net demo topology")
    done = []
    for n in drop:
        if not _NET_NAME.fullmatch(n):
            continue
        rc, _, err = _docker("network", "disconnect", n, cid)
        done.append(n if rc == 0 else f"{n}(failed:{err.strip() or rc})")
    return f"egress isolated: disconnected {target} from {', '.join(done)}"


def quarantine_container(target):
    cid = _resolve(target)
    rc, _, err = _docker("pause", cid)
    if rc != 0:
        raise Rejected(f"pause failed: {err.strip() or rc}")
    return f"{target} quarantined (paused — all processes frozen in place)"


def release_container(target):
    cid = _resolve(target)
    rc, _, err = _docker("unpause", cid)
    if rc != 0:
        raise Rejected(f"unpause failed: {err.strip() or rc}")
    return f"{target} released (unpaused)"


# ---- tool registry (Anthropic tool-use schemas) ----------------------------

_T = {"type": "object", "properties": {"target": {"type": "string",
      "description": "logical service name; only 'dvwa' is permitted"}},
      "required": ["target"]}

CONTROL_TOOLS = [
    {"name": "list_processes", "description":
     "List processes in the target container, each marked [baseline] (present at "
     "boot, protected) or [NEW] (spawned since — a possible attacker process). "
     "Use this to GROUND a kill_process call on a real pid.", "input_schema": _T},
    {"name": "list_sessions", "description":
     "List active application session ids in the target. Use to ground kill_session.",
     "input_schema": _T},
    {"name": "kill_process", "description":
     "Kill ONE attacker-spawned process (e.g. a reverse shell from RCE). Only a "
     "live, non-baseline pid can be killed; system processes are refused.",
     "input_schema": {"type": "object", "properties": {
         "target": _T["properties"]["target"],
         "pid": {"type": "integer", "description": "pid from list_processes marked [NEW]"}},
         "required": ["target", "pid"]}},
    {"name": "kill_session", "description":
     "Invalidate the attacker's application session server-side (force-logout). "
     "Beats an authenticated or agentic attacker even if it rotates IP.",
     "input_schema": {"type": "object", "properties": {
         "target": _T["properties"]["target"],
         "session_id": {"type": "string", "description": "id from list_sessions"}},
         "required": ["target", "session_id"]}},
    {"name": "isolate_egress", "description":
     "Cut the target's outbound network (stops C2 callbacks, data exfil, pulling "
     "a 2nd-stage payload) while keeping it reachable through the proxy.",
     "input_schema": _T},
    {"name": "quarantine_container", "description":
     "Freeze the whole target container (docker pause). Nuclear containment — the "
     "attacker loses the target entirely. Reversible with release_container.",
     "input_schema": _T},
    {"name": "release_container", "description":
     "Un-freeze a quarantined container (docker unpause).", "input_schema": _T},
]

CONTROL_DISPATCH = {
    "list_processes": list_processes, "list_sessions": list_sessions,
    "kill_process": kill_process, "kill_session": kill_session,
    "isolate_egress": isolate_egress, "quarantine_container": quarantine_container,
    "release_container": release_container,
}


def run_tool(name, params):
    """Validate + execute one control tool. NEVER raises — returns a string and
    audits the attempt. This is what the agent loop calls."""
    params = params or {}
    if name not in CONTROL_DISPATCH:
        return f"ERROR: unknown control tool {name!r}"
    try:
        out = CONTROL_DISPATCH[name](**params)
        _audit(name, params, "ok", out)
        return out
    except Rejected as e:
        _audit(name, params, "rejected", str(e))
        return f"REJECTED: {e}"
    except Exception as e:  # noqa: BLE001 — a tool must never kill the loop
        _audit(name, params, "error", str(e))
        return f"ERROR: {e}"


def _audit(name, params, outcome, detail):
    try:
        store.append_jsonl(ACTIONS_FILE, {"ts": store.now(), "tool": name,
                           "params": params, "outcome": outcome, "detail": detail})
    except Exception:
        pass


def register(tools, dispatch):
    """One-line integration into blue_agent's existing loop: extend its TOOLS and
    route each handler through run_tool so it can never raise into the loop."""
    tools.extend(CONTROL_TOOLS)
    for t in CONTROL_TOOLS:
        dispatch[t["name"]] = (lambda _n=t["name"], **p: run_tool(_n, p))
    return tools, dispatch


# blue_agent exposes a generic hook: a list of {"name","schema","fn"} it folds
# into TOOLS/DISPATCH. Expose our control tools in that exact shape; fn is routed
# through run_tool so a tool can never raise into the agent loop.
REGISTER = [{"name": t["name"], "schema": t,
             "fn": (lambda _n=t["name"], **p: run_tool(_n, p))} for t in CONTROL_TOOLS]


# best-effort baseline at import == at agent boot (guarded: never breaks import)
try:
    capture_baseline()
except Exception:  # noqa: BLE001
    pass


# ---- self-test (no real containers touched) --------------------------------

def _selftest():
    global _RUNNER
    fake = {"pids": [100, 101, 102]}  # baseline set

    def runner(args):
        a = " ".join(args)
        if args[0] == "ps":
            return (0, "fakecid\n", "") if "service=dvwa" in a or "service=proxy" in a else (0, "", "")
        if args[0] == "top":
            tbl = "UID PID PPID C STIME TTY TIME CMD\n" + "".join(
                f"root {p} 1 0 00:00 ? 00:00:00 proc{p}\n" for p in fake["pids"])
            return (0, tbl, "")
        if args[0] == "inspect":
            return (0, "breach-agent_default \n", "")
        if args[0] == "exec" and "ls" in a:
            return (0, "sess_abc\nsess_def\n", "")
        if args[0] in ("exec", "pause", "unpause", "network"):
            return (0, "", "")
        return (0, "", "")

    _RUNNER = runner
    _BASELINE.clear()
    capture_baseline()
    assert _BASELINE["dvwa"] == frozenset({100, 101, 102}), _BASELINE

    # target boundary: the agent cannot touch the proxy or itself
    assert run_tool("quarantine_container", {"target": "proxy"}).startswith("REJECTED")
    assert run_tool("quarantine_container", {"target": "blue"}).startswith("REJECTED")
    assert run_tool("quarantine_container", {"target": "dvwa"}).startswith("dvwa quarantined")

    # kill: attacker spawns pid 1234 AFTER baseline
    fake["pids"] = [100, 101, 102, 1234]
    assert run_tool("kill_process", {"target": "dvwa", "pid": 100}).startswith("REJECTED")   # baseline
    assert run_tool("kill_process", {"target": "dvwa", "pid": 777}).startswith("REJECTED")   # not live
    assert "notint" and run_tool("kill_process", {"target": "dvwa", "pid": "x"}).startswith("REJECTED")
    assert run_tool("kill_process", {"target": "dvwa", "pid": 1234}).startswith("killed")    # happy path

    # session id must be charset-clean (no path traversal)
    assert run_tool("kill_session", {"target": "dvwa", "session_id": "../../etc/passwd"}).startswith("REJECTED")
    assert run_tool("kill_session", {"target": "dvwa", "session_id": "abc"}).startswith("invalidated")

    # unknown tool and bad kwargs never raise
    assert run_tool("bogus", {}).startswith("ERROR")
    assert run_tool("kill_process", {"target": "dvwa", "oops": 1}).startswith("ERROR")

    # register() wires into a plain tools/dispatch pair and routes safely
    tools, disp = [], {}
    register(tools, disp)
    assert len(tools) == len(CONTROL_TOOLS) and "kill_process" in disp
    assert disp["quarantine_container"](target="proxy").startswith("REJECTED")

    # REGISTER export matches blue_agent's {name,schema,fn} hook shape
    assert {r["name"] for r in REGISTER} == set(CONTROL_DISPATCH)
    assert all(set(r) == {"name", "schema", "fn"} for r in REGISTER)
    assert next(r for r in REGISTER if r["name"] == "kill_session")["fn"](
        target="proxy", session_id="x").startswith("REJECTED")

    print("actuator self-test: ALL PASSED")


if __name__ == "__main__":
    if "--probe" in sys.argv:  # live read-only peek at the real dvwa container
        print(list_processes("dvwa"))
        print(list_sessions("dvwa"))
    else:
        _selftest()
