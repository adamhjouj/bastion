"""Privileged action layer for the blue-team agent — the agent's "hands inside
the infrastructure" that a WAF structurally lacks (session kill, egress cut,
process kill, quarantine), WITHOUT giving the LLM a shell.

Safety model (this is the whole point of the file):
  * The LLM never emits a command string. It calls a named tool with scalar
    params; this module maps each tool to ONE fixed, arg-list subprocess call.
    No shell=True, ever — the model's input can never become a command.
  * Every target is a LOGICAL service name validated against ALLOWED_TARGETS
    ({"dvwa"}). The agent cannot act on the proxy, on itself, on the mail worker, or on
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
import secrets
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
_DB_USER_RE = re.compile(r"db_user'\s*\]\s*=\s*'([^']+)'")      # DVWA config.inc.php
_DB_PASS_RE = re.compile(r"db_password'\s*\]\s*=\s*'([^']*)'")
_DB_IDENT = re.compile(r"[A-Za-z0-9_]{1,32}")                   # db usernames we'll touch

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
    if len(ids) != 1:
        raise Rejected(f"expected exactly one running container for service {target!r}, found {len(ids)}")
    return ids[0]


def _pos_int(v):
    if isinstance(v, bool) or not isinstance(v, (int, str)):
        raise Rejected(f"pid must be an integer, got {v!r}")
    s = str(v)
    if not s.isdigit() or int(s) <= 0:
        raise Rejected(f"pid must be a positive integer, got {v!r}")
    return int(s)


def _pids(cid):
    """[(pid:int, cmd:str)] for the container, read from INSIDE the container's
    PID namespace. Must match the namespace `docker exec kill` acts in — `docker
    top` reports HOST pids (different numbers under a VM/rosetta), so killing a
    top-reported pid fails or hits the wrong in-container process. `ps -eo
    pid=,args=` suppresses the header; busybox (no -eo) falls back to plain ps."""
    rc, out, err = _docker("exec", cid, "ps", "-eo", "pid=,args=")
    if rc != 0:
        rc, out, err = _docker("exec", cid, "ps")  # busybox fallback
        if rc != 0:
            raise Rejected(f"ps in {cid} failed: {err.strip() or rc}")
    rows = []
    for ln in out.splitlines():
        parts = ln.split(None, 1)
        if not parts or not parts[0].isdigit():  # skips any header / blank line
            continue
        rows.append((int(parts[0]), parts[1].strip() if len(parts) > 1 else ""))
    return rows


def _nets(cid):
    rc, out, _ = _docker(
        "inspect", "-f",
        "{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}", cid)
    return set(out.split()) if rc == 0 else set()


def _identity(cid, pid):
    rc, out, _ = _docker("exec", cid, "cat", f"/proc/{pid}/stat")
    try:
        # comm can contain spaces/parentheses; fields after its final ')' start at state.
        start = out.rsplit(")", 1)[1].split()[19]
        if rc or not start.isdigit():
            raise ValueError()
        return (cid, pid, start)
    except (IndexError, ValueError):
        raise Rejected("cannot establish process identity")


def capture_baseline():
    """Explicit startup snapshot. Container IDs and start times prevent PID-reuse trust."""
    for target in ALLOWED_TARGETS:
        cid = _resolve(target)
        identities = []
        for pid, _ in _pids(cid):
            try:
                identities.append(_identity(cid, pid))
            except Rejected:
                continue  # short-lived process exited during discovery
        if not identities:
            raise Rejected("baseline unavailable")
        _BASELINE[target] = frozenset(identities)


# ---- actions (grounding reads first, then the privileged verbs) ------------

def list_processes(target):
    cid = _resolve(target)
    base = _BASELINE.get(target, frozenset())
    lines = []
    for pid, cmd in _pids(cid):
        try:
            identity = _identity(cid, pid)
        except Rejected:
            continue
        executable = cmd.split()[0] if cmd else "unknown"
        protected = identity in base or pid == 1 or executable.rsplit("/", 1)[-1] in {"apache2", "httpd", "mysqld", "mariadbd", "php-fpm", "init", "supervisord"}
        lines.append(f"pid={pid} start_time={identity[2]} {'[protected]' if protected else '[candidate, NOT proof]'} {executable}")
    return "processes in {}:\n{}".format(target, "\n".join(lines) or "(none)")


def list_sessions(target):
    cid = _resolve(target)
    rc, out, err = _docker("exec", cid, "sh", "-c", f"ls -1 {SESS_DIR} 2>/dev/null")
    if rc != 0:
        raise Rejected(f"could not list sessions: {err.strip() or rc}")
    ids = [ln[5:] for ln in out.split() if ln.startswith("sess_")]
    return "active sessions in {}: {}".format(target, ", ".join(ids) or "(none)")


def kill_process(target, pid, start_time):
    cid = _resolve(target)
    pid = _pos_int(pid)
    base = _BASELINE.get(target)
    if not base or any(identity[0] != cid for identity in base):
        raise Rejected("missing or stale baseline; operator must verify target after restart")
    identity = _identity(cid, pid)
    if str(start_time) != identity[2] or identity in base or pid == 1:
        raise Rejected("stale identity or protected process")
    cmd = next((cmd for p, cmd in _pids(cid) if p == pid), "")
    executable = cmd.split()[0].rsplit("/", 1)[-1] if cmd else ""
    if not executable or executable in {"apache2", "httpd", "mysqld", "mariadbd", "php-fpm", "init", "supervisord"}:
        raise Rejected("protected service process")
    # Linux pidfd pins the process before identity verification, avoiding check/kill PID reuse.
    # If target lacks modern Python/pidfd support, refuse rather than fall back to unsafe kill.
    helper = ("import os,signal,sys; p=int(sys.argv[1]); fd=os.pidfd_open(p); "
              "s=open('/proc/%d/stat'%p).read().rsplit(')',1)[1].split()[19]; "
              "assert s==sys.argv[2], 'stale identity'; signal.pidfd_send_signal(fd,signal.SIGKILL)")
    rc, _, _ = _docker("exec", cid, "python3", "-c", helper, str(pid), str(start_time))
    if rc:
        raise Rejected("safe kill unavailable or identity changed; target needs Python with pidfd support")
    return f"killed verified candidate pid {pid} in {target}"


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


def rotate_secret(target):
    """Rotate the target app's DATABASE password so credentials an attacker stole
    (RCE, SQLi exfil, or reading the config) are immediately useless. Sets a fresh
    random password on the DB account via the container's local root socket, updates
    the app config to match, and verifies the OLD password is now rejected and the
    new one works. The new secret is generated here and is NEVER logged, audited, or
    returned — only the fact of rotation is. (DVWA has no separate app keys; the DB
    password is the credential of value.)"""
    cid = _resolve(target)
    rc, out, err = _docker("exec", cid, "sh", "-c",
                           "find /var/www -name config.inc.php 2>/dev/null | head -1")
    path = out.strip()
    if rc != 0 or not path:
        raise Rejected(f"could not locate app DB config: {err.strip() or 'not found'}")
    rc, cfg, err = _docker("exec", cid, "cat", path)
    if rc != 0:
        raise Rejected(f"could not read config: {err.strip() or rc}")
    mu, mp = _DB_USER_RE.search(cfg), _DB_PASS_RE.search(cfg)
    if not mu or not mp:
        raise Rejected("could not parse db_user/db_password from config")
    user, old = mu.group(1), mp.group(1)
    if not _DB_IDENT.fullmatch(user):
        raise Rejected(f"refusing to rotate: unexpected db_user {user!r}")
    new = secrets.token_hex(16)   # 32 hex chars: high entropy, shell/sed/SQL-safe

    # 1. set the new password on the DB account (root via the container's local
    #    socket — no old password needed). SET PASSWORD/PASSWORD() works across
    #    old MariaDB (10.1) and new; ALTER USER does not exist on 10.1.
    rc, _, err = _docker("exec", cid, "mysql", "-u", "root", "-e",
        f"SET PASSWORD FOR '{user}'@'localhost' = PASSWORD('{new}');")
    if rc != 0:
        # DB errors can echo the SQL (and thus the new secret) — redact it.
        raise Rejected(f"DB password change failed: {(err.strip() or str(rc)).replace(new, '***')}")

    # 2. update the app config to match, right after the ALTER.
    # ponytail: tiny window where the app would see a mismatch — fine on one box;
    # a transactional rotation would need app cooperation.
    expr = r"s#\(db_password'[^']*=[^']*'\)[^']*#\1" + new + "#"
    rc, _, err = _docker("exec", cid, "sed", "-i", expr, path)
    def rollback():
        # Hex literal avoids interpolating a potentially compromised old password into SQL.
        old_expr = "0x" + old.encode().hex() if old else "''"
        db_rc = _docker("exec", cid, "mysql", "-u", "root", "-e",
                       f"SET PASSWORD FOR '{user}'@'localhost' = PASSWORD({old_expr});")[0]
        escaped = old.replace("\\", "\\\\").replace("&", "\\&").replace("#", "\\#")
        reset_expr = r"s#\(db_password'[^']*=[^']*'\)[^']*#\1" + escaped + "#"
        cfg_rc = _docker("exec", cid, "sed", "-i", reset_expr, path)[0]
        verified = _docker("exec", cid, "mysql", "-u", user, f"--password={old}", "-e", "SELECT 1")[0] == 0
        return not db_rc and not cfg_rc and verified

    if rc != 0:
        recovered = rollback()
        raise Rejected(f"rotation failed; rollback_verified={recovered}; "
                       + ("old credentials restored" if recovered else "OPERATOR RECOVERY REQUIRED"))

    # 3. verify: new creds work AND the old (possibly stolen) creds are dead.
    #    --password= form (not -p) so an empty old password can't trigger a prompt.
    new_ok = _docker("exec", cid, "mysql", "-u", user, f"--password={new}", "-e", "SELECT 1")[0] == 0
    old_dead = _docker("exec", cid, "mysql", "-u", user, f"--password={old}", "-e", "SELECT 1")[0] != 0
    if not (new_ok and old_dead):
        recovered = rollback()
        raise Rejected(f"rotation verification failed; rollback_verified={recovered}; "
                       + ("old credentials restored" if recovered else "OPERATOR RECOVERY REQUIRED"))
    return (f"rotated DB password for '{user}' in {target}: stolen credentials are now "
            f"invalid, app config updated, verified (old rejected, new works). "
            f"New secret not logged.")


# ---- tool registry (Anthropic tool-use schemas) ----------------------------

_T = {"type": "object", "properties": {"target": {"type": "string",
      "description": "logical service name; only 'dvwa' is permitted"}},
      "required": ["target"]}

CONTROL_TOOLS = [
    {"name": "list_processes", "description":
     "List processes in the target container, each marked [baseline] (present at "
     "boot, protected) or a candidate (new is NOT proof of compromise). "
     "Use this to GROUND a kill_process call on a real pid.", "input_schema": _T},
    {"name": "list_sessions", "description":
     "List active application session ids in the target. Use to ground kill_session.",
     "input_schema": _T},
    {"name": "kill_process", "description":
     "Kill ONE attacker-spawned process (e.g. a reverse shell from RCE). Only a "
     "live, non-baseline identity can be killed; system processes are refused. "
     "Requires operator policy and Linux pidfd support in the target.",
     "input_schema": {"type": "object", "properties": {
         "target": _T["properties"]["target"],
         "pid": {"type": "integer", "description": "confirmed malicious candidate PID"},
         "start_time": {"type": "string", "pattern": "^[0-9]+$", "description": "identity from list_processes"}},
         "required": ["target", "pid", "start_time"]}},
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
    {"name": "rotate_secret", "description":
     "Rotate the target app's database password so credentials an attacker stole "
     "(via RCE, SQLi exfil, or reading the config) are instantly useless. Generates "
     "a fresh secret server-side (never shown), updates the app config to match, and "
     "verifies the old creds are dead. Use after a confirmed credential-exposure breach.",
     "input_schema": _T},
]

CONTROL_DISPATCH = {
    "list_processes": list_processes, "list_sessions": list_sessions,
    "kill_process": kill_process, "kill_session": kill_session,
    "isolate_egress": isolate_egress, "quarantine_container": quarantine_container,
    "release_container": release_container, "rotate_secret": rotate_secret,
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


# No Docker or network work at import. The isolated actuator captures its baseline
# explicitly at startup; stale/missing baselines fail closed for process termination.


# ---- self-test (no real containers touched) --------------------------------

def _selftest():
    global _RUNNER
    fake = {"pids": [100, 101, 102]}  # baseline set

    def runner(args):
        a = " ".join(args)
        if args[0] == "ps":
            return (0, "fakecid\n", "") if "service=dvwa" in a or "service=proxy" in a else (0, "", "")
        if args[0] == "exec" and "ps" in args:  # _pids reads container-ns `ps`
            return (0, "".join(f"{p} proc{p}\n" for p in fake["pids"]), "")
        if args[0] == "inspect":
            return (0, "breach-agent_default \n", "")
        if args[0] == "exec" and "ls" in a:
            return (0, "sess_abc\nsess_def\n", "")
        if args[0] == "exec" and "find" in a:
            return (0, "/var/www/html/config/config.inc.php\n", "")
        if args[0] == "exec" and "cat" in a:
            return (0, "$_DVWA[ 'db_user' ] = 'app';\n"
                       "$_DVWA[ 'db_password' ] = 'oldpw';\n", "")
        if args[0] == "exec" and "mysql" in a:
            # old (possibly stolen) creds must be dead after rotation
            return (1, "", "Access denied") if "--password=oldpw" in args else (0, "1\n", "")
        if args[0] in ("exec", "pause", "unpause", "network"):  # sed, kill, rm, ...
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

    # rotate_secret: happy path confirms + NEVER leaks the secret; boundary holds
    out = run_tool("rotate_secret", {"target": "dvwa"})
    assert out.startswith("rotated DB password"), out
    assert "oldpw" not in out and "not logged" in out.lower(), out
    assert run_tool("rotate_secret", {"target": "proxy"}).startswith("REJECTED")

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

    # rotate_secret must NOT leak the generated secret even if the DB echoes the SQL
    def failrunner(args):
        a = " ".join(args)
        if args[0] == "ps":
            return (0, "fakecid\n", "")
        if args[0] == "exec" and "find" in a:
            return (0, "/c.php\n", "")
        if args[0] == "exec" and "cat" in a:
            return (0, "$_DVWA[ 'db_user' ] = 'app';\n$_DVWA[ 'db_password' ] = 'oldpw';\n", "")
        if args[0] == "exec" and "mysql" in a:   # echo the whole command incl the secret
            return (1, "", f"ERROR 1064 syntax near \"{a}\"")
        return (0, "", "")
    _RUNNER = failrunner
    try:
        rotate_secret("dvwa")
        assert False, "rotate_secret should have raised on DB failure"
    except Rejected as e:
        assert not re.search(r"[0-9a-f]{32}", str(e)), f"secret leaked in error: {e}"

    print("actuator self-test: ALL PASSED")


if __name__ == "__main__":
    if "--probe" in sys.argv:  # live read-only peek at the real dvwa container
        print(list_processes("dvwa"))
        print(list_sessions("dvwa"))
    else:
        _selftest()
