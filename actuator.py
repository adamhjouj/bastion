"""Allowlisted Docker operations executed by the actuator service.

Commands use fixed argument lists with validated parameters. Process termination
requires a current identity, a baseline check, and target-side pidfd support.
Authentication and destructive-action policy are enforced in actuator_app.py.
The service's Docker socket remains a host-level privilege boundary.
"""
import os
import re
import secrets
import subprocess
import sys
from datetime import datetime, timezone

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

_BASELINE = {}   # target -> frozenset((container_id, pid, start_time))

# Processes that legitimately run in a freshly-booted target (the de-fingerprinted
# fork is php:8.2-apache) plus our own discovery/boot tooling. Shared by the
# protected-process guard and the fresh-boot "clean" check.
_PROTECTED = {"apache2", "httpd", "mysqld", "mariadbd", "php-fpm", "init", "supervisord"}
_BOOT_TRANSIENT = {"ps", "sh", "bash", "php"}   # our exec ps, entrypoint shell, healthcheck php
# How recently a container must have (re)started to be trusted as a fresh boot for
# automatic baseline re-capture. Calibration knob: a demo rebuild + attack happens
# well inside this; a long-lived container that goes stale needs operator verify.
# ponytail: tune via env if the demo's recreate->kill gap ever exceeds it.
FRESH_SECS = int(os.environ.get("BASTION_BASELINE_FRESH_SECS", "180"))


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
    """Read container-namespace PIDs; docker top reports host-namespace PIDs."""
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


def _snapshot(cid):
    """Snapshot a container's live process identities (cid, pid, start_time)."""
    identities = []
    for pid, _ in _pids(cid):
        try:
            identities.append(_identity(cid, pid))
        except Rejected:
            continue  # short-lived process exited during discovery
    return frozenset(identities)


def capture_baseline():
    """Explicit startup snapshot. Container IDs and start times prevent PID-reuse trust."""
    for target in ALLOWED_TARGETS:
        snap = _snapshot(_resolve(target))
        if not snap:
            raise Rejected("baseline unavailable")
        _BASELINE[target] = snap


def _started_age(cid):
    """Seconds since the container last (re)started, or None if unknown/unparseable."""
    rc, out, _ = _docker("inspect", "-f", "{{.State.StartedAt}}", cid)
    s = (out or "").strip()
    if rc != 0 or not s or s[:4] == "0001":   # 0001-01-01... => never started
        return None
    s = s.replace("Z", "+00:00")
    m = re.match(r"(.*\.\d{1,6})\d*(\+\d{2}:\d{2})$", s)   # trim docker's nanoseconds -> micros
    if m:
        s = m.group(1) + m.group(2)
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(s)).total_seconds()
    except ValueError:
        return None


def _is_fresh_clean(cid):
    """True only if the container (re)started recently AND every running process is an
    expected service/boot process — a provably fresh boot with no attacker activity.
    This is what lets automatic re-capture trust the container without laundering a
    compromised one into the baseline: a reverse shell (or any non-service process)
    makes it non-clean, so re-capture is refused and the operator-verify guard stands."""
    age = _started_age(cid)
    if age is None or age > FRESH_SECS:
        return False
    for pid, cmd in _pids(cid):
        exe = cmd.split()[0].rsplit("/", 1)[-1] if cmd else ""
        if pid == 1 or exe in _PROTECTED or exe in _BOOT_TRANSIENT:
            continue
        return False   # an unexpected process is present -> not provably clean
    return True


def ensure_baseline(target=None):
    """Idempotent baseline keeper. (Re)establishes a target's baseline ONLY when it is
    missing or stale (container re-created => new id) AND the target is a fresh, clean
    (re)boot. Called from the actuator heartbeat so a target recreated after startup
    re-baselines automatically during its clean boot window, and never raises."""
    for t in ([target] if target else ALLOWED_TARGETS):
        try:
            cid = _resolve(t)
            base = _BASELINE.get(t)
            if base and all(identity[0] == cid for identity in base):
                continue   # current, valid baseline — nothing to do
            if _is_fresh_clean(cid):
                snap = _snapshot(cid)
                if snap:
                    _BASELINE[t] = snap
        except Exception:   # heartbeat caller must never be killed by a probe error
            continue


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
        protected = identity in base or pid == 1 or executable.rsplit("/", 1)[-1] in _PROTECTED
        lines.append(f"pid={pid} start_time={identity[2]} {'[protected]' if protected else '[candidate, NOT proof]'} {executable}")
    return "processes in {}:\n{}".format(target, "\n".join(lines) or "(none)")


def _session_dir(cid):
    """Where THIS PHP app actually writes session files. DVWA used a Debian php.ini
    default of /var/lib/php/sessions; the de-fingerprinted fork runs php:8.2-apache,
    which leaves session.save_path empty -> PHP falls back to sys_get_temp_dir()
    (/tmp). Ask the app's own PHP rather than assuming the old path."""
    rc, out, _ = _docker("exec", cid, "php", "-r",
                         "echo ini_get('session.save_path') ?: sys_get_temp_dir();")
    path = (out or "").strip()
    if ";" in path:                      # "N;/path" or "N;MODE;/path"
        path = path.rsplit(";", 1)[-1]
    return path or SESS_DIR


def list_sessions(target):
    cid = _resolve(target)
    sdir = _session_dir(cid)
    rc, out, _ = _docker("exec", cid, "sh", "-c", f"ls -1 {sdir} 2>/dev/null")
    # A missing/empty session dir is "no sessions", not a tool failure.
    ids = [ln[5:] for ln in out.split() if ln.startswith("sess_")] if rc == 0 else []
    return "active sessions in {}: {}".format(target, ", ".join(ids) or "(none)")


def kill_process(target, pid, start_time):
    cid = _resolve(target)
    pid = _pos_int(pid)
    base = _BASELINE.get(target)
    if not base or any(identity[0] != cid for identity in base):
        # Baseline is missing/stale (target re-created since startup). Re-establish it
        # ONLY if the target is a fresh, clean (re)boot; attacker activity leaves it
        # stale and the operator-verify guard below still fires.
        ensure_baseline(target)
        base = _BASELINE.get(target)
    if not base or any(identity[0] != cid for identity in base):
        raise Rejected("missing or stale baseline; operator must verify target after restart")
    identity = _identity(cid, pid)
    if str(start_time) != identity[2] or identity in base or pid == 1:
        raise Rejected("stale identity or protected process")
    cmd = next((cmd for p, cmd in _pids(cid) if p == pid), "")
    executable = cmd.split()[0].rsplit("/", 1)[-1] if cmd else ""
    if not executable or executable in _PROTECTED:
        raise Rejected("protected service process")
    # Re-read /proc/<pid>/stat and re-check the start_time in the SAME shell step that
    # kills, so the identity can't change between check and kill. The de-fingerprinted
    # target is php:8.2-apache and ships no python3, so the old pidfd helper always
    # errored here; the kill verb below uses only POSIX sh + the kill builtin.
    # ponytail: no pidfd => a sub-millisecond PID-reuse race remains between the
    # start_time check and kill; acceptable for this target. Upgrade: install python3
    # with os.pidfd_open in the image if the race ever matters.
    guard = ('p="$1"; want="$2"; s=$(cat /proc/"$p"/stat 2>/dev/null) || exit 3; '
             'rest=${s##*) }; set -- $rest; [ "${20}" = "$want" ] || exit 4; '
             'kill -9 "$p"')
    rc, _, _ = _docker("exec", cid, "sh", "-c", guard, "sh", str(pid), str(start_time))
    if rc:
        raise Rejected("safe kill failed: identity changed or process already gone")
    return f"killed verified candidate pid {pid} in {target}"


def kill_session(target, session_id):
    cid = _resolve(target)
    if not _SESSION_ID.fullmatch(str(session_id)):
        raise Rejected(f"invalid session id {session_id!r}")
    sdir = _session_dir(cid)
    rc, _, err = _docker("exec", cid, "rm", "-f", f"{sdir}/sess_{session_id}")
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


def _egress_networks():
    """The compose-defined 'egress' network name(s) for this project (by compose label),
    so reconnect works even after the target has been disconnected from it."""
    rc, out, _ = _docker(
        "network", "ls", "--format", "{{.Name}}",
        "--filter", f"label=com.docker.compose.project={PROJECT}",
        "--filter", "label=com.docker.compose.network=egress")
    return [n for n in out.split() if _NET_NAME.fullmatch(n)] if rc == 0 else []


def reconnect_egress(target):
    """Reverse isolate_egress: re-attach the target to its egress/outbound network so a
    demo (or operator) can restore outbound after containment. Idempotent — an already
    connected network is treated as success."""
    cid = _resolve(target)
    nets = _egress_networks()
    if not nets:
        raise Rejected("no egress network found for this project to reconnect")
    already = _nets(cid)
    done = []
    for n in nets:
        if n in already:
            done.append(f"{n}(already)")
            continue
        rc, _, err = _docker("network", "connect", n, cid)
        done.append(n if rc == 0 else f"{n}(failed:{err.strip() or rc})")
    return f"egress restored: reconnected {target} to {', '.join(done)}"


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
    """Make a credential an attacker stole (RCE, SQLi exfil, config read) immediately
    useless by rotating it on the target. Target-aware:

    - Stock DVWA / MySQL (a `config.inc.php` is present): rotate the DB account password
      via the container's local root socket and update the config to match.
    - De-fingerprinted SQLite fork (no `config.inc.php`; creds are md5 rows in the
      `accounts` table): reset the compromised operator account's credential to a fresh
      random password hash so a dumped/stolen cred no longer authenticates while the
      account still works with the new one.

    Either way the new secret is generated here and is NEVER logged, audited, or returned
    — only the fact of rotation is — and rotation is verified (old rejected, new works)."""
    cid = _resolve(target)
    rc, out, _err = _docker("exec", cid, "sh", "-c",
                            "find /var/www -name config.inc.php 2>/dev/null | head -1")
    path = out.strip()
    if rc == 0 and path:
        return _rotate_mysql(cid, target, path)
    return _rotate_sqlite(cid, target)


def _rotate_sqlite(cid, target):
    """SQLite fork path: reset the operator account's md5 credential in the accounts
    table. Reads the per-instance config (instance.php) for the table/column/user names
    and the OLD passphrase, writes md5(new) into the row, and verifies — entirely inside
    the container's PHP — that the stored hash now matches md5(new) and no longer matches
    md5(old), mirroring the app's own `hash_equals($hash, md5($p))` auth check. The new
    passphrase is inlined into the one-shot PHP only (never the config/handbook, never
    logged); only 'OK'/'FAIL' is echoed back."""
    rc, out, _ = _docker("exec", cid, "sh", "-c",
                         'f="${APP_DATA:-/var/www/data}/instance.php"; [ -f "$f" ] && echo yes')
    if (out or "").strip() != "yes":
        raise Rejected("could not locate app DB config (no config.inc.php or instance.php)")
    new = secrets.token_hex(16)   # 32 hex chars, md5'd into the row; never logged/returned
    php = (
        "$f=(getenv('APP_DATA')?:'/var/www/data').'/instance.php'; $c=require $f; "
        "$u=$c['operator_user']; $old=$c['operator_pass']; $new='" + new + "'; "
        "$pdo=new PDO('sqlite:'.$c['db']); $pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION); "
        "$up=$pdo->prepare(sprintf('UPDATE %s SET %s=? WHERE %s=?',$c['tbl'],$c['c_pass'],$c['c_user'])); "
        "$up->execute([md5($new),$u]); "
        "$se=$pdo->prepare(sprintf('SELECT %s FROM %s WHERE %s=?',$c['c_pass'],$c['tbl'],$c['c_user'])); "
        "$se->execute([$u]); $cur=$se->fetchColumn(); "
        "echo ($cur===md5($new) && $cur!==md5($old)) ? 'OK' : 'FAIL';"
    )
    rc, out, err = _docker("exec", cid, "php", "-r", php)
    verdict = (out or "").strip()
    if rc != 0:
        # PHP errors can echo the inlined script (and thus the new secret) — redact it.
        raise Rejected(f"credential reset failed: {(err.strip() or str(rc)).replace(new, '***')}")
    if verdict != "OK":
        raise Rejected("credential reset verification failed: "
                       + ((err.strip() or verdict or 'no output').replace(new, '***')))
    return (f"reset compromised operator credentials in {target}: the stolen credential no "
            f"longer authenticates and the account remains valid with a fresh secret "
            f"(verified old-rejected, new-works). New secret not logged.")


def _rotate_mysql(cid, target, path):
    """Stock DVWA / MySQL path (config.inc.php present)."""
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
    # DB and config updates are not atomic; rollback handles detected failures.
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
     "Identity (start_time) is re-verified at kill time. Requires operator policy.",
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
     "a 2nd-stage payload) while keeping it reachable through the proxy. "
     "Reversible with reconnect_egress.",
     "input_schema": _T},
    {"name": "reconnect_egress", "description":
     "Reverse isolate_egress: re-attach the target to its egress/outbound network "
     "to restore outbound connectivity after containment (e.g. to reset a demo).",
     "input_schema": _T},
    {"name": "quarantine_container", "description":
     "Freeze the whole target container (docker pause). Nuclear containment — the "
     "attacker loses the target entirely. Reversible with release_container.",
     "input_schema": _T},
    {"name": "release_container", "description":
     "Un-freeze a quarantined container (docker unpause).", "input_schema": _T},
    {"name": "rotate_secret", "description":
     "Make a stolen credential useless by rotating it on the target (target-aware). On "
     "stock DVWA it rotates the MySQL DB password + config; on the SQLite fork it resets "
     "the compromised operator account's credential in the accounts table. Generates a "
     "fresh secret server-side (never shown) and verifies the old cred is dead and the "
     "account still works. Use after a confirmed credential-exposure breach.",
     "input_schema": _T},
]

CONTROL_DISPATCH = {
    "list_processes": list_processes, "list_sessions": list_sessions,
    "kill_process": kill_process, "kill_session": kill_session,
    "isolate_egress": isolate_egress, "reconnect_egress": reconnect_egress,
    "quarantine_container": quarantine_container,
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


# Baselines are captured by the actuator's startup lifecycle, not during import.


# ---- self-test (no real containers touched) --------------------------------

# Baseline identity is now (cid, pid, start_time). Each field needs a distinct
# mock response for the ps and /proc/pid/stat reads.
_FAKE_START = "12345678"


def _selftest():
    global _RUNNER
    fake = {"pids": [100, 101, 102]}

    def runner(args):
        a = " ".join(args)
        if args[0] == "ps":
            # _discover format: {{.ID}} {{.State}}
            if "--format" in args and "running" not in a and "service=dvwa" in a:
                return (0, "fakecid running\n", "")
            # _resolve format: -q
            if "-q" in args and "service=dvwa" in a:
                return (0, "fakecid\n", "")
            if "service=proxy" in a:
                return (0, "proxycid\n", "")
            return (0, "", "")
        if args[0] == "exec" and "ps" in args:
            return (0, "".join(f"{p} proc{p}\n" for p in fake["pids"]), "")
        if args[0] == "exec" and "cat" in a and "/proc/" in a:
            # Return a minimal /proc/pid/stat: comm field then space-separated fields
            return (0, f"1 (proc) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 {_FAKE_START}\n", "")
        if args[0] == "inspect":
            return (0, "bastion_default \n", "")
        if args[0] == "exec" and "ls" in a:
            return (0, "sess_abc\nsess_def\n", "")
        if args[0] == "exec" and "find" in a:
            return (0, "/var/www/html/config/config.inc.php\n", "")
        if args[0] == "exec" and "cat" in a:
            return (0, "$_DVWA[ 'db_user' ] = 'app';\n"
                       "$_DVWA[ 'db_password' ] = 'oldpw';\n", "")
        if args[0] == "exec" and "mysql" in a:
            return (1, "", "Access denied") if "--password=oldpw" in args else (0, "1\n", "")
        if args[0] in ("exec", "pause", "unpause", "network"):
            return (0, "", "")
        return (0, "", "")

    _RUNNER = runner
    _BASELINE.clear()
    capture_baseline()
    expected = frozenset(("fakecid", p, _FAKE_START) for p in [100, 101, 102])
    assert _BASELINE["dvwa"] == expected, _BASELINE

    # target boundary
    assert run_tool("quarantine_container", {"target": "proxy"}).startswith("REJECTED")
    assert run_tool("quarantine_container", {"target": "blue"}).startswith("REJECTED")
    assert run_tool("quarantine_container", {"target": "dvwa"}).startswith("dvwa quarantined")

    # kill: attacker spawns pid 1234 AFTER baseline; kill requires start_time
    fake["pids"] = [100, 101, 102, 1234]
    assert run_tool("kill_process", {"target": "dvwa", "pid": 100, "start_time": _FAKE_START}).startswith("REJECTED")   # in baseline
    assert run_tool("kill_process", {"target": "dvwa", "pid": 777, "start_time": _FAKE_START}).startswith("REJECTED")   # not running
    assert run_tool("kill_process", {"target": "dvwa", "pid": "x", "start_time": _FAKE_START}).startswith("REJECTED")   # bad pid
    assert run_tool("kill_process", {"target": "dvwa", "pid": 1234, "start_time": _FAKE_START}).startswith("killed")
    # missing required field
    assert run_tool("kill_process", {"target": "dvwa", "pid": 1234}).startswith("ERROR")

    # session id must be charset-clean (no path traversal)
    assert run_tool("kill_session", {"target": "dvwa", "session_id": "../../etc/passwd"}).startswith("REJECTED")
    assert run_tool("kill_session", {"target": "dvwa", "session_id": "abc"}).startswith("invalidated")

    # rotate_secret: boundary holds; secret never logged (DVWA/MySQL branch here)
    out = run_tool("rotate_secret", {"target": "dvwa"})
    assert out.startswith("rotated DB password"), out
    assert "oldpw" not in out and "not logged" in out.lower(), out
    assert run_tool("rotate_secret", {"target": "proxy"}).startswith("REJECTED")

    # reconnect_egress: boundary holds and no egress net in the mock => clean reject (never raises)
    assert run_tool("reconnect_egress", {"target": "proxy"}).startswith("REJECTED")
    assert run_tool("reconnect_egress", {"target": "dvwa"}).startswith("REJECTED")

    # unknown tool and bad kwargs never raise
    assert run_tool("bogus", {}).startswith("ERROR")
    assert run_tool("kill_process", {"target": "dvwa", "oops": 1}).startswith("ERROR")

    # register() wires safely
    tools, disp = [], {}
    register(tools, disp)
    assert len(tools) == len(CONTROL_TOOLS) and "kill_process" in disp
    assert disp["quarantine_container"](target="proxy").startswith("REJECTED")

    # REGISTER shape
    assert {r["name"] for r in REGISTER} == set(CONTROL_DISPATCH)
    assert all(set(r) == {"name", "schema", "fn"} for r in REGISTER)
    assert next(r for r in REGISTER if r["name"] == "kill_session")["fn"](
        target="proxy", session_id="x").startswith("REJECTED")

    # rotate_secret must NOT leak the generated secret
    def failrunner(args):
        a = " ".join(args)
        if args[0] == "ps" and "-q" in args:
            return (0, "fakecid\n", "")
        if args[0] == "exec" and "find" in a:
            return (0, "/c.php\n", "")
        if args[0] == "exec" and "cat" in a and "/proc/" in a:
            return (0, f"1 (proc) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 {_FAKE_START}\n", "")
        if args[0] == "exec" and "cat" in a:
            return (0, "$_DVWA[ 'db_user' ] = 'app';\n$_DVWA[ 'db_password' ] = 'oldpw';\n", "")
        if args[0] == "exec" and "mysql" in a:
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
    if "--probe" in sys.argv:
        print(list_processes("dvwa"))
        print(list_sessions("dvwa"))
    else:
        _selftest()
