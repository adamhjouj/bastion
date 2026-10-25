"""Reset the lab to a clean, exploitable state between demo/test runs.

Virtual patches, IP bans and honeypot diversions PERSIST (shared state in the
bastion-data volume), so a second run of the same vuln would be pre-blocked. Run
this between runs to clear the blue-team response and restore the target to medium.

    python ops/reset_demo.py          # clear vpatch + bans + diversions, restore the target
                                      # (unquarantine, reconnect egress, APP_LEVEL=medium)
    python ops/reset_demo.py --keep-bans  # keep IP bans (only clear vpatch + diversions + level)

Does NOT touch request/incident history (the dashboard keeps its audit trail).
"""
import argparse
import subprocess
import sys


def _exec(service, args):
    return subprocess.run(["docker", "compose", "exec", "-T", service, *args],
                          capture_output=True, text=True)


def clear_state(keep_bans):
    code = (
        "import store\n"
        "with store.state_lock:\n"
        "    st = store.load_state()\n"
        "    before = (len(st.get('vpatch',[])), len(st.get('denylist',[])), len(st.get('honeypot',[])))\n"
        "    st['vpatch'] = []\n"
        "    st['honeypot'] = []\n"
        + ("" if keep_bans else "    st['denylist'] = []\n") +
        "    store.save_state(st)\n"
        "    print('state before (vpatch,denylist,honeypot) =', before)\n"
        "    print('state after  =', (len(st['vpatch']), len(st['denylist']), len(st['honeypot'])))\n")
    r = _exec("blue", ["python", "-c", code])
    sys.stdout.write(r.stdout)
    if r.returncode != 0:
        sys.exit(f"state reset failed: {r.stderr.strip()}")


def restore_level(level="medium"):
    """Undo target-side changes through the same path the dashboard's Reset button uses
    (remediation_tools.restore_lab, run in the actuator, the only side with the Docker
    socket): unfreeze a quarantine, reconnect egress, and set the app level back."""
    code = ("import json, remediation_tools\n"
            f"r = remediation_tools.restore_lab(level={level!r})\n"
            "print('target restore:', json.dumps(r))\n"
            "raise SystemExit(0 if r.get('ok') else 1)\n")
    r = _exec("actuator", ["python", "-c", code])
    sys.stdout.write(r.stdout)
    if r.returncode != 0:
        sys.exit(f"target restore failed: {(r.stderr or r.stdout).strip()}")


def main():
    p = argparse.ArgumentParser(description="Reset the lab between demo runs")
    p.add_argument("--keep-bans", action="store_true", help="do not clear IP denylist")
    p.add_argument("--level", default="medium", help="APP_LEVEL to restore (default medium)")
    args = p.parse_args()
    clear_state(args.keep_bans)
    restore_level(args.level)
    print("lab reset — vulns exploitable again, blue-team response cleared.")


if __name__ == "__main__":
    main()
