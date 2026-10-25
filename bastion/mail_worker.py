"""Independent outbox worker and one-message live test command.

  python -m bastion.mail_worker --env-file .env --check
  python -m bastion.mail_worker --env-file .env --test

The test sends exactly one synthetic email, never an attack or queued real alert.
"""
import argparse
import json
import os
import signal
import threading
import uuid
from pathlib import Path

from dotenv import load_dotenv

from bastion.notifications import MailError, prepare_message, report_context, send_email, validate_config


def enrich_outbox_item(item):
    """Turn the raise-time alert into the full review report, once, on the first delivery attempt.

    The action list, audit head and trend are only complete at send time, but the payload bound
    to a provider idempotency key must never change between retries. So the enriched `_mail` is
    persisted back onto the outbox row before the first send; retries (attempts > 1) and rows
    already carrying an enriched message are left exactly as they are. Enrichment never fails
    the send: on any error the raise-time message goes out instead.
    """
    from bastion import store
    key = item.get("_mail_key")
    if not key or (item.get("_mail") or {}).get("enriched"):
        return item
    try:
        with store.connection() as db:
            row = db.execute("SELECT attempts FROM outbox WHERE key=?", (key,)).fetchone()
        if row is None or row["attempts"] > 1:
            return item
        enriched = {k: v for k, v in item.items() if k != "_mail_key"}
        enriched["_mail"] = prepare_message(enriched, report_context(enriched))
        with store.connection(write=True) as db:
            db.execute("UPDATE outbox SET data=? WHERE key=?", (json.dumps(enriched), key))
    except Exception:
        # Includes a MailError from re-reading ALERT_FROM/ALERT_TO: the raise-time message
        # captured the addresses that were valid when the alert was queued.
        print("[mail-worker] report enrichment failed; sending the raise-time alert instead", flush=True)
        return item
    return {**enriched, "_mail_key": key}


def deliver(item):
    return send_email(enrich_outbox_item(item))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", help="load this local .env file; never prints secrets")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="validate settings without making network calls")
    group.add_argument("--test", action="store_true", help="queue and send exactly one labeled test email")
    args = parser.parse_args(argv)
    if args.env_file:
        if not Path(args.env_file).is_file():
            parser.error("environment file does not exist")
        load_dotenv(args.env_file, override=False)
    # Import after loading env so the store sees the configured data directory.
    from bastion import store
    try:
        # --check/--test are diagnostics: fail fast and report. The continuous
        # daemon (no flags, what docker-compose runs) must never gate startup on
        # this; a missing/bad key is handled per-message in the loop below so one
        # bad .env value can't crash-loop the container (store.deliver_mail already
        # retries/dead-letters there without raising).
        if args.check or args.test:
            test_incident = {"ts": store.now(), "case_id": "test-" + uuid.uuid4().hex,
                             "severity": "info", "attack_type": "notification_test",
                             "source_ip": "not applicable", "evidence": "Synthetic notification test; no exploit or attack was run.",
                             "summary": "Bastion alert delivery is connected. This test passed through the durable outbox and configured email provider."}
            prepared = prepare_message(test_incident)
            key = validate_config()
            provider = "resend" if key else "local (no RESEND_API_KEY; alerts land in local_mail.jsonl and stdout)"
            if args.check:
                print(f"Email configuration valid: provider={provider}, recipients={len(prepared['to'])}. No email sent; DNS/key permissions not verified.")
                return 0
            store.initialize()
            case_id = test_incident["case_id"]
            store.queue_mail(case_id, test_incident)
            result = store.deliver_mail(deliver, key=case_id)
            print(json.dumps(result))
            if result and result["status"] == "accepted":
                print("Accepted by the mail provider. Check your inbox/spam folder and the provider's email log; inbox delivery is not yet confirmed.")
                return 0
            return 1
        store.initialize()
        mode = "Resend" if os.getenv("RESEND_API_KEY", "").strip() else "local fallback (no RESEND_API_KEY; alerts logged to local_mail.jsonl and stdout)"
        print(f"Mail worker started in {mode} mode; waiting for queued notifications", flush=True)
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        while not stop.is_set():
            try:
                store.set_health("mail-worker", {"ready": True})
                result = store.deliver_mail(deliver)
                if result:
                    print(json.dumps(result), flush=True)
            except Exception:
                # Unexpected errors must not log request objects or credentials.
                store.set_health("mail", {"available": False, "error": "mail worker failure"})
            stop.wait(1)
        store.set_health("mail-worker", {"ready": False})
        print("Mail worker stopped", flush=True)
        return 0
    except MailError as exc:
        print(f"Email configuration/delivery error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
