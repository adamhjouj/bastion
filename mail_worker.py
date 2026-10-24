"""Independent outbox worker and one-message live test command.

  python mail_worker.py --env-file .env --check
  python mail_worker.py --env-file .env --test

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

from notifications import MailError, prepare_message, send_email, validate_config


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
    import store
    try:
        test_incident = {"ts": store.now(), "case_id": "test-" + uuid.uuid4().hex,
                         "severity": "info", "attack_type": "notification_test",
                         "source_ip": "not applicable", "evidence": "Synthetic notification test; no exploit or attack was run.",
                         "summary": "Bastion alert delivery is connected. This test passed through the durable outbox and configured email provider."}
        prepared = prepare_message(test_incident)
        validate_config()
        if args.check:
            print(f"Email configuration valid: provider={prepared['provider']}, recipients={len(prepared['to'])}. No email sent; DNS/key permissions not verified.")
            return 0
        store.initialize()
        if args.test:
            key = test_incident["case_id"]
            store.queue_mail(key, test_incident)
            result = store.deliver_mail(send_email, key=key)
            print(json.dumps(result))
            if result and result["status"] == "accepted":
                print("Accepted by the mail provider. Check your inbox/spam folder and the provider's email log; inbox delivery is not yet confirmed.")
                return 0
            return 1
        print("Mail worker started; waiting for queued Resend notifications", flush=True)
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        while not stop.is_set():
            try:
                store.set_health("mail-worker", {"ready": True})
                result = store.deliver_mail(send_email)
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
