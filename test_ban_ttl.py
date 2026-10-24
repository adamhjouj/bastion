"""Self-check: provisional reflex bans expire; agent re-ban upgrades to durable."""
import pathlib, tempfile
import store


def test_ttl_lifecycle():
    store.STATE_FILE = pathlib.Path(tempfile.mkdtemp()) / "state.json"
    from blue_agent import do_blacklist_ip

    # reflex ban that already expired -> proxy predicate must treat it INACTIVE
    do_blacklist_ip("1.2.3.4", "reflex", expires=store.now_plus(-60))
    d = next(x for x in store.load_state()["denylist"] if x["ip"] == "1.2.3.4")
    now = store.now()
    active = (not d.get("expires")) or d["expires"] > now
    assert active is False, d

    # agent confirms -> re-ban with no expiry upgrades it to durable (permanent)
    do_blacklist_ip("1.2.3.4", "agent-confirmed")
    d = next(x for x in store.load_state()["denylist"] if x["ip"] == "1.2.3.4")
    assert d["expires"] is None, d
    active = (not d.get("expires")) or d["expires"] > now
    assert active is True, d

    # a durable ban must NOT be weakened back to a TTL
    do_blacklist_ip("1.2.3.4", "reflex again", expires=store.now_plus(60))
    d = next(x for x in store.load_state()["denylist"] if x["ip"] == "1.2.3.4")
    assert d["expires"] is None, d
    print("ttl ban lifecycle: ok")


if __name__ == "__main__":
    test_ttl_lifecycle()
