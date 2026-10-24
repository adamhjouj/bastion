"""Self-check: enforced_security pins the security cookie, keeps other cookies."""
from proxy import _enforce_security_cookie as ec


def test_enforce():
    # strips client-chosen security=low, pins to high, keeps PHPSESSID
    r = ec("PHPSESSID=abc; security=low", "high")
    assert "PHPSESSID=abc" in r and r.endswith("security=high") and "security=low" not in r, r
    # no cookie header at all -> just the pinned level
    assert ec(None, "impossible") == "security=impossible"
    assert ec("", "medium") == "security=medium"
    # security in the middle, other cookies preserved and order kept
    r = ec("a=1; security=low; b=2", "high")
    assert r == "a=1; b=2; security=high", r
    print("enforce cookie: ok")


if __name__ == "__main__":
    test_enforce()
