"""Self-test for rate_limit: no network, no sleeps — rewind stored monotonic
stamps instead of waiting, so it's fast and deterministic.
Run: .venv/bin/python test_rate_limit.py"""
import rate_limit

rate_limit.reset()
rate_limit.RATE_LIMIT_MAX = 5
rate_limit.RATE_LIMIT_WINDOW = 10.0
rate_limit.RATE_LIMIT_ENABLED = True

IP = "10.0.0.1"
OTHER = "10.0.0.2"

# First MAX calls allowed, then limited.
for i in range(5):
    assert rate_limit.limited(IP) is False, f"call {i} should be allowed"
assert rate_limit.limited(IP) is True, "6th call should be limited"
assert rate_limit.limited(IP) is True, "stays limited on immediate repeat"

# Per-IP independence: a different IP is unaffected while IP is limited.
assert rate_limit.limited(OTHER) is False, "other IP must not be limited"

# Window recovery WITHOUT sleeping: rewind IP's stored stamps past the window.
# _hits[ip] is a deque of time.monotonic() stamps (documented internal name).
for i, t in enumerate(rate_limit._hits[IP]):
    rate_limit._hits[IP][i] = t - (rate_limit.RATE_LIMIT_WINDOW + 1)
assert rate_limit.limited(IP) is False, "window slid → allowed again"

# Disabled: always False, records nothing.
rate_limit.RATE_LIMIT_ENABLED = False
rate_limit.reset()
for i in range(50):
    assert rate_limit.limited(IP) is False, "disabled must never limit"
assert len(rate_limit._hits) == 0, "disabled records nothing"

print("rate_limit test: ALL PASSED")
