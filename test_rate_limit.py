"""Rate limiter: capacity control, per-IP isolation and LRU eviction."""
import collections
import time

import pytest

import rate_limit


@pytest.fixture(autouse=True)
def fresh():
    rate_limit.reset()
    rate_limit.RATE_LIMIT_MAX = 5
    rate_limit.RATE_LIMIT_WINDOW = 60.0
    rate_limit.RATE_LIMIT_ENABLED = True
    yield
    rate_limit.reset()


def test_allows_up_to_limit():
    for _ in range(5):
        assert not rate_limit.limited("10.0.0.1")


def test_blocks_over_limit():
    for _ in range(5):
        rate_limit.limited("10.0.0.1")
    assert rate_limit.limited("10.0.0.1")


def test_per_ip_isolation():
    for _ in range(5):
        rate_limit.limited("10.0.0.1")
    assert not rate_limit.limited("10.0.0.2")


def test_window_recovery():
    for _ in range(5):
        rate_limit.limited("10.0.0.1")
    assert rate_limit.limited("10.0.0.1")
    dq = rate_limit._hits["10.0.0.1"]
    for i in range(len(dq)):
        dq[i] = dq[i] - (rate_limit.RATE_LIMIT_WINDOW + 1)
    assert not rate_limit.limited("10.0.0.1")


def test_disabled_never_limits():
    rate_limit.RATE_LIMIT_ENABLED = False
    for _ in range(50):
        assert not rate_limit.limited("10.0.0.1")
    assert len(rate_limit._hits) == 0


def test_lru_eviction_bounded():
    rate_limit.MAX_IDENTITIES = 3
    for i in range(4):
        rate_limit.limited(f"10.0.{i}.1")
    assert len(rate_limit._hits) <= 3
    rate_limit.MAX_IDENTITIES = 10000


def test_retry_after_positive():
    assert rate_limit.retry_after() >= 1
