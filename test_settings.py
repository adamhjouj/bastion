"""Settings validation and mode contracts."""
import pytest
from settings import Settings


def _s(**kw):
    base = dict(mode="observe", management_token="x" * 32, inline_failure="reject",
                demo_identity=False, trusted_proxies="", request_limit=65536,
                response_limit=2097152, timeout=5.0, concurrency=8,
                budget_per_minute=120, queue_limit=10000, allow_destructive=False)
    base.update(kw)
    return Settings(**base)


def test_observe_mode_valid():
    _s().validate()  # no exception


def test_short_token_rejected():
    with pytest.raises(ValueError, match="MANAGEMENT_TOKEN"):
        _s(management_token="short").validate()


def test_invalid_mode():
    with pytest.raises(ValueError, match="BASTION_MODE"):
        _s(mode="turbo").validate()


def test_invalid_inline_failure():
    with pytest.raises(ValueError):
        _s(inline_failure="crash").validate()


def test_zero_limit_rejected():
    with pytest.raises(ValueError):
        _s(timeout=0).validate()


def test_inline_needs_jev(monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    with pytest.raises(ValueError, match="TYPESAFE_API_KEY"):
        _s(mode="inline").validate()


def test_agent_needs_llm(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    with pytest.raises(ValueError, match="LLM"):
        _s(mode="agent").validate()


def test_all_modes_enumerated():
    from settings import MODES
    assert MODES == {"observe", "agent", "classifier-contain", "inline"}
