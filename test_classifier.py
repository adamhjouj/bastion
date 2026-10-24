"""Classifier schema validation, circuit breaker and budget enforcement."""
import asyncio
import json

import httpx
import pytest

import classifier
import store


def _resp(noul, choice, probs=None):
    return {"answers": {"malicious": {"noul": noul},
                        "attack_type": {"choice": choice, "confidence": 0.9,
                                        "probabilities": probs or {choice: noul, "benign": 1 - noul,
                                                                    "sql_injection": 0.0, "command_injection": 0.0,
                                                                    "xss": 0.0, "path_traversal": 0.0, "other": 0.0}}}}


def test_malicious_verdict():
    v = classifier.parse_answers(_resp(0.95, "sql_injection"))
    assert v["malicious"] is True and v["attack_type"] == "sql_injection"


def test_benign_verdict():
    v = classifier.parse_answers(_resp(0.02, "benign"))
    assert v["malicious"] is False


def test_flagged_benign_choice_uses_best_nonbenign():
    probs = {"sql_injection": 0.6, "benign": 0.3, "xss": 0.1,
             "command_injection": 0.0, "path_traversal": 0.0, "other": 0.0}
    v = classifier.parse_answers(_resp(0.8, "benign", probs))
    assert v["malicious"] is True and v["attack_type"] == "sql_injection"


def test_invalid_score_rejected():
    with pytest.raises(ValueError, match="score"):
        classifier.parse_answers({"answers": {"malicious": {"noul": 2.0},
                                              "attack_type": {"choice": "benign", "probabilities": {}}}})


def test_invalid_attack_type_rejected():
    with pytest.raises(ValueError, match="category"):
        classifier.parse_answers({"answers": {"malicious": {"noul": 0.5},
                                              "attack_type": {"choice": "rootkit", "probabilities": {}}}})


def test_invalid_probability_rejected():
    with pytest.raises(ValueError, match="probabilities"):
        classifier.parse_answers({"answers": {"malicious": {"noul": 0.5},
                                              "attack_type": {"choice": "benign",
                                                              "probabilities": {"benign": -0.1}}}})


def test_source_identity_not_in_payload():
    event = {"method": "GET", "path": "/x", "query": "q=1", "ip": "10.13.37.7"}
    p = classifier.payload(event)
    assert "10.13.37.7" not in p["state"]
    assert "ip" not in p["state"]


def test_budget_exhausted_returns_unavailable(monkeypatch):
    monkeypatch.setattr(store, "spend", lambda name, limit: False)
    result = classifier.classify_request({"method": "GET", "path": "/", "query": "", "body": ""})
    assert result["malicious"] is None and "budget" in result["error"]


def test_api_error_returns_unavailable():
    def boom(req):
        raise httpx.ConnectError("refused")
    result = classifier.classify_request({}, timeout=1)
    assert result["malicious"] is None


def test_async_circuit_opens_after_failures():
    from settings import Settings
    policy = Settings(mode="inline", management_token="x" * 32, inline_failure="reject",
                      demo_identity=False, trusted_proxies="", request_limit=65536,
                      response_limit=2097152, timeout=0.01, concurrency=8,
                      budget_per_minute=9999, queue_limit=10000, allow_destructive=False)

    async def scenario():
        async def boom(request):
            raise httpx.ConnectError("refused")
        clf = classifier.AsyncClassifier(policy, transport=httpx.MockTransport(boom))
        for _ in range(3):
            v = await clf.classify({"method": "GET", "path": "/", "query": "", "body": ""})
            assert v["malicious"] is None
        # Circuit should now be open.
        import time
        clf.open_until = time.monotonic() + 10
        v = await clf.classify({"method": "GET", "path": "/", "query": "", "body": ""})
        assert "circuit" in v.get("error", "")
        await clf.close()

    asyncio.run(scenario())
