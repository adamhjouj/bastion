"""Redaction and structured request view."""
import privacy


def test_sensitive_keys():
    assert privacy.sensitive("password")
    assert privacy.sensitive("Authorization")
    assert privacy.sensitive("PHPSESSID")
    assert privacy.sensitive("user_token")
    assert privacy.sensitive("api_key")
    assert not privacy.sensitive("username")
    assert not privacy.sensitive("path")


def test_redact_dict():
    out = privacy.redact({"password": "secret", "username": "alice"})
    assert out["password"] == "[REDACTED]"
    assert out["username"] == "alice"


def test_redact_nested():
    out = privacy.redact({"credentials": {"token": "abc"}})
    assert out["credentials"]["token"] == "[REDACTED]"


def test_form_view_redacts_sensitive():
    pairs = privacy.form_view("username=alice&password=s3cr3t&Submit=Login")
    d = dict(pairs)
    assert d["username"] == "alice"
    assert d["password"] == "[REDACTED]"
    assert d["Submit"] == "Login"


def test_form_view_preserves_duplicates():
    pairs = privacy.form_view("a=1&a=2")
    assert [v for k, v in pairs if k == "a"] == ["1", "2"]


def test_request_view_form():
    view = privacy.request_view("POST", "/login", "", "username=alice&password=s3cr3t",
                                "application/x-www-form-urlencoded")
    body_pairs = dict(pair for pair in view["body_view"])
    assert body_pairs["username"] == "alice"
    assert body_pairs["password"] == "[REDACTED]"
    assert view["redacted"] is True


def test_request_view_json():
    import json
    view = privacy.request_view("POST", "/api", "", json.dumps({"token": "abc", "data": "x"}),
                                "application/json")
    assert view["body_view"]["token"] == "[REDACTED]"
    assert view["body_view"]["data"] == "x"


def test_request_view_binary_omitted():
    view = privacy.request_view("POST", "/upload", "", b"\x89PNG".decode("latin1"), "image/png")
    assert "binary" in view["body"]


def test_request_view_unstructured_text_omitted():
    view = privacy.request_view("POST", "/data", "", "plain text", "text/plain")
    assert "omitted" in view["body"]
