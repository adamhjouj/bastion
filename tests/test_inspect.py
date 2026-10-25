"""inspect_target returns facts only, with no heuristic threat signals."""
import json

from bastion.blue_agent import do_inspect_target


def test_returns_recorded_fields():
    result = json.loads(do_inspect_target("/login", "POST", "user=alice", "data=x"))
    assert result["path"] == "/login"
    assert result["method"] == "POST"
    assert result["query"] == "user=alice"
    assert result["body"] == "data=x"


def test_no_heuristic_fields():
    result = json.loads(do_inspect_target("/vuln/sqli/", "GET", "id=1 UNION SELECT 1", ""))
    for key in ("shell_metachars", "sql_tokens", "xss_tokens", "known_endpoint",
                "path_param", "escapes_dir", "shell_tokens"):
        assert key not in result


def test_note_present():
    result = json.loads(do_inspect_target("/"))
    assert "note" in result


def test_defaults_empty():
    result = json.loads(do_inspect_target("/"))
    assert result["query"] == "" and result["body"] == ""
