"""Log storage, cursor recovery, bounded readers and display-safety tests."""
import asyncio
import hashlib

import pytest

import log_store
import store
from log_collector import DockerLogCollector, bounded_lines


def entry(text="hello", index=0, container="a" * 12, stream="stdout"):
    return {"container_id": container, "ts": f"2026-01-01T00:00:{index:02d}.000000001Z", "stream": stream,
            "text": text, "digest": hashlib.sha256(text.encode()).hexdigest(), "occurrence": 0}


def test_log_append_and_duplicate_replay():
    log_store.append("blue", [entry()])
    log_store.append("blue", [entry()])
    page = log_store.page("blue")
    assert len(page["entries"]) == 1
    assert page["entries"][0]["text"] == "hello"
    assert log_store.watermark("blue", "a" * 12) == entry()["ts"]


def test_identical_lines_in_same_timestamp_are_not_lost():
    one = entry()
    two = {**one, "occurrence": 1}
    log_store.append("blue", [one, two])
    assert len(log_store.page("blue")["entries"]) == 2


def test_logs_are_separate_from_request_queue():
    log_store.append("proxy", [entry()])
    assert store.claim_events() == []
    assert store.count_lines(store.EVENTS_FILE) == 0


def test_retention_and_cursor_reset():
    log_store.append("blue", [entry("old")])
    cursor = log_store.page("blue")["next_cursor"]
    log_store.append("blue", [entry("new", 1), entry("newer", 2)], retention=2)
    page = log_store.page("blue", cursor)
    assert page["reset"]
    assert [r["text"] for r in page["entries"]] == ["new", "newer"]


def test_cursor_does_not_duplicate_lines():
    log_store.append("blue", [entry()])
    cursor = log_store.page("blue")["next_cursor"]
    assert log_store.page("blue", cursor)["entries"] == []
    log_store.append("blue", [entry("second", 1)])
    assert [r["text"] for r in log_store.page("blue", cursor)["entries"]] == ["second"]


def test_source_history_isolated():
    log_store.append("blue", [entry("blue")])
    log_store.append("proxy", [entry("proxy")])
    assert log_store.page("blue")["entries"][0]["text"] == "blue"
    assert log_store.page("proxy")["entries"][0]["text"] == "proxy"


def test_common_credentials_and_control_sequences_are_redacted(monkeypatch):
    monkeypatch.setenv("ACTUATOR_TOKEN", "private-control-token")
    text = "\x1b[31mwarning\x1b[0m password=secret&token=ordinary Authorization: Bearer verysecret ACTUATOR_TOKEN=private-control-token re_12345678901234567890"
    log_store.append("blue", [entry(text)])
    saved = log_store.page("blue")["entries"][0]["text"]
    for secret in ("password=secret", "verysecret", "private-control-token", "re_12345678901234567890", "\x1b"):
        assert secret not in saved


def test_line_storage_is_bounded():
    log_store.append("blue", [entry("x" * 10000)])
    row = log_store.page("blue")["entries"][0]
    assert len(row["text"]) <= 4096 and row["truncated"]


def test_unknown_source_is_rejected():
    with pytest.raises(ValueError):
        log_store.page("some-unrelated-container")
    with pytest.raises(ValueError):
        DockerLogCollector("project", sources=["unrelated"])


def test_missing_and_stale_source_are_explicit():
    assert log_store.page("red")["status"]["status"] == "unavailable"
    log_store.set_source("blue", "streaming", "following")
    with store.connection(write=True) as db:
        db.execute("UPDATE log_sources SET updated=? WHERE source='blue'", (store.now_plus(-60),))
    assert log_store.page("blue")["status"]["status"] == "stale"


def test_container_recreation_keeps_history_and_new_identity():
    log_store.append("proxy", [entry("before", container="a" * 12)])
    log_store.append("proxy", [entry("after", container="b" * 12)])
    assert len(log_store.page("proxy")["entries"]) == 2
    assert log_store.watermark("proxy", "c" * 12) is None


def test_bounded_reader_drains_huge_line_and_preserves_next_line():
    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data(b"x" * 100000 + b"\nnext\n")
        reader.feed_eof()
        values = [line async for line in bounded_lines(reader, maximum=128)]
        assert values == [("x" * 128, True), ("next", False)]
    asyncio.run(scenario())


def test_reader_handles_utf8_and_partial_final_line():
    async def scenario():
        reader = asyncio.StreamReader()
        reader.feed_data("hello é".encode())
        reader.feed_eof()
        assert [line async for line in bounded_lines(reader)] == [("hello é", False)]
    asyncio.run(scenario())
