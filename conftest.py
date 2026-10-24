"""Shared pytest fixtures. No global or import-time side effects."""
import os
import tempfile
from pathlib import Path

import pytest

import store


@pytest.fixture(autouse=True)
def isolated_data(tmp_path, monkeypatch):
    """Redirect every store path to a fresh temp directory for each test."""
    monkeypatch.setattr(store, "DATA", tmp_path)
    monkeypatch.setattr(store, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(store, "EVENTS_FILE", tmp_path / "events.jsonl")
    monkeypatch.setattr(store, "INCIDENTS_FILE", tmp_path / "incidents.jsonl")
    monkeypatch.setattr(store, "ACTIONS_FILE", tmp_path / "actions.jsonl")
    monkeypatch.setenv("BASTION_DATA_DIR", str(tmp_path))
    store.initialize()
    return tmp_path
