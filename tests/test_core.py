"""Unit tests for core verification behavior."""

import subprocess
from pathlib import Path

from brew_guard import core
from brew_guard.config import JsonFileError


def test_check_quarantine_blocks_on_missing_date_by_default(monkeypatch):
    monkeypatch.setattr(core, "audit_log", lambda *args, **kwargs: None)
    monkeypatch.setattr(core, "get_formula_last_modified", lambda *args, **kwargs: None)

    ok, lines, code = core.check_quarantine(
        "wget",
        "formula",
        False,
        {"allowed": {}, "quarantine_days": 3, "block_on_date_resolution_error": True},
    )

    assert ok is False
    assert code == "blocked_no_date"
    assert any("Cannot determine modification date" in line for line in lines)


def test_check_quarantine_warns_when_date_block_disabled(monkeypatch):
    monkeypatch.setattr(core, "audit_log", lambda *args, **kwargs: None)
    monkeypatch.setattr(core, "get_formula_last_modified", lambda *args, **kwargs: None)

    ok, lines, code = core.check_quarantine(
        "wget",
        "formula",
        False,
        {"allowed": {}, "quarantine_days": 3, "block_on_date_resolution_error": False},
    )

    assert ok is True
    assert code == "warn_no_date"
    assert any("WARN" in line for line in lines)


def test_check_hash_changes_blocks_on_invalid_lockfile_by_default(monkeypatch):
    monkeypatch.setattr(core, "audit_log", lambda *args, **kwargs: None)

    def raise_json_error():
        raise JsonFileError(Path("/tmp/lockfile.json"), "bad json")

    monkeypatch.setattr(
        core,
        "load_lockfile",
        raise_json_error,
    )

    ok, lines, code = core.check_hash_changes(
        "wget",
        {"formulae": [{}]},
        "formula",
        False,
        {"block_on_lockfile_error": True},
    )

    assert ok is False
    assert code == "blocked_lockfile_error"
    assert any("Cannot read lockfile" in line for line in lines)


def test_check_hash_changes_warns_when_lockfile_block_disabled(monkeypatch):
    monkeypatch.setattr(core, "audit_log", lambda *args, **kwargs: None)

    def raise_json_error():
        raise JsonFileError(Path("/tmp/lockfile.json"), "bad json")

    monkeypatch.setattr(
        core,
        "load_lockfile",
        raise_json_error,
    )

    ok, lines, code = core.check_hash_changes(
        "wget",
        {"formulae": [{}]},
        "formula",
        False,
        {"block_on_lockfile_error": False},
    )

    assert ok is True
    assert code == "warn_lockfile_error"
    assert any("treating as untracked" in line for line in lines)


def test_verify_attestation_timeout_is_failure(monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="gh", timeout=30)

    monkeypatch.setattr(core, "run", fake_run)

    ok, lines, code = core.verify_attestation(
        "wget",
        {"formulae": [{"bottle": {"stable": {"files": {"sonoma": {"sha256": "abc"}}}}}]},
    )

    assert ok is False
    assert code == "timeout"
    assert any("ATTEST TIMEOUT" in line for line in lines)


def test_get_formula_last_modified_recovers_from_invalid_cache(monkeypatch):
    saved: list[dict] = []

    def fake_load_json(path):
        raise JsonFileError(path, "bad json")

    def fake_save_json(path, data):
        saved.append(data)

    monkeypatch.setattr(core, "load_json", fake_load_json)
    monkeypatch.setattr(core, "save_json", fake_save_json)
    monkeypatch.setattr(
        core,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout="2025-01-01T00:00:00Z\n",
            stderr="",
        ),
    )

    last_modified = core.get_formula_last_modified("wget", "formula")

    assert last_modified == "2025-01-01T00:00:00Z"
    assert saved[0] == {}
    assert saved[-1]["wget"]["last_modified"] == "2025-01-01T00:00:00Z"
