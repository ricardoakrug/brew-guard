"""Unit tests for core verification behavior."""

import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from brew_guard import core
from brew_guard.config import JsonFileError


def _iso_days_ago(days: float) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_check_quarantine_blocks_on_missing_date_by_default(monkeypatch):
    monkeypatch.setattr(core, "audit_log", lambda *args, **kwargs: None)
    monkeypatch.setattr(core, "get_formula_last_modified", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        core, "load_lockfile", lambda: {"version": 1, "updated": "", "packages": {}}
    )

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
    monkeypatch.setattr(
        core, "load_lockfile", lambda: {"version": 1, "updated": "", "packages": {}}
    )

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


def _setup_lockfile_stub(monkeypatch, lf: dict) -> list[dict]:
    saved: list[dict] = []

    def fake_load():
        import copy
        return copy.deepcopy(lf)

    def fake_save(new_lf):
        saved.append(new_lf)
        lf.clear()
        lf.update(new_lf)

    monkeypatch.setattr(core, "load_lockfile", fake_load)
    monkeypatch.setattr(core, "save_lockfile", fake_save)
    monkeypatch.setattr(core, "audit_log", lambda *args, **kwargs: None)
    return saved


def test_quarantine_uses_first_outdated_seen(monkeypatch):
    lf = {
        "version": 1,
        "updated": "",
        "packages": {
            "infisical": {
                "type": "formula",
                "version": "0.43.72",
                "formula_last_commit": _iso_days_ago(0),
                "first_outdated_seen": _iso_days_ago(5),
            }
        },
    }
    _setup_lockfile_stub(monkeypatch, lf)

    ok, lines, code = core.check_quarantine(
        "infisical",
        "formula",
        False,
        {"allowed": {}, "quarantine_days": 3},
    )

    assert ok is True
    assert code == "ok"
    assert any("outdated" in line for line in lines)


def test_quarantine_stamps_when_missing(monkeypatch):
    lf = {
        "version": 1,
        "updated": "",
        "packages": {
            "gh": {
                "type": "formula",
                "version": "2.89.0",
                "formula_last_commit": _iso_days_ago(0),
            }
        },
    }
    saved = _setup_lockfile_stub(monkeypatch, lf)

    ok, lines, code = core.check_quarantine(
        "gh",
        "formula",
        False,
        {"allowed": {}, "quarantine_days": 3},
    )

    assert ok is False
    assert code == "blocked_quarantine"
    assert lf["packages"]["gh"]["first_outdated_seen"]
    assert saved, "lockfile should have been written"


def test_quarantine_preserved_across_version_bump(monkeypatch):
    stamp = _iso_days_ago(5)
    lf = {
        "version": 1,
        "updated": "",
        "packages": {
            "infisical": {
                "type": "formula",
                "version": "0.43.72",
                "formula_last_commit": _iso_days_ago(5),
                "first_outdated_seen": stamp,
            }
        },
    }
    _setup_lockfile_stub(monkeypatch, lf)

    ok_a, _, code_a = core.check_quarantine(
        "infisical",
        "formula",
        False,
        {"allowed": {}, "quarantine_days": 3},
    )

    lf["packages"]["infisical"]["version"] = "0.43.76"
    lf["packages"]["infisical"]["formula_last_commit"] = _iso_days_ago(0)

    ok_b, _, code_b = core.check_quarantine(
        "infisical",
        "formula",
        False,
        {"allowed": {}, "quarantine_days": 3},
    )

    assert ok_a is True and code_a == "ok"
    assert ok_b is True and code_b == "ok"
    assert lf["packages"]["infisical"]["first_outdated_seen"] == stamp


def test_first_outdated_cleared_on_upgrade(monkeypatch):
    lf = {
        "version": 1,
        "updated": "",
        "packages": {
            "infisical": {
                "type": "formula",
                "version": "0.43.72",
                "first_seen": _iso_days_ago(10),
                "first_outdated_seen": _iso_days_ago(5),
            }
        },
    }
    _setup_lockfile_stub(monkeypatch, lf)
    monkeypatch.setattr(core, "get_formula_last_modified", lambda *a, **kw: _iso_days_ago(0))

    info = {
        "formulae": [
            {
                "versions": {"stable": "0.43.76"},
                "bottle": {"stable": {"files": {"sonoma": {"sha256": "b" * 64}}}},
                "urls": {"stable": {"checksum": "s" * 64}},
                "ruby_source_checksum": {"sha256": "r" * 64},
                "tap_git_head": "abc123",
            }
        ]
    }

    core.update_lockfile_entry("infisical", "formula", info)

    entry = lf["packages"]["infisical"]
    assert "first_outdated_seen" not in entry
    assert entry["version"] == "0.43.76"


def test_fresh_install_uses_upstream_age(monkeypatch):
    lf = {"version": 1, "updated": "", "packages": {}}
    _setup_lockfile_stub(monkeypatch, lf)
    monkeypatch.setattr(core, "get_formula_last_modified", lambda *a, **kw: _iso_days_ago(0))

    ok, lines, code = core.check_quarantine(
        "new-pkg",
        "formula",
        False,
        {"allowed": {}, "quarantine_days": 3},
    )

    assert ok is False
    assert code == "blocked_quarantine"
    assert any("modified" in line for line in lines)


def test_baseline_entries_have_no_stamp(monkeypatch):
    lf = {"version": 1, "updated": "", "packages": {}}
    _setup_lockfile_stub(monkeypatch, lf)

    core.batch_update_lockfile(
        [
            {
                "name": "wget",
                "versions": {"stable": "1.0"},
                "bottle": {"stable": {"files": {"sonoma": {"sha256": "a" * 64}}}},
                "urls": {"stable": {"checksum": "s" * 64}},
                "ruby_source_checksum": {"sha256": "r" * 64},
                "tap_git_head": "x",
            }
        ],
        [
            {
                "token": "slack",
                "version": "1",
                "sha256": "c" * 64,
                "url": "https://example.com",
            }
        ],
    )

    assert "first_outdated_seen" not in lf["packages"]["wget"]
    assert "first_outdated_seen" not in lf["packages"]["slack"]


def test_stamp_outdated_seen_batches_unset(monkeypatch):
    existing_stamp = _iso_days_ago(4)
    lf = {
        "version": 1,
        "updated": "",
        "packages": {
            "gh": {"type": "formula", "version": "2.89.0"},
            "infisical": {
                "type": "formula",
                "version": "0.43.72",
                "first_outdated_seen": existing_stamp,
            },
            "nss": {"type": "formula", "version": "3.122"},
        },
    }
    _setup_lockfile_stub(monkeypatch, lf)

    stamped = core.stamp_outdated_seen(["gh", "infisical", "nss", "missing-pkg"])

    assert stamped == 2
    assert lf["packages"]["gh"]["first_outdated_seen"]
    assert lf["packages"]["nss"]["first_outdated_seen"]
    assert lf["packages"]["infisical"]["first_outdated_seen"] == existing_stamp
