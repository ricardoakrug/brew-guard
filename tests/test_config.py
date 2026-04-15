"""Unit tests for config module pure functions."""

import json
import os
from pathlib import Path
from unittest.mock import patch

from brew_guard.config import find_brew, iso_to_epoch, load_json, now_iso, save_json


def test_load_json_valid(tmp_path):
    f = tmp_path / "test.json"
    f.write_text('{"key": "value"}')
    assert load_json(f) == {"key": "value"}


def test_load_json_missing(tmp_path):
    f = tmp_path / "missing.json"
    assert load_json(f) == {}


def test_load_json_invalid(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("not json")
    assert load_json(f) == {}


def test_save_json_roundtrip(tmp_path):
    f = tmp_path / "out.json"
    data = {"packages": {"wget": {"version": "1.21"}}}
    save_json(f, data)
    assert json.loads(f.read_text()) == data


def test_save_json_atomic(tmp_path):
    f = tmp_path / "out.json"
    save_json(f, {"a": 1})
    # tmp file should not remain
    assert not (tmp_path / "out.tmp").exists()


def test_iso_to_epoch_valid():
    epoch = iso_to_epoch("2025-01-01T00:00:00Z")
    assert epoch > 0
    assert isinstance(epoch, float)


def test_iso_to_epoch_invalid():
    assert iso_to_epoch("not-a-date") == 0
    assert iso_to_epoch(None) == 0


def test_now_iso_format():
    ts = now_iso()
    assert ts.endswith("Z")
    assert "T" in ts


def test_find_brew_with_which():
    with patch("shutil.which", return_value="/opt/homebrew/bin/brew"):
        with patch("os.path.realpath", return_value="/opt/homebrew/bin/brew"):
            # Reset cached value
            import brew_guard.config

            brew_guard.config._brew_path = None
            result = find_brew()
            assert result == "/opt/homebrew/bin/brew"
            brew_guard.config._brew_path = None


def test_find_brew_skips_self():
    with patch("shutil.which", return_value="/usr/local/bin/brew-guard"):
        with patch("os.path.realpath", return_value="/usr/local/bin/brew-guard"):
            with patch("os.path.isfile", side_effect=lambda p: p == "/opt/homebrew/bin/brew"):
                import brew_guard.config

                brew_guard.config._brew_path = None
                result = find_brew()
                assert result == "/opt/homebrew/bin/brew"
                brew_guard.config._brew_path = None
