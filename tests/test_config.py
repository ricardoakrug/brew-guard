"""Unit tests for config module pure functions."""

import json
import os
from unittest.mock import patch

from brew_guard.config import (
    check_alias_in_rc,
    detect_shell,
    find_brew,
    get_rc_file,
    iso_to_epoch,
    load_json,
    now_iso,
    save_json,
    validate_config_key,
    validate_config_value,
)


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


# ── Config Validation ────────────────────────────────────────────────


def test_validate_config_key_valid():
    assert validate_config_key("quarantine_days") is None
    assert validate_config_key("attestation_check") is None
    assert validate_config_key("strict_no_check_casks") is None


def test_validate_config_key_unknown():
    err = validate_config_key("nonexistent_key")
    assert err is not None
    assert "Unknown config key" in err


def test_validate_config_key_typo_suggestion():
    err = validate_config_key("quarantine_day")
    assert err is not None
    assert "quarantine_days" in err
    assert "Did you mean" in err


def test_validate_config_value_int():
    val, err = validate_config_value("quarantine_days", "7")
    assert val == 7
    assert err is None


def test_validate_config_value_int_invalid():
    val, err = validate_config_value("quarantine_days", "abc")
    assert err is not None
    assert "integer" in err


def test_validate_config_value_bool():
    val, err = validate_config_value("attestation_check", "true")
    assert val is True
    assert err is None

    val, err = validate_config_value("attestation_check", "false")
    assert val is False
    assert err is None


def test_validate_config_value_bool_invalid():
    val, err = validate_config_value("attestation_check", "yes")
    assert err is not None
    assert "true/false" in err


# ── Shell Detection ──────────────────────────────────────────────────


def test_detect_shell_zsh():
    with patch.dict(os.environ, {"SHELL": "/bin/zsh"}):
        assert detect_shell() == "zsh"


def test_detect_shell_bash():
    with patch.dict(os.environ, {"SHELL": "/bin/bash"}):
        assert detect_shell() == "bash"


def test_detect_shell_fish():
    with patch.dict(os.environ, {"SHELL": "/usr/local/bin/fish"}):
        assert detect_shell() == "fish"


def test_get_rc_file_zsh():
    with patch.dict(os.environ, {"SHELL": "/bin/zsh"}):
        rc = get_rc_file()
        assert rc is not None
        assert rc.name == ".zshrc"


def test_get_rc_file_unsupported():
    with patch.dict(os.environ, {"SHELL": "/bin/csh"}):
        assert get_rc_file() is None


def test_check_alias_in_rc_found(tmp_path):
    rc = tmp_path / ".zshrc"
    rc.write_text("# some config\nalias brew='brew-guard'\n# more config\n")
    with patch("brew_guard.config.get_rc_file", return_value=rc):
        found, path = check_alias_in_rc()
        assert found is True
        assert path == rc


def test_check_alias_in_rc_not_found(tmp_path):
    rc = tmp_path / ".zshrc"
    rc.write_text("# some config\n")
    with patch("brew_guard.config.get_rc_file", return_value=rc):
        found, path = check_alias_in_rc()
        assert found is False


def test_check_alias_in_rc_double_quotes(tmp_path):
    rc = tmp_path / ".zshrc"
    rc.write_text('alias brew="brew-guard"\n')
    with patch("brew_guard.config.get_rc_file", return_value=rc):
        found, _ = check_alias_in_rc()
        assert found is True
