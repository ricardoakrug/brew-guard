"""Tests for CLI orchestration and zero-write behavior."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from brew_guard import cli


def test_split_protected_args_preserves_option_values():
    parsed = cli._split_protected_args(
        ["--cask", "--language", "en-US", "iterm2", "--greedy", "--", "--literal"]
    )

    assert parsed.flags == ["--cask", "--language", "en-US", "--greedy"]
    assert parsed.packages == ["iterm2", "--literal"]


def test_main_help_does_not_initialize(monkeypatch):
    init_calls: list[str] = []
    monkeypatch.setattr(cli, "init", lambda: init_calls.append("init"))
    monkeypatch.setattr(sys, "argv", ["brew-guard", "help"])

    cli.main()

    assert init_calls == []


def test_main_passthrough_does_not_initialize(monkeypatch):
    init_calls: list[str] = []
    passthrough_calls: list[tuple[str, str | None, list[str] | None]] = []

    monkeypatch.setattr(cli, "init", lambda: init_calls.append("init"))
    monkeypatch.setattr(cli, "find_brew", lambda: "/opt/homebrew/bin/brew")

    def fake_passthrough(real_brew, subcmd=None, args=None):
        passthrough_calls.append((real_brew, subcmd, args))

    monkeypatch.setattr(
        cli,
        "_run_passthrough",
        fake_passthrough,
    )
    monkeypatch.setattr(sys, "argv", ["brew-guard", "search", "wget"])

    cli.main()

    assert init_calls == []
    assert passthrough_calls == [("/opt/homebrew/bin/brew", "search", ["wget"])]


def test_cmd_upgrade_partially_upgrades_clear_packages_and_preserves_flags(monkeypatch):
    run_calls: list[tuple[str, str, list[str]]] = []
    refreshed: list[list[str]] = []
    outdated_args: list[list[str]] = []

    monkeypatch.setattr(cli, "init", lambda: None)
    monkeypatch.setattr(cli, "find_brew", lambda: "/opt/homebrew/bin/brew")
    monkeypatch.setattr(cli, "_load_config_or_exit", lambda: {})
    monkeypatch.setattr(
        cli,
        "brew_outdated",
        lambda args=None: (
            outdated_args.append(args or [])
            or {
                "formulae": [],
                "casks": [{"name": "google-chrome"}, {"name": "iterm2"}],
            }
        ),
    )

    def fake_evaluate(name, cfg, *, force, requested_type=None, cache_writes=True):
        assert requested_type == "cask"
        if name == "google-chrome":
            return cli.PackageCheck(name, "cask", {"casks": [{}]}, True, "OK")
        return cli.PackageCheck(name, "cask", {"casks": [{}]}, False, "BLOCKED")

    monkeypatch.setattr(cli, "_evaluate_package", fake_evaluate)
    monkeypatch.setattr(
        cli,
        "_run_brew_command",
        lambda real_brew, subcmd, args: run_calls.append((real_brew, subcmd, args)) or 0,
    )
    monkeypatch.setattr(
        cli,
        "_refresh_tracked_packages",
        lambda packages: refreshed.append([package.name for package in packages]),
    )

    with pytest.raises(SystemExit) as exc:
        cli.cmd_upgrade(["--cask", "--greedy", "--language", "en-US"])

    assert exc.value.code == 0
    assert outdated_args == [["--cask", "--greedy"]]
    assert run_calls == [
        (
            "/opt/homebrew/bin/brew",
            "upgrade",
            ["--cask", "--greedy", "--language", "en-US", "google-chrome"],
        )
    ]
    assert refreshed == [["google-chrome"]]


def test_cmd_install_dry_run_does_not_refresh_state(monkeypatch):
    refreshed: list[str] = []

    monkeypatch.setattr(cli, "init", lambda: None)
    monkeypatch.setattr(cli, "find_brew", lambda: "/opt/homebrew/bin/brew")
    monkeypatch.setattr(cli, "_load_config_or_exit", lambda: {})

    def fake_evaluate(*args, **kwargs):
        return cli.PackageCheck("ripgrep", "formula", {"formulae": [{}]}, True, "OK")

    monkeypatch.setattr(
        cli,
        "_evaluate_package",
        fake_evaluate,
    )
    monkeypatch.setattr(cli, "_run_brew_command", lambda real_brew, subcmd, args: 0)
    monkeypatch.setattr(
        cli,
        "_refresh_tracked_packages",
        lambda packages: refreshed.extend(package.name for package in packages),
    )

    with pytest.raises(SystemExit) as exc:
        cli.cmd_install("install", ["--dry-run", "ripgrep"])

    assert exc.value.code == 0
    assert refreshed == []


def test_help_subprocess_does_not_create_state_files(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    home_dir = tmp_path / "home"
    env = os.environ.copy()
    env["HOME"] = str(home_dir)
    env["PYTHONPATH"] = str(repo_root / "src")

    result = subprocess.run(
        [sys.executable, "-m", "brew_guard", "help"],
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert not (home_dir / ".brew-guard").exists()
