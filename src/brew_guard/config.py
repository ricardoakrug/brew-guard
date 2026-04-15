"""Constants, paths, brew detection, JSON I/O, config and lockfile management."""

import difflib
import json
import os
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────
BREW_GUARD_DIR = Path.home() / ".brew-guard"
LOCKFILE = BREW_GUARD_DIR / "lockfile.json"
CONFIG_FILE = BREW_GUARD_DIR / "config.json"
CACHE_DIR = BREW_GUARD_DIR / "cache"
DATE_CACHE = CACHE_DIR / "formula_dates.json"
AUDIT_LOG = CACHE_DIR / "audit.log"
DATE_CACHE_TTL = 3600  # 1 hour

BOTTLE_ARCH_KEYS = [
    "arm64_tahoe",
    "arm64_sequoia",
    "arm64_sonoma",
    "arm64_ventura",
    "tahoe",
    "sequoia",
    "sonoma",
    "ventura",
]

DEFAULT_CONFIG = {
    "quarantine_days": 3,
    "attestation_check": False,
    "strict_attestation": False,
    "strict_no_check_casks": False,
    "block_on_date_resolution_error": True,
    "block_on_lockfile_error": True,
    "allowed": {},
}

# Schema for config validation: key -> expected type
CONFIG_SCHEMA: dict[str, type] = {
    "quarantine_days": int,
    "attestation_check": bool,
    "strict_attestation": bool,
    "strict_no_check_casks": bool,
    "block_on_date_resolution_error": bool,
    "block_on_lockfile_error": bool,
    "allowed": dict,
}


class JsonFileError(RuntimeError):
    """Raised when a persistent JSON state file cannot be trusted."""

    def __init__(self, path: Path, reason: str):
        self.path = path
        self.reason = reason
        super().__init__(f"{path}: {reason}")

# ── Brew Detection ────────────────────────────────────────────────────
_brew_path: str | None = None

BREW_FALLBACK_PATHS = [
    "/opt/homebrew/bin/brew",
    "/usr/local/bin/brew",
    "/home/linuxbrew/.linuxbrew/bin/brew",
]


def find_brew() -> str:
    global _brew_path
    if _brew_path:
        return _brew_path

    found = shutil.which("brew")
    if found:
        real = os.path.realpath(found)
        if "brew-guard" not in real:
            _brew_path = real
            return _brew_path

    for path in BREW_FALLBACK_PATHS:
        if os.path.isfile(path):
            _brew_path = path
            return _brew_path

    print("brew-guard: Cannot find Homebrew. Is it installed?", file=sys.stderr)
    sys.exit(1)


# ── JSON I/O ──────────────────────────────────────────────────────────
def load_json(path: Path, *, invalid_ok: bool = False) -> dict:
    try:
        raw = path.read_text()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        if invalid_ok:
            return {}
        raise JsonFileError(path, f"cannot be read ({exc})") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        if invalid_ok:
            return {}
        raise JsonFileError(path, f"contains invalid JSON ({exc.msg})") from exc

    if not isinstance(data, dict):
        if invalid_ok:
            return {}
        raise JsonFileError(path, "must contain a JSON object")
    return data


def save_json(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    tmp.rename(path)


# ── Time Helpers ──────────────────────────────────────────────────────
def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_to_epoch(iso: str) -> float | None:
    try:
        clean = iso.replace("Z", "+00:00")
        return datetime.fromisoformat(clean).timestamp()
    except (ValueError, TypeError, AttributeError):
        return None


def epoch_now() -> float:
    return time.time()


# ── Config & Lockfile ─────────────────────────────────────────────────
def load_config() -> dict:
    cfg = load_json(CONFIG_FILE)
    for k, v in DEFAULT_CONFIG.items():
        cfg.setdefault(k, v)
    return cfg


def save_config(cfg: dict):
    save_json(CONFIG_FILE, cfg)


def load_lockfile() -> dict:
    lf = load_json(LOCKFILE)
    lf.setdefault("version", 1)
    lf.setdefault("updated", "")
    lf.setdefault("packages", {})
    return lf


def save_lockfile(lf: dict):
    lf["updated"] = now_iso()
    save_json(LOCKFILE, lf)


def get_config(key: str, default=None):
    return load_config().get(key, default)


# ── Init ──────────────────────────────────────────────────────────────
def init():
    BREW_GUARD_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_FILE.exists():
        save_config(DEFAULT_CONFIG.copy())
    if not LOCKFILE.exists():
        save_lockfile({"version": 1, "updated": "", "packages": {}})
    if not DATE_CACHE.exists():
        save_json(DATE_CACHE, {})
    AUDIT_LOG.touch(exist_ok=True)


# ── Config Validation ────────────────────────────────────────────────
def validate_config_key(key: str) -> str | None:
    """Return None if key is valid, or an error message if not."""
    if key in CONFIG_SCHEMA:
        return None
    matches = difflib.get_close_matches(key, CONFIG_SCHEMA.keys(), n=1, cutoff=0.6)
    if matches:
        return f"Unknown config key: {key}. Did you mean '{matches[0]}'?"
    valid = ", ".join(sorted(CONFIG_SCHEMA.keys()))
    return f"Unknown config key: {key}. Valid keys: {valid}"


def validate_config_value(key: str, raw: str) -> tuple[int | bool | str, str | None]:
    """Parse and validate a raw string value for a config key.

    Returns (parsed_value, error_message). error_message is None on success.
    """
    expected = CONFIG_SCHEMA.get(key)
    if expected is int:
        if raw.isdigit():
            return int(raw), None
        return raw, f"'{key}' expects an integer, got '{raw}'"
    if expected is bool:
        if raw in ("true", "false"):
            return raw == "true", None
        return raw, f"'{key}' expects true/false, got '{raw}'"
    return raw, None


# ── Shell Detection ──────────────────────────────────────────────────
SHELL_RC_MAP = {
    "zsh": ".zshrc",
    "bash": ".bashrc",
    "fish": "config.fish",
}

ALIAS_PATTERN = re.compile(r"""alias\s+brew\s*=\s*['"]brew-guard['"]""")
FISH_ABBR_PATTERN = re.compile(r"""abbr\s+.*brew\s+brew-guard""")


def detect_shell() -> str:
    """Return shell name from $SHELL (e.g., 'zsh', 'bash', 'fish')."""
    shell_path = os.environ.get("SHELL", "")
    return os.path.basename(shell_path)


def get_rc_file() -> Path | None:
    """Return path to shell rc file, or None if shell unsupported."""
    shell = detect_shell()
    rc_name = SHELL_RC_MAP.get(shell)
    if not rc_name:
        return None
    if shell == "fish":
        return Path.home() / ".config" / "fish" / rc_name
    return Path.home() / rc_name


def check_alias_in_rc() -> tuple[bool, Path | None]:
    """Check if brew alias exists in shell rc file.

    Returns (alias_found, rc_path).
    """
    rc = get_rc_file()
    if not rc or not rc.exists():
        return False, rc
    content = rc.read_text()
    shell = detect_shell()
    if shell == "fish":
        return bool(FISH_ABBR_PATTERN.search(content)), rc
    return bool(ALIAS_PATTERN.search(content)), rc


def add_alias_to_rc(rc_path: Path) -> bool:
    """Append brew alias to rc file. Returns True on success."""
    shell = detect_shell()
    if shell == "fish":
        line = "abbr --add brew brew-guard"
    else:
        line = "alias brew='brew-guard'"
    with open(rc_path, "a") as f:
        f.write(f"\n# brew-guard: intercept brew commands\n{line}\n")
    return True
