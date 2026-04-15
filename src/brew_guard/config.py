"""Constants, paths, brew detection, JSON I/O, config and lockfile management."""

import json
import os
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
    "allowed": {},
}

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
def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_json(path: Path, data: dict):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    tmp.rename(path)


# ── Time Helpers ──────────────────────────────────────────────────────
def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_to_epoch(iso: str) -> float:
    try:
        clean = iso.replace("Z", "+00:00")
        return datetime.fromisoformat(clean).timestamp()
    except (ValueError, TypeError, AttributeError):
        return 0


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
