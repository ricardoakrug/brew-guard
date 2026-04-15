"""Core logic: brew interaction, quarantine checks, hash tracking, GitHub queries."""

import json
import subprocess

from brew_guard.config import (
    AUDIT_LOG,
    BOTTLE_ARCH_KEYS,
    DATE_CACHE,
    DATE_CACHE_TTL,
    epoch_now,
    find_brew,
    iso_to_epoch,
    load_config,
    load_json,
    load_lockfile,
    now_iso,
    save_json,
    save_lockfile,
)
from brew_guard.output import audit_log, blue, bold, dim, green, red, yellow


# ── Subprocess Helpers ────────────────────────────────────────────────
def run(cmd: list[str], capture=True, timeout=60) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout)


def brew_info(name: str, is_cask=False) -> dict | None:
    cmd = [find_brew(), "info", "--json=v2"]
    if is_cask:
        cmd.append("--cask")
    cmd.append(name)
    try:
        r = run(cmd)
        if r.returncode == 0:
            return json.loads(r.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    return None


def brew_info_installed(is_cask=False) -> dict:
    cmd = [find_brew(), "info", "--json=v2", "--installed"]
    if is_cask:
        cmd.insert(3, "--cask")
    try:
        r = run(cmd, timeout=120)
        if r.returncode == 0:
            return json.loads(r.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    return {"formulae": [], "casks": []}


def brew_outdated() -> dict:
    try:
        r = run([find_brew(), "outdated", "--json=v2"])
        if r.returncode == 0:
            return json.loads(r.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    return {"formulae": [], "casks": []}


# ── Date Resolution ──────────────────────────────────────────────────
def get_formula_last_modified(name: str, pkg_type: str) -> str | None:
    cache = load_json(DATE_CACHE)
    now_ts = epoch_now()
    entry = cache.get(name)
    if entry and (now_ts - entry.get("fetched_at", 0)) < DATE_CACHE_TTL:
        return entry.get("last_modified")

    letter = name[0].lower()
    if pkg_type == "formula":
        repo = "homebrew/homebrew-core"
        path = f"Formula/{letter}/{name}.rb"
    elif pkg_type == "cask":
        repo = "homebrew/homebrew-cask"
        path = f"Casks/{letter}/{name}.rb"
    else:
        return None

    try:
        r = run(
            [
                "gh",
                "api",
                f"repos/{repo}/commits?path={path}&per_page=1",
                "--jq",
                ".[0].commit.committer.date",
            ],
            timeout=15,
        )
        if r.returncode == 0 and r.stdout.strip():
            last_mod = r.stdout.strip()
            if last_mod == "null" or not last_mod:
                return None
            cache[name] = {"last_modified": last_mod, "fetched_at": now_ts}
            save_json(DATE_CACHE, cache)
            return last_mod
    except subprocess.TimeoutExpired:
        pass
    return None


# ── Bottle SHA Resolution ────────────────────────────────────────────
def get_bottle_sha(formula_info: dict) -> str:
    files = formula_info.get("bottle", {}).get("stable", {}).get("files", {})
    for arch in BOTTLE_ARCH_KEYS:
        sha = files.get(arch, {}).get("sha256", "")
        if sha:
            return sha
    return ""


# ── Type Detection ───────────────────────────────────────────────────
def detect_type(info: dict) -> str:
    if info.get("formulae"):
        return "formula"
    if info.get("casks"):
        return "cask"
    return "unknown"


def get_pkg_data(info: dict, pkg_type: str) -> dict:
    if pkg_type == "formula":
        return info.get("formulae", [{}])[0]
    return info.get("casks", [{}])[0]


# ── Quarantine Check ─────────────────────────────────────────────────
def check_quarantine(name: str, pkg_type: str, force: bool) -> tuple[bool, list[str]]:
    cfg = load_config()
    lines: list[str] = []

    allowed = cfg.get("allowed", {}).get(name)
    if allowed:
        lines.append(f"  {green('ALLOWED')}: {name} ({dim('reason: ' + allowed)})")
        return True, lines

    quarantine_days = cfg.get("quarantine_days", 3)
    last_mod = get_formula_last_modified(name, pkg_type)

    if not last_mod:
        lines.append(f"  {yellow('WARN')}: Cannot determine modification date for {name}")
        audit_log(AUDIT_LOG, "WARN_NO_DATE", name, "modification date unknown")
        return True, lines

    mod_epoch = iso_to_epoch(last_mod)
    age_days = int((epoch_now() - mod_epoch) / 86400)

    if age_days < quarantine_days:
        remaining = quarantine_days - age_days
        lines.append("")
        msg = f"{bold(name)} modified {bold(str(age_days))} day(s) ago"
        lines.append(f"  {red(bold('BLOCKED'))}: {msg}")
        lines.append(f"  Quarantine: {quarantine_days}d | Clear in: {remaining}d")
        lines.append(f"  Last commit: {dim(last_mod)}")
        lines.append("")

        if force:
            lines.append(f"  {yellow('--force: bypassing quarantine')}")
            audit_log(
                AUDIT_LOG,
                "FORCE_QUARANTINE",
                name,
                f"age={age_days}d quarantine={quarantine_days}d",
            )
            return True, lines

        lines.append(f"  Override:  {dim('brew install --force ' + name)}")
        lines.append(f"  Permanent: {dim('brew allow ' + name + ' --reason ...')}")
        audit_log(
            AUDIT_LOG,
            "BLOCKED_QUARANTINE",
            name,
            f"age={age_days}d quarantine={quarantine_days}d",
        )
        return False, lines

    msg = f"{name} modified {age_days}d ago (quarantine: {quarantine_days}d)"
    lines.append(f"  {green('OK')}: {msg}")
    return True, lines


# ── Hash Change Check ────────────────────────────────────────────────
def check_hash_changes(
    name: str, info: dict, pkg_type: str, force: bool
) -> tuple[bool, list[str]]:
    lf = load_lockfile()
    stored = lf.get("packages", {}).get(name)
    if not stored:
        return True, []

    changes: list[str] = []
    pkg_data = get_pkg_data(info, pkg_type)

    if pkg_type == "formula":
        new_bottle = get_bottle_sha(pkg_data)
        new_source = pkg_data.get("urls", {}).get("stable", {}).get("checksum", "")
        new_ruby = pkg_data.get("ruby_source_checksum", {}).get("sha256", "")

        old_bottle = stored.get("sha256_bottle", "")
        old_source = stored.get("sha256_source", "")
        old_ruby = stored.get("ruby_source_sha256", "")

        if old_bottle and new_bottle and old_bottle != new_bottle:
            changes.append(f"bottle SHA256: {old_bottle[:16]}... -> {new_bottle[:16]}...")
        if old_source and new_source and old_source != new_source:
            changes.append(f"source SHA256: {old_source[:16]}... -> {new_source[:16]}...")
        if old_ruby and new_ruby and old_ruby != new_ruby:
            changes.append(f"formula SHA256: {old_ruby[:16]}... -> {new_ruby[:16]}...")
    else:
        new_sha = pkg_data.get("sha256", "")
        new_url = pkg_data.get("url", "")
        old_sha = stored.get("sha256", "")
        old_url = stored.get("url", "")

        if new_sha == "no_check":
            if old_url and new_url and old_url != new_url:
                changes.append(f"URL changed (no_check): {old_url} -> {new_url}")
        elif old_sha and new_sha and old_sha != new_sha:
            changes.append(f"cask SHA256: {old_sha[:16]}... -> {new_sha[:16]}...")

    if not changes:
        return True, []

    lines = [
        "",
        f"  {red(bold('HASH CHANGE'))} detected for {bold(name)}:",
    ]
    for c in changes:
        lines.append(f"    {yellow('->')} {c}")
    lines.append("")
    lines.append("  May be legitimate update or supply chain compromise.")

    if force:
        lines.append(f"  {yellow('--force: accepting new hashes')}")
        audit_log(AUDIT_LOG, "FORCE_HASH_CHANGE", name, "; ".join(changes))
        return True, lines

    audit_log(AUDIT_LOG, "BLOCKED_HASH_CHANGE", name, "; ".join(changes))
    return False, lines


# ── Lockfile Update ──────────────────────────────────────────────────
def update_lockfile_entry(name: str, pkg_type: str, info: dict):
    lf = load_lockfile()
    now = now_iso()
    existing = lf["packages"].get(name, {})
    first_seen = existing.get("first_seen", now)
    last_mod = get_formula_last_modified(name, pkg_type) or "UNKNOWN"
    pkg_data = get_pkg_data(info, pkg_type)

    if pkg_type == "formula":
        entry = {
            "type": "formula",
            "version": pkg_data.get("versions", {}).get("stable", ""),
            "sha256_bottle": get_bottle_sha(pkg_data),
            "sha256_source": pkg_data.get("urls", {}).get("stable", {}).get("checksum", ""),
            "ruby_source_sha256": pkg_data.get("ruby_source_checksum", {}).get("sha256", ""),
            "tap_git_head": pkg_data.get("tap_git_head", ""),
            "formula_last_commit": last_mod,
            "first_seen": first_seen,
            "last_verified": now,
        }
    else:
        entry = {
            "type": "cask",
            "version": pkg_data.get("version", ""),
            "sha256": pkg_data.get("sha256", ""),
            "url": pkg_data.get("url", ""),
            "formula_last_commit": last_mod,
            "first_seen": first_seen,
            "last_verified": now,
        }

    lf["packages"][name] = entry
    save_lockfile(lf)


def batch_update_lockfile(formulae: list[dict], casks: list[dict]) -> tuple[int, int]:
    lf = load_lockfile()
    now = now_iso()

    for f in formulae:
        name = f.get("name", "")
        if not name:
            continue
        existing = lf["packages"].get(name, {})
        lf["packages"][name] = {
            "type": "formula",
            "version": f.get("versions", {}).get("stable", ""),
            "sha256_bottle": get_bottle_sha(f),
            "sha256_source": f.get("urls", {}).get("stable", {}).get("checksum", ""),
            "ruby_source_sha256": f.get("ruby_source_checksum", {}).get("sha256", ""),
            "tap_git_head": f.get("tap_git_head", ""),
            "formula_last_commit": "TRUSTED_BASELINE",
            "first_seen": existing.get("first_seen", now),
            "last_verified": now,
        }

    for c in casks:
        token = c.get("token", "")
        if not token:
            continue
        existing = lf["packages"].get(token, {})
        lf["packages"][token] = {
            "type": "cask",
            "version": c.get("version", ""),
            "sha256": c.get("sha256", ""),
            "url": c.get("url", ""),
            "formula_last_commit": "TRUSTED_BASELINE",
            "first_seen": existing.get("first_seen", now),
            "last_verified": now,
        }

    save_lockfile(lf)
    return len(formulae), len(casks)


# ── Attestation ──────────────────────────────────────────────────────
def verify_attestation(name: str, info: dict) -> tuple[bool, list[str]]:
    lines: list[str] = []
    pkg_data = get_pkg_data(info, "formula")
    bottle_sha = get_bottle_sha(pkg_data)
    if not bottle_sha:
        lines.append(f"  {yellow('ATTEST')}: no bottle SHA found, skipping")
        return True, lines

    lines.append(f"  {blue('ATTEST')}: Verifying {name}...")
    try:
        r = run(
            [
                "gh",
                "attestation",
                "verify",
                f"oci://ghcr.io/homebrew/core/{name}",
                "--owner",
                "homebrew",
            ],
            timeout=30,
        )
        if r.returncode == 0:
            lines.append(f"  {green('ATTEST OK')}")
            return True, lines
        else:
            lines.append(f"  {red('ATTEST FAIL')}")
            return False, lines
    except subprocess.TimeoutExpired:
        lines.append(f"  {yellow('ATTEST TIMEOUT')}")
        return True, lines
