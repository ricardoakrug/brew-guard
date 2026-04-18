"""Core logic: brew interaction, quarantine checks, hash tracking, GitHub queries."""

import json
import subprocess

from brew_guard.config import (
    AUDIT_LOG,
    BOTTLE_ARCH_KEYS,
    DATE_CACHE,
    DATE_CACHE_TTL,
    JsonFileError,
    epoch_now,
    find_brew,
    iso_to_epoch,
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


def brew_outdated(extra_args: list[str] | None = None) -> dict:
    cmd = [find_brew(), "outdated", "--json=v2"]
    if extra_args:
        cmd.extend(extra_args)
    try:
        r = run(cmd)
        if r.returncode == 0:
            return json.loads(r.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    return {"formulae": [], "casks": []}


# ── Date Resolution ──────────────────────────────────────────────────
def _load_date_cache(cache_writes: bool) -> dict:
    try:
        return load_json(DATE_CACHE)
    except JsonFileError:
        if cache_writes:
            save_json(DATE_CACHE, {})
        return {}


def get_formula_last_modified(
    name: str, pkg_type: str, cache_writes: bool = True
) -> str | None:
    if not name:
        return None

    cache = _load_date_cache(cache_writes)
    now_ts = epoch_now()
    entry = cache.get(name)
    if entry and (now_ts - entry.get("fetched_at", 0)) < DATE_CACHE_TTL:
        cached_last_mod = entry.get("last_modified")
        if iso_to_epoch(cached_last_mod) is not None:
            return cached_last_mod

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
            if last_mod != "null" and iso_to_epoch(last_mod) is not None:
                if cache_writes:
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
def _get_tracked_entry(name: str) -> dict | None:
    try:
        lf = load_lockfile()
    except JsonFileError:
        return None
    return lf.get("packages", {}).get(name)


def _stamp_first_outdated_seen(name: str) -> str | None:
    try:
        lf = load_lockfile()
    except JsonFileError:
        return None
    entry = lf.get("packages", {}).get(name)
    if not entry:
        return None
    stamp = entry.get("first_outdated_seen")
    if stamp:
        return stamp
    stamp = now_iso()
    entry["first_outdated_seen"] = stamp
    try:
        save_lockfile(lf)
    except JsonFileError:
        return None
    return stamp


def check_quarantine(
    name: str,
    pkg_type: str,
    force: bool,
    cfg: dict,
    *,
    cache_writes: bool = True,
) -> tuple[bool, list[str], str]:
    lines: list[str] = []

    allowed = cfg.get("allowed", {}).get(name)
    if allowed:
        lines.append(f"  {green('ALLOWED')}: {name} ({dim('reason: ' + allowed)})")
        return True, lines, "allowed"

    quarantine_days = cfg.get("quarantine_days", 3)
    tracked = _get_tracked_entry(name)

    if tracked is not None:
        stamp = tracked.get("first_outdated_seen") or _stamp_first_outdated_seen(name)
        stamp_epoch = iso_to_epoch(stamp) if stamp else None
        if stamp_epoch is None:
            stamp_epoch = epoch_now()
        age_days = int((epoch_now() - stamp_epoch) / 86400)
        return _evaluate_quarantine_age(
            name,
            age_days,
            quarantine_days,
            force,
            source="outdated",
            detail=f"first seen outdated: {dim(stamp)}" if stamp else "",
        )

    last_mod = get_formula_last_modified(name, pkg_type, cache_writes=cache_writes)
    mod_epoch = iso_to_epoch(last_mod) if last_mod else None

    if mod_epoch is None:
        reason = "modification date unavailable"
        block_on_error = cfg.get("block_on_date_resolution_error", True)

        if force:
            lines.append(f"  {yellow('--force: bypassing modification-date verification')}")
            lines.append(f"  {yellow('WARN')}: Cannot determine modification date for {name}")
            audit_log(AUDIT_LOG, "FORCE_NO_DATE", name, reason)
            return True, lines, "forced_no_date"

        if block_on_error:
            lines.append("")
            lines.append(f"  {red(bold('BLOCKED'))}: Cannot determine modification date for {name}")
            lines.append("  brew-guard cannot verify quarantine age.")
            lines.append(f"  Repair: {dim('check gh auth status or try again later')}")
            lines.append(f"  Override: {dim('brew install --force ' + name)}")
            audit_log(AUDIT_LOG, "BLOCKED_NO_DATE", name, reason)
            return False, lines, "blocked_no_date"

        lines.append(f"  {yellow('WARN')}: Cannot determine modification date for {name}")
        audit_log(AUDIT_LOG, "WARN_NO_DATE", name, reason)
        return True, lines, "warn_no_date"

    age_days = int((epoch_now() - mod_epoch) / 86400)
    return _evaluate_quarantine_age(
        name,
        age_days,
        quarantine_days,
        force,
        source="upstream",
        detail=f"Last commit: {dim(last_mod)}",
    )


def _evaluate_quarantine_age(
    name: str,
    age_days: int,
    quarantine_days: int,
    force: bool,
    *,
    source: str,
    detail: str,
) -> tuple[bool, list[str], str]:
    lines: list[str] = []
    phrase = "outdated" if source == "outdated" else "modified"

    if age_days < quarantine_days:
        remaining = quarantine_days - age_days
        lines.append("")
        msg = f"{bold(name)} {phrase} {bold(str(age_days))} day(s) ago"
        lines.append(f"  {red(bold('BLOCKED'))}: {msg}")
        lines.append(f"  Quarantine: {quarantine_days}d | Clear in: {remaining}d")
        if detail:
            lines.append(f"  {detail}")
        lines.append("")

        if force:
            lines.append(f"  {yellow('--force: bypassing quarantine')}")
            audit_log(
                AUDIT_LOG,
                "FORCE_QUARANTINE",
                name,
                f"{phrase}={age_days}d quarantine={quarantine_days}d",
            )
            return True, lines, "forced_quarantine"

        lines.append(f"  Override:  {dim('brew install --force ' + name)}")
        lines.append(f"  Permanent: {dim('brew allow ' + name + ' --reason ...')}")
        audit_log(
            AUDIT_LOG,
            "BLOCKED_QUARANTINE",
            name,
            f"{phrase}={age_days}d quarantine={quarantine_days}d",
        )
        return False, lines, "blocked_quarantine"

    msg = f"{name} {phrase} {age_days}d ago (quarantine: {quarantine_days}d)"
    lines.append(f"  {green('OK')}: {msg}")
    return True, lines, "ok"


# ── Hash Change Check ────────────────────────────────────────────────
def check_hash_changes(
    name: str, info: dict, pkg_type: str, force: bool, cfg: dict
) -> tuple[bool, list[str], str]:
    try:
        lf = load_lockfile()
    except JsonFileError as exc:
        detail = f"{exc.path}: {exc.reason}"
        block_on_error = cfg.get("block_on_lockfile_error", True)

        if force:
            lines = [
                f"  {yellow('--force: bypassing lockfile verification')}",
                f"  {yellow('WARN')}: Cannot read lockfile ({detail})",
            ]
            audit_log(AUDIT_LOG, "FORCE_LOCKFILE", name, detail)
            return True, lines, "forced_lockfile_error"

        if block_on_error:
            lines = [
                "",
                f"  {red(bold('BLOCKED'))}: Cannot read lockfile for {bold(name)}",
                f"  {dim(detail)}",
                f"  Repair: {dim('fix or replace ~/.brew-guard/lockfile.json, then rerun')}",
            ]
            audit_log(AUDIT_LOG, "BLOCKED_LOCKFILE", name, detail)
            return False, lines, "blocked_lockfile_error"

        lines = [f"  {yellow('WARN')}: Cannot read lockfile ({detail}); treating as untracked"]
        audit_log(AUDIT_LOG, "WARN_LOCKFILE", name, detail)
        return True, lines, "warn_lockfile_error"

    stored = lf.get("packages", {}).get(name)
    if not stored:
        return True, [], "ok"

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
        return True, [], "ok"

    lines = [
        "",
        f"  {red(bold('HASH CHANGE'))} detected for {bold(name)}:",
    ]
    for change in changes:
        lines.append(f"    {yellow('->')} {change}")
    lines.append("")
    lines.append("  May be legitimate update or supply chain compromise.")

    if force:
        lines.append(f"  {yellow('--force: accepting new hashes')}")
        audit_log(AUDIT_LOG, "FORCE_HASH_CHANGE", name, "; ".join(changes))
        return True, lines, "forced_hash_change"

    audit_log(AUDIT_LOG, "BLOCKED_HASH_CHANGE", name, "; ".join(changes))
    return False, lines, "blocked_hash_change"


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


def stamp_outdated_seen(names: list[str]) -> int:
    """Stamp first_outdated_seen=now on any tracked entries that lack it.

    Returns number of entries newly stamped. Silent on lockfile errors
    (check_hash_changes reports those via its own code path).
    """
    if not names:
        return 0
    try:
        lf = load_lockfile()
    except JsonFileError:
        return 0
    now = now_iso()
    stamped = 0
    for name in names:
        entry = lf.get("packages", {}).get(name)
        if not entry:
            continue
        if entry.get("first_outdated_seen"):
            continue
        entry["first_outdated_seen"] = now
        stamped += 1
    if stamped:
        try:
            save_lockfile(lf)
        except JsonFileError:
            return 0
    return stamped


def batch_update_lockfile(formulae: list[dict], casks: list[dict]) -> tuple[int, int]:
    lf = load_lockfile()
    now = now_iso()

    for formula in formulae:
        name = formula.get("name", "")
        if not name:
            continue
        existing = lf["packages"].get(name, {})
        lf["packages"][name] = {
            "type": "formula",
            "version": formula.get("versions", {}).get("stable", ""),
            "sha256_bottle": get_bottle_sha(formula),
            "sha256_source": formula.get("urls", {}).get("stable", {}).get("checksum", ""),
            "ruby_source_sha256": formula.get("ruby_source_checksum", {}).get("sha256", ""),
            "tap_git_head": formula.get("tap_git_head", ""),
            "formula_last_commit": "TRUSTED_BASELINE",
            "first_seen": existing.get("first_seen", now),
            "last_verified": now,
        }

    for cask in casks:
        token = cask.get("token", "")
        if not token:
            continue
        existing = lf["packages"].get(token, {})
        lf["packages"][token] = {
            "type": "cask",
            "version": cask.get("version", ""),
            "sha256": cask.get("sha256", ""),
            "url": cask.get("url", ""),
            "formula_last_commit": "TRUSTED_BASELINE",
            "first_seen": existing.get("first_seen", now),
            "last_verified": now,
        }

    save_lockfile(lf)
    return len(formulae), len(casks)


# ── Attestation ──────────────────────────────────────────────────────
def verify_attestation(name: str, info: dict) -> tuple[bool, list[str], str]:
    lines: list[str] = []
    pkg_data = get_pkg_data(info, "formula")
    bottle_sha = get_bottle_sha(pkg_data)
    if not bottle_sha:
        lines.append(f"  {yellow('ATTEST')}: no bottle SHA found, skipping")
        return True, lines, "skip"

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
    except subprocess.TimeoutExpired:
        lines.append(f"  {red('ATTEST TIMEOUT')}")
        return False, lines, "timeout"

    if r.returncode == 0:
        lines.append(f"  {green('ATTEST OK')}")
        return True, lines, "ok"

    lines.append(f"  {red('ATTEST FAIL')}")
    stderr = r.stderr.strip()
    if stderr:
        lines.append(f"  {dim(stderr.splitlines()[0])}")
    return False, lines, "failure"
