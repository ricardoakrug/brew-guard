"""CLI entry point: command dispatch and all user-facing commands."""

import json
import os
import sys

from brew_guard.config import (
    AUDIT_LOG,
    BREW_GUARD_DIR,
    CONFIG_FILE,
    LOCKFILE,
    epoch_now,
    find_brew,
    get_config,
    init,
    iso_to_epoch,
    load_config,
    load_lockfile,
    save_config,
)
from brew_guard.core import (
    batch_update_lockfile,
    brew_info,
    brew_info_installed,
    brew_outdated,
    check_hash_changes,
    check_quarantine,
    detect_type,
    get_formula_last_modified,
    get_pkg_data,
    update_lockfile_entry,
    verify_attestation,
)
from brew_guard.output import audit_log, blue, bold, dim, green, red, yellow


# ── Commands ─────────────────────────────────────────────────────────
def cmd_setup():
    from brew_guard.core import run

    print(f"{bold('brew-guard setup')}: Initializing...")
    init()
    print(f"  Created {BREW_GUARD_DIR}/")

    r = run(["gh", "auth", "status"], timeout=10)
    if r.returncode == 0:
        print(f"  {green('OK')}: gh authenticated")
    else:
        print(f"  {yellow('WARN')}: gh not authenticated (rate limit: 60 req/hr)")
        print("  Run: gh auth login")

    print("  Scanning installed formulae...")
    installed = brew_info_installed()
    formulae = installed.get("formulae", [])

    print("  Scanning installed casks...")
    cask_data = brew_info_installed(is_cask=True)
    casks = cask_data.get("casks", [])

    fc, cc = batch_update_lockfile(formulae, casks)

    print()
    print(f"{green('Setup complete.')}")
    print(f"  {fc} formulae + {cc} casks recorded in lockfile")
    print(f"  Dates: {blue('TRUSTED_BASELINE')} (existing installs trusted)")
    print("  Future installs/upgrades query GitHub for modification dates")
    print(f"  Config:   {CONFIG_FILE}")
    print(f"  Lockfile: {LOCKFILE}")
    print()
    print("  Add this alias to your shell config:")
    print("    alias brew='brew-guard'")


def cmd_install(subcmd: str, args: list[str]):
    force = "--force" in args
    is_cask = "--cask" in args
    packages = [a for a in args if not a.startswith("-")]
    real_brew = find_brew()

    if not packages:
        sys.stdout.flush()
        os.execv(real_brew, [real_brew, subcmd] + args)

    blocked: list[str] = []
    passed: list[str] = []

    for pkg in packages:
        print(f"{bold('brew-guard')}: Checking {bold(pkg)}...")

        info = brew_info(pkg, is_cask=is_cask)
        if not info:
            print(f"  {red('ERROR')}: Cannot fetch brew info for {pkg}")
            blocked.append(pkg)
            continue

        pkg_type = "cask" if is_cask else detect_type(info)
        if pkg_type == "unknown":
            print(f"  {red('ERROR')}: Cannot determine type for {pkg}")
            blocked.append(pkg)
            continue

        pkg_data = get_pkg_data(info, pkg_type)

        # Check 1: Quarantine
        ok, lines = check_quarantine(pkg, pkg_type, force)
        for line in lines:
            print(line)
        if not ok:
            blocked.append(pkg)
            continue

        # Check 2: Hash changes
        ok, lines = check_hash_changes(pkg, info, pkg_type, force)
        for line in lines:
            print(line)
        if not ok:
            blocked.append(pkg)
            continue

        # Check 3: no_check cask warning
        if pkg_type == "cask" and pkg_data.get("sha256") == "no_check":
            print(f"  {yellow('WARN')}: {pkg} has sha256:no_check — integrity unverifiable")
            if get_config("strict_no_check_casks", False) and not force:
                print(f"  {red('BLOCKED')}: strict_no_check_casks enabled")
                audit_log(AUDIT_LOG, "BLOCKED_NO_CHECK", pkg, "sha256:no_check")
                blocked.append(pkg)
                continue

        # Check 4: Attestation (optional)
        if get_config("attestation_check", False) and pkg_type == "formula":
            ok, lines = verify_attestation(pkg, info)
            for line in lines:
                print(line)
            if not ok and get_config("strict_attestation", False) and not force:
                blocked.append(pkg)
                continue

        update_lockfile_entry(pkg, pkg_type, info)
        audit_log(AUDIT_LOG, "PASSED", pkg, "all checks ok")
        passed.append(pkg)

    if blocked and not force:
        print()
        print(f"{red('brew-guard')}: {len(blocked)} package(s) blocked. Use --force to bypass.")
        sys.exit(1)

    print()
    print(f"{green('brew-guard')}: All checks passed. Installing...")
    sys.stdout.flush()
    os.execv(real_brew, [real_brew, subcmd] + args)


def cmd_upgrade(args: list[str]):
    force = "--force" in args
    packages = [a for a in args if not a.startswith("-")]
    passthrough_args = args[:]
    real_brew = find_brew()

    if packages:
        cmd_install("upgrade", args)
        return

    outdated = brew_outdated()
    outdated_formulae = outdated.get("formulae", [])
    outdated_casks = outdated.get("casks", [])

    total = len(outdated_formulae) + len(outdated_casks)
    if total == 0:
        print(f"{bold('brew-guard')}: Everything up to date.")
        return

    print(f"{bold('brew-guard')}: Checking {total} outdated package(s)...\n")

    rows: list[tuple[str, str, str, str, str]] = []
    blocked_names: list[str] = []
    clear_names: list[str] = []

    cfg = load_config()
    quarantine_days = cfg.get("quarantine_days", 3)

    for f in outdated_formulae:
        name = f.get("name", "")
        installed_versions = f.get("installed_versions", [])
        installed_ver = installed_versions[0] if installed_versions else ""
        current_ver = f.get("current_version", "")

        last_mod = get_formula_last_modified(name, "formula")
        if last_mod:
            age_days = int((epoch_now() - iso_to_epoch(last_mod)) / 86400)
            age_str = f"{age_days}d"
        else:
            age_days = 999
            age_str = "?"

        allowed = cfg.get("allowed", {}).get(name)

        if allowed:
            status = green("ALLOWED")
            clear_names.append(name)
        elif age_days < quarantine_days:
            remaining = quarantine_days - age_days
            status = red(f"QUARANTINE ({remaining}d remaining)")
            blocked_names.append(name)
        else:
            status = green("OK")
            clear_names.append(name)

        rows.append((name, installed_ver, current_ver, age_str, status))

    for c in outdated_casks:
        name = c.get("name", "")
        installed_ver = (
            c.get("installed_versions", [""])[0] if c.get("installed_versions") else ""
        )
        current_ver = c.get("current_version", "")

        last_mod = get_formula_last_modified(name, "cask")
        if last_mod:
            age_days = int((epoch_now() - iso_to_epoch(last_mod)) / 86400)
            age_str = f"{age_days}d"
        else:
            age_days = 999
            age_str = "?"

        allowed = cfg.get("allowed", {}).get(name)

        if allowed:
            status = green("ALLOWED")
            clear_names.append(name)
        elif age_days < quarantine_days:
            remaining = quarantine_days - age_days
            status = red(f"QUARANTINE ({remaining}d remaining)")
            blocked_names.append(name)
        else:
            status = green("OK")
            clear_names.append(name)

        rows.append((name, installed_ver, current_ver, age_str, status))

    # Print table
    col_w = [
        max(len("PACKAGE"), max((len(r[0]) for r in rows), default=7)),
        max(len("INSTALLED"), max((len(r[1]) for r in rows), default=9)),
        max(len("AVAILABLE"), max((len(r[2]) for r in rows), default=9)),
        max(len("AGE"), max((len(r[3]) for r in rows), default=3)),
    ]

    header = (
        f"  {bold('PACKAGE'):<{col_w[0]+9}s} "
        f"{bold('INSTALLED'):<{col_w[1]+9}s} "
        f"{bold('AVAILABLE'):<{col_w[2]+9}s} "
        f"{bold('AGE'):<{col_w[3]+9}s} "
        f"{bold('STATUS')}"
    )
    print(header)
    print(f"  {'─' * col_w[0]} {'─' * col_w[1]} {'─' * col_w[2]} {'─' * col_w[3]} {'─' * 20}")

    for name, inst, avail, age, status in rows:
        print(
            f"  {name:<{col_w[0]}s} "
            f"{dim(inst):<{col_w[1]+9}s} "
            f"{avail:<{col_w[2]}s} "
            f"{age:<{col_w[3]}s} "
            f"{status}"
        )

    print()
    if blocked_names:
        print(
            f"  {bold('Summary')}: {green(str(len(clear_names)))} clear, "
            f"{red(str(len(blocked_names)))} quarantined"
        )
        for name in blocked_names:
            audit_log(AUDIT_LOG, "BLOCKED_QUARANTINE", name, f"quarantine={quarantine_days}d")
        if not force:
            print(f"  Quarantined packages must age past {quarantine_days} days.")
            print(f"  Override: {dim('brew upgrade --force')}")
    else:
        print(f"  {bold('Summary')}: {green('All ' + str(len(clear_names)) + ' packages clear')}")

    if force:
        print()
        print(f"{yellow('--force')}: Upgrading all {total} packages...")
        for name in blocked_names:
            audit_log(
                AUDIT_LOG, "FORCE_QUARANTINE", name, f"quarantine={quarantine_days}d forced"
            )
        sys.stdout.flush()
        os.execv(real_brew, [real_brew, "upgrade"] + passthrough_args)
    elif clear_names:
        print()
        print(f"{green('brew-guard')}: Upgrading {len(clear_names)} clear package(s)...")
        sys.stdout.flush()
        os.execv(real_brew, [real_brew, "upgrade"] + clear_names)
    else:
        print()
        print(f"{red('brew-guard')}: All outdated packages are quarantined. Nothing to upgrade.")
        sys.exit(1)


def cmd_status():
    lf = load_lockfile()
    if not lf.get("packages"):
        print("No lockfile found. Run: brew-guard setup")
        sys.exit(1)

    cfg = load_config()
    quarantine_days = cfg.get("quarantine_days", 3)
    now_ts = epoch_now()

    print(f"{bold('brew-guard status')} (quarantine: {quarantine_days} days)\n")

    rows: list[tuple[str, str, str, str, str]] = []
    for name, pkg in sorted(lf["packages"].items()):
        pkg_type = pkg.get("type", "?")
        version = pkg.get("version", "?")
        last_mod = pkg.get("formula_last_commit", "")

        if not last_mod or last_mod in ("UNKNOWN", "TRUSTED_BASELINE"):
            age_str = "--"
            status = blue("baseline")
        else:
            mod_epoch = iso_to_epoch(last_mod)
            age_days = int((now_ts - mod_epoch) / 86400)
            age_str = str(age_days)
            if age_days < quarantine_days:
                status = red("QUARANTINE")
            else:
                status = green("ok")

        rows.append((name, pkg_type, version, age_str, status))

    col_w = [
        max(len("PACKAGE"), max((len(r[0]) for r in rows), default=7)),
        max(len("TYPE"), max((len(r[1]) for r in rows), default=4)),
        max(len("VERSION"), max((len(r[2]) for r in rows), default=7)),
        max(len("AGE"), max((len(r[3]) for r in rows), default=3)),
    ]

    print(
        f"  {bold('PACKAGE'):<{col_w[0]+9}s} "
        f"{bold('TYPE'):<{col_w[1]+9}s} "
        f"{bold('VERSION'):<{col_w[2]+9}s} "
        f"{bold('AGE'):<{col_w[3]+9}s} "
        f"{bold('STATUS')}"
    )
    print(f"  {'─' * col_w[0]} {'─' * col_w[1]} {'─' * col_w[2]} {'─' * col_w[3]} {'─' * 12}")

    for name, ptype, ver, age, status in rows:
        print(
            f"  {name:<{col_w[0]}s} "
            f"{dim(ptype):<{col_w[1]+9}s} "
            f"{ver:<{col_w[2]}s} "
            f"{age:<{col_w[3]}s} "
            f"{status}"
        )


def cmd_audit():
    lf = load_lockfile()
    if not lf.get("packages"):
        print("No lockfile found. Run: brew-guard setup")
        sys.exit(1)

    print(f"{bold('brew-guard audit')}: Re-checking all installed packages...\n")

    issues = 0
    checked = 0

    for name, pkg in sorted(lf["packages"].items()):
        pkg_type = pkg.get("type", "formula")
        is_cask = pkg_type == "cask"
        info = brew_info(name, is_cask=is_cask)
        if not info:
            continue

        checked += 1
        ok, lines = check_hash_changes(name, info, pkg_type, force=False)
        if not ok:
            issues += 1
            for line in lines:
                print(line)

    print()
    if issues:
        print(
            f"{bold('Audit complete.')}: "
            f"{red(str(issues))} hash change(s) detected in {checked} packages"
        )
    else:
        print(f"{bold('Audit complete.')}: {green('No issues')} in {checked} packages")


def cmd_verify(name: str):
    if not name:
        print("Usage: brew-guard verify <package>")
        sys.exit(1)

    print(f"{bold('brew-guard verify')}: {bold(name)}\n")

    lf = load_lockfile()
    stored = lf.get("packages", {}).get(name)
    if not stored:
        print(f"  {yellow('NOT TRACKED')}: {name} not in lockfile")
        print("  Run: brew-guard setup")
        sys.exit(1)

    pkg_type = stored.get("type", "formula")
    is_cask = pkg_type == "cask"
    info = brew_info(name, is_cask=is_cask)

    ok, lines = check_quarantine(name, pkg_type, force=False)
    for line in lines:
        print(line)

    if info:
        ok, lines = check_hash_changes(name, info, pkg_type, force=False)
        for line in lines:
            print(line)

    print(f"\n  {blue('Lockfile entry')}:")
    for k, v in sorted(stored.items()):
        val_str = str(v)
        if len(val_str) > 60:
            val_str = val_str[:57] + "..."
        print(f"    {dim(k)}: {val_str}")


def cmd_allow(args: list[str]):
    name = None
    reason = None
    i = 0
    while i < len(args):
        if args[i] == "--reason" and i + 1 < len(args):
            reason = args[i + 1]
            i += 2
        elif not args[i].startswith("-"):
            name = args[i]
            i += 1
        else:
            i += 1

    if not name:
        print("Usage: brew-guard allow <package> --reason 'why'")
        sys.exit(1)
    if not reason:
        print("Must provide --reason")
        sys.exit(1)

    cfg = load_config()
    cfg["allowed"][name] = reason
    save_config(cfg)
    print(f"{green('Allowed')}: {bold(name)} ({dim(reason)})")
    audit_log(AUDIT_LOG, "ALLOW", name, reason)


def cmd_config(args: list[str]):
    action = args[0] if args else ""
    cfg = load_config()

    if action == "get":
        key = args[1] if len(args) > 1 else ""
        if key:
            val = cfg.get(key)
            if val is not None:
                print(f"{key} = {json.dumps(val)}")
            else:
                print(f"Unknown key: {key}")
        else:
            print(json.dumps(cfg, indent=2))
    elif action == "set":
        if len(args) < 3:
            print("Usage: brew-guard config set <key> <value>")
            sys.exit(1)
        key, raw_val = args[1], args[2]
        if raw_val.isdigit():
            val: str | int | bool = int(raw_val)
        elif raw_val in ("true", "false"):
            val = raw_val == "true"
        else:
            val = raw_val
        cfg[key] = val
        save_config(cfg)
        print(f"Set {bold(key)} = {json.dumps(val)}")
    else:
        print(json.dumps(cfg, indent=2))


def cmd_help():
    print(f"""{bold('brew-guard')}: Supply chain protection for Homebrew

{bold('Usage')}: brew-guard <command> [args]

{bold('Protected commands')}:
  install <pkg> [--force] [--cask]  Install with quarantine + hash checks
  upgrade [<pkg>] [--force]         Upgrade with checks (partial upgrade if some quarantined)

{bold('Management')}:
  setup                             Initialize and scan installed packages
  status                            Show all packages with age info
  audit                             Re-check all installed for hash changes
  verify <pkg>                      Deep-check single package
  allow <pkg> --reason '...'        Permanently bypass quarantine
  config [get|set] [key] [value]    View/change configuration

All other commands pass through to brew.

{bold('Config keys')}:
  quarantine_days {dim('(default: 3)')}      Days before formula update is trusted
  attestation_check {dim('(default: false)')} Verify Sigstore attestations
  strict_attestation {dim('(default: false)')}Block on attestation failure
  strict_no_check_casks {dim('(default: false)')}Block casks with sha256:no_check""")


# ── Main ─────────────────────────────────────────────────────────────
def main():
    init()

    if len(sys.argv) < 2:
        real_brew = find_brew()
        sys.stdout.flush()
        os.execv(real_brew, [real_brew])

    subcmd = sys.argv[1]
    rest = sys.argv[2:]

    dispatch = {
        "install": lambda: cmd_install("install", rest),
        "reinstall": lambda: cmd_install("reinstall", rest),
        "upgrade": lambda: cmd_upgrade(rest),
        "setup": cmd_setup,
        "status": cmd_status,
        "audit": cmd_audit,
        "verify": lambda: cmd_verify(rest[0] if rest else ""),
        "allow": lambda: cmd_allow(rest),
        "config": lambda: cmd_config(rest),
        "help": cmd_help,
        "--help": cmd_help,
        "-h": cmd_help,
    }

    handler = dispatch.get(subcmd)
    if handler:
        handler()
    else:
        real_brew = find_brew()
        sys.stdout.flush()
        os.execv(real_brew, [real_brew, subcmd] + rest)
