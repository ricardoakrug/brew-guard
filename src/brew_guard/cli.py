"""CLI entry point: command dispatch and all user-facing commands."""

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field

from brew_guard.config import (
    AUDIT_LOG,
    CONFIG_FILE,
    LOCKFILE,
    JsonFileError,
    add_alias_to_rc,
    check_alias_in_rc,
    detect_shell,
    epoch_now,
    find_brew,
    init,
    iso_to_epoch,
    load_config,
    load_lockfile,
    save_config,
    validate_config_key,
    validate_config_value,
)
from brew_guard.core import (
    batch_update_lockfile,
    brew_info,
    brew_info_installed,
    brew_outdated,
    check_hash_changes,
    check_quarantine,
    detect_type,
    get_pkg_data,
    update_lockfile_entry,
    verify_attestation,
)
from brew_guard.output import audit_log, blue, bold, dim, green, red, yellow

OPTIONS_WITH_VALUES = {
    "--appdir",
    "--audio-unit-plugindir",
    "--bottle-arch",
    "--cc",
    "--colorpickerdir",
    "--dictionarydir",
    "--fontdir",
    "--input-methoddir",
    "--internet-plugindir",
    "--keyboard-layoutdir",
    "--language",
    "--mdimporterdir",
    "--prefpanedir",
    "--qlplugindir",
    "--screen-saverdir",
    "--servicedir",
    "--vst-plugindir",
    "--vst3-plugindir",
}

OUTDATED_SELECTION_FLAGS = {
    "--cask",
    "--casks",
    "--fetch-HEAD",
    "--formula",
    "--formulae",
    "--greedy",
    "--greedy-auto-updates",
    "--greedy-latest",
    "-g",
}


@dataclass
class ParsedArgs:
    flags: list[str]
    packages: list[str]


@dataclass
class PackageCheck:
    name: str
    pkg_type: str | None
    info: dict | None
    ok: bool
    status: str
    lines: list[str] = field(default_factory=list)
    forced: bool = False
    warned: bool = False
    allowlisted: bool = False


# ── Commands ─────────────────────────────────────────────────────────
def _ask(prompt: str, default: str = "") -> str:
    """Prompt user for input with optional default."""
    if default:
        prompt = f"{prompt} [{default}]: "
    else:
        prompt = f"{prompt}: "
    try:
        answer = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(1)
    return answer or default


def _ask_yn(prompt: str, default: bool = True) -> bool:
    """Yes/no prompt. Returns bool."""
    suffix = "[Y/n]" if default else "[y/N]"
    try:
        answer = input(f"{prompt} {suffix} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(1)
    if not answer:
        return default
    return answer in ("y", "yes")


def _split_protected_args(args: list[str]) -> ParsedArgs:
    flags: list[str] = []
    packages: list[str] = []
    i = 0
    parsing_flags = True

    while i < len(args):
        arg = args[i]
        if parsing_flags and arg == "--":
            parsing_flags = False
            i += 1
            continue

        if parsing_flags and arg.startswith("-") and arg != "-":
            flags.append(arg)
            if "=" not in arg and arg in OPTIONS_WITH_VALUES and i + 1 < len(args):
                flags.append(args[i + 1])
                i += 2
                continue
            i += 1
            continue

        packages.append(arg)
        i += 1

    return ParsedArgs(flags=flags, packages=packages)


def _has_flag(flags: list[str], *names: str) -> bool:
    return any(name in flags for name in names)


def _requested_type_from_flags(flags: list[str]) -> str | None:
    if _has_flag(flags, "--cask", "--casks"):
        return "cask"
    if _has_flag(flags, "--formula", "--formulae"):
        return "formula"
    return None


def _is_dry_run(flags: list[str]) -> bool:
    return _has_flag(flags, "--dry-run", "-n")


def _extract_outdated_args(flags: list[str]) -> list[str]:
    return [flag for flag in flags if flag in OUTDATED_SELECTION_FLAGS]


def _print_json_error(exc: JsonFileError, repair: str):
    print(f"{red('Error')}: {exc.path} {exc.reason}")
    print(f"  Repair: {repair}")


def _exit_json_error(exc: JsonFileError, repair: str):
    _print_json_error(exc, repair)
    sys.exit(1)


def _load_config_or_exit() -> dict:
    try:
        return load_config()
    except JsonFileError as exc:
        _exit_json_error(exc, "fix or replace ~/.brew-guard/config.json, then rerun")


def _load_lockfile_or_exit() -> dict:
    try:
        return load_lockfile()
    except JsonFileError as exc:
        _exit_json_error(exc, "fix or replace ~/.brew-guard/lockfile.json, then rerun")


def _run_passthrough(real_brew: str, subcmd: str | None = None, args: list[str] | None = None):
    argv = [real_brew]
    if subcmd:
        argv.append(subcmd)
    if args:
        argv.extend(args)
    sys.stdout.flush()
    os.execv(real_brew, argv)


def _run_brew_command(real_brew: str, subcmd: str, args: list[str]) -> int:
    completed = subprocess.run([real_brew, subcmd] + args, check=False)
    return completed.returncode


def _status_for_success(*, forced: bool, warned: bool, allowlisted: bool) -> str:
    if allowlisted:
        return green("ALLOWED")
    if forced:
        return yellow("FORCED")
    if warned:
        return yellow("WARN")
    return green("OK")


def _evaluate_package(
    name: str,
    cfg: dict,
    *,
    force: bool,
    requested_type: str | None = None,
    cache_writes: bool = True,
) -> PackageCheck:
    lines: list[str] = []
    forced = False
    warned = False
    allowlisted = False

    info = brew_info(name, is_cask=requested_type == "cask")
    if not info:
        lines.append(f"  {red('ERROR')}: Cannot fetch brew info for {name}")
        if force:
            lines.append(f"  {yellow('--force: bypassing brew info lookup failure')}")
            return PackageCheck(
                name=name,
                pkg_type=requested_type,
                info=None,
                ok=True,
                status=yellow("FORCED"),
                lines=lines,
                forced=True,
            )
        return PackageCheck(
            name=name,
            pkg_type=requested_type,
            info=None,
            ok=False,
            status=red("BLOCKED: INFO"),
            lines=lines,
        )

    pkg_type = requested_type or detect_type(info)
    if pkg_type == "unknown":
        lines.append(f"  {red('ERROR')}: Cannot determine type for {name}")
        if force:
            lines.append(f"  {yellow('--force: bypassing package type detection failure')}")
            return PackageCheck(
                name=name,
                pkg_type=None,
                info=info,
                ok=True,
                status=yellow("FORCED"),
                lines=lines,
                forced=True,
            )
        return PackageCheck(
            name=name,
            pkg_type=None,
            info=info,
            ok=False,
            status=red("BLOCKED: TYPE"),
            lines=lines,
        )

    ok, result_lines, code = check_quarantine(
        name,
        pkg_type,
        force,
        cfg,
        cache_writes=cache_writes,
    )
    lines.extend(result_lines)
    if code == "allowed":
        allowlisted = True
    if code.startswith("forced_"):
        forced = True
    if code.startswith("warn_"):
        warned = True
    if not ok:
        return PackageCheck(
            name=name,
            pkg_type=pkg_type,
            info=info,
            ok=False,
            status=red("BLOCKED: QUARANTINE"),
            lines=lines,
        )

    ok, result_lines, code = check_hash_changes(name, info, pkg_type, force, cfg)
    lines.extend(result_lines)
    if code.startswith("forced_"):
        forced = True
    if code.startswith("warn_"):
        warned = True
    if not ok:
        status = "BLOCKED: LOCKFILE" if code == "blocked_lockfile_error" else "BLOCKED: HASH"
        return PackageCheck(
            name=name,
            pkg_type=pkg_type,
            info=info,
            ok=False,
            status=red(status),
            lines=lines,
        )

    pkg_data = get_pkg_data(info, pkg_type)
    if pkg_type == "cask" and pkg_data.get("sha256") == "no_check":
        lines.append(f"  {yellow('WARN')}: {name} has sha256:no_check — integrity unverifiable")
        warned = True
        if cfg.get("strict_no_check_casks", False):
            if force:
                forced = True
                lines.append(f"  {yellow('--force: bypassing strict no_check policy')}")
                audit_log(AUDIT_LOG, "FORCE_NO_CHECK", name, "sha256:no_check")
            else:
                lines.append(f"  {red('BLOCKED')}: strict_no_check_casks enabled")
                audit_log(AUDIT_LOG, "BLOCKED_NO_CHECK", name, "sha256:no_check")
                return PackageCheck(
                    name=name,
                    pkg_type=pkg_type,
                    info=info,
                    ok=False,
                    status=red("BLOCKED: NO_CHECK"),
                    lines=lines,
                )

    if cfg.get("attestation_check", False) and pkg_type == "formula":
        ok, result_lines, code = verify_attestation(name, info)
        lines.extend(result_lines)
        if not ok:
            if force:
                forced = True
                lines.append(f"  {yellow('--force: bypassing attestation verification')}")
                audit_log(AUDIT_LOG, "FORCE_ATTESTATION", name, code)
            elif cfg.get("strict_attestation", False):
                audit_log(AUDIT_LOG, "BLOCKED_ATTESTATION", name, code)
                return PackageCheck(
                    name=name,
                    pkg_type=pkg_type,
                    info=info,
                    ok=False,
                    status=red("BLOCKED: ATTEST"),
                    lines=lines,
                )
            else:
                warned = True
                audit_log(AUDIT_LOG, "WARN_ATTESTATION", name, code)

    return PackageCheck(
        name=name,
        pkg_type=pkg_type,
        info=info,
        ok=True,
        status=_status_for_success(forced=forced, warned=warned, allowlisted=allowlisted),
        lines=lines,
        forced=forced,
        warned=warned,
        allowlisted=allowlisted,
    )


def _refresh_tracked_packages(packages: list[PackageCheck]):
    for package in packages:
        if package.pkg_type not in {"formula", "cask"}:
            continue

        info = brew_info(package.name, is_cask=package.pkg_type == "cask") or package.info
        if info:
            try:
                update_lockfile_entry(package.name, package.pkg_type, info)
            except JsonFileError as exc:
                print(
                    f"  {yellow('WARN')}: Installed {package.name}, but state was not updated "
                    f"({exc.path} {exc.reason})"
                )

        reason = "all checks ok"
        if package.allowlisted:
            reason = "allowlisted"
        elif package.forced:
            reason = "checks bypassed with --force"
        elif package.warned:
            reason = "passed with warnings"
        audit_log(AUDIT_LOG, "PASSED", package.name, reason)


def _run_checked_command(
    real_brew: str,
    subcmd: str,
    brew_args: list[str],
    packages: list[PackageCheck],
    *,
    message: str,
    dry_run: bool,
):
    print()
    print(message)
    returncode = _run_brew_command(real_brew, subcmd, brew_args)
    if returncode == 0:
        if dry_run:
            print(f"{blue('brew-guard')}: Dry run completed. State unchanged.")
        else:
            _refresh_tracked_packages(packages)
    sys.exit(returncode)


def cmd_setup():
    import shutil

    from brew_guard.core import run

    is_first_run = not CONFIG_FILE.exists()
    lockfile_existed = LOCKFILE.exists()
    existing_packages = set()
    if lockfile_existed:
        try:
            existing_packages = set(load_lockfile().get("packages", {}).keys())
        except JsonFileError as exc:
            _exit_json_error(exc, "fix or replace ~/.brew-guard/lockfile.json, then rerun setup")

    print(f"\n{bold('brew-guard setup')}")
    print(f"{'─' * 50}")

    print(f"\n{bold('1. Prerequisites')}\n")

    try:
        real_brew = find_brew()
        print(f"  {green('✓')} Homebrew found: {dim(real_brew)}")
    except SystemExit:
        print(f"  {red('✗')} Homebrew not found")
        print("    Install: https://brew.sh")
        sys.exit(1)

    gh_path = shutil.which("gh")
    if not gh_path:
        print(f"  {red('✗')} GitHub CLI (gh) not found")
        print("    Install: brew install gh")
        print()
        print(f"  {red('brew-guard requires gh to query formula modification dates.')}")
        print("  Install gh first, then re-run: brew-guard setup")
        sys.exit(1)
    print(f"  {green('✓')} GitHub CLI found: {dim(gh_path)}")

    r = run(["gh", "auth", "status"], timeout=10)
    if r.returncode == 0:
        print(f"  {green('✓')} GitHub CLI authenticated (5,000 req/hr)")
    else:
        print(f"  {yellow('!')} GitHub CLI not authenticated")
        print("    Without auth: rate limit is 60 req/hr (will hit limits quickly)")
        print("    With auth:    rate limit is 5,000 req/hr")
        print()
        if _ask_yn("    Continue without authentication?", default=False):
            print(f"  {yellow('Continuing degraded.')} Run 'gh auth login' later.")
        else:
            print(f"\n  Run: {bold('gh auth login')}")
            print("  Then re-run: brew-guard setup")
            sys.exit(0)

    print(f"\n{bold('2. Shell alias')}\n")

    alias_found, rc_path = check_alias_in_rc()
    shell = detect_shell()

    if alias_found:
        print(f"  {green('✓')} Alias found in {dim(str(rc_path))}")
    elif rc_path:
        print(f"  {yellow('!')} No brew alias found in {rc_path.name}")
        print()
        alias_line = "abbr --add brew brew-guard" if shell == "fish" else "alias brew='brew-guard'"
        print(f"    Will add to {rc_path}:")
        print(f"    {dim(alias_line)}")
        print()
        if _ask_yn("    Add alias now?"):
            add_alias_to_rc(rc_path)
            print(f"  {green('✓')} Alias added to {rc_path.name}")
            print(f"    Run: {dim(f'source {rc_path}')} to activate")
            alias_found = True
        else:
            print(f"  {yellow('Skipped.')} Add manually:")
            print(f"    echo \"{alias_line}\" >> {rc_path}")
    else:
        print(f"  {yellow('!')} Unsupported shell: {shell or 'unknown'}")
        print("    Add this alias to your shell config manually:")
        print("    alias brew='brew-guard'")

    print(f"\n{bold('3. Configuration')}\n")

    init()

    if is_first_run:
        print("  Default settings (press Enter to accept defaults):\n")
        q_days = _ask(
            f"  Quarantine period in days {dim('(blocks packages modified within this window)')}",
            default="3",
        )
        try:
            q_days_int = int(q_days)
        except ValueError:
            print(f"  {yellow('Invalid number, using default: 3')}")
            q_days_int = 3

        strict_casks = _ask_yn(
            f"  Block casks with sha256:no_check? {dim('(unverifiable downloads)')}",
            default=False,
        )

        cfg = _load_config_or_exit()
        cfg["quarantine_days"] = q_days_int
        cfg["strict_no_check_casks"] = strict_casks
        save_config(cfg)

        print(f"\n  {green('✓')} Config saved to {dim(str(CONFIG_FILE))}")
    else:
        cfg = _load_config_or_exit()
        print(f"  Existing config found at {dim(str(CONFIG_FILE))}:")
        print(f"    quarantine_days:              {cfg.get('quarantine_days', 3)}")
        print(f"    attestation_check:            {cfg.get('attestation_check', False)}")
        print(f"    strict_attestation:           {cfg.get('strict_attestation', False)}")
        print(f"    strict_no_check_casks:        {cfg.get('strict_no_check_casks', False)}")
        print(
            "    block_on_date_resolution_error:"
            f" {cfg.get('block_on_date_resolution_error', True)}"
        )
        print(
            f"    block_on_lockfile_error:      {cfg.get('block_on_lockfile_error', True)}"
        )
        allowed_count = len(cfg.get("allowed", {}))
        if allowed_count:
            print(f"    allowed:                      {allowed_count} package(s)")
        print(f"\n  {green('✓')} Keeping existing config")
        print(f"    Change with: {dim('brew-guard config set <key> <value>')}")

    print(f"\n{bold('4. Scanning installed packages')}\n")

    print("  Scanning formulae...")
    installed = brew_info_installed()
    formulae = installed.get("formulae", [])

    print("  Scanning casks...")
    cask_data = brew_info_installed(is_cask=True)
    casks = cask_data.get("casks", [])

    try:
        fc, cc = batch_update_lockfile(formulae, casks)
    except JsonFileError as exc:
        _exit_json_error(exc, "fix or replace ~/.brew-guard/lockfile.json, then rerun setup")

    if existing_packages:
        new_lf = _load_lockfile_or_exit()
        current_packages = set(new_lf.get("packages", {}).keys())
        new_packages = current_packages - existing_packages
        if new_packages:
            print(f"  {green('+')} {len(new_packages)} new package(s) added")
            for package in sorted(new_packages):
                print(f"    {dim('+')} {package}")
        print(f"  {fc} formulae + {cc} casks total in lockfile")
    else:
        print(f"  {green('✓')} {fc} formulae + {cc} casks recorded in lockfile")
        print(f"  Dates: {blue('TRUSTED_BASELINE')} (existing installs trusted)")

    print(f"\n{'─' * 50}")
    print(f"{bold('Setup complete!')}\n")
    gh_ok = r.returncode == 0
    gh_icon = green("✓") if gh_ok else yellow("!")
    gh_msg = "authenticated" if gh_ok else "not authenticated (degraded)"
    alias_icon = green("✓") if alias_found else yellow("!")
    alias_msg = "active" if alias_found else "needs shell reload or manual add"

    print(f"  {green('✓')} Homebrew     {dim(real_brew)}")
    print(f"  {gh_icon} GitHub CLI   {gh_msg}")
    print(f"  {alias_icon} Shell alias  {alias_msg}")
    print(f"  {green('✓')} Lockfile     {dim(str(LOCKFILE))}")
    print(f"  {green('✓')} Config       {dim(str(CONFIG_FILE))}")
    print()
    print("  Future installs/upgrades are now checked automatically.")
    if not alias_found and rc_path:
        print(f"  {yellow('Reminder')}: reload your shell to activate the alias:")
        print(f"    source {rc_path}")
    print()


def cmd_install(subcmd: str, args: list[str]):
    parsed = _split_protected_args(args)
    real_brew = find_brew()

    if not parsed.packages:
        _run_passthrough(real_brew, subcmd, args)

    init()
    cfg = _load_config_or_exit()
    force = _has_flag(parsed.flags, "--force", "-f")
    requested_type = _requested_type_from_flags(parsed.flags)

    checked: list[PackageCheck] = []
    blocked: list[PackageCheck] = []
    for package in parsed.packages:
        print(f"{bold('brew-guard')}: Checking {bold(package)}...")
        result = _evaluate_package(
            package,
            cfg,
            force=force,
            requested_type=requested_type,
        )
        for line in result.lines:
            print(line)
        checked.append(result)
        if not result.ok:
            blocked.append(result)

    if blocked and not force:
        print()
        print(f"{red('brew-guard')}: {len(blocked)} package(s) blocked. Use --force to bypass.")
        sys.exit(1)

    action = {
        "install": "Installing...",
        "reinstall": "Reinstalling...",
        "upgrade": "Upgrading...",
    }[subcmd]
    _run_checked_command(
        real_brew,
        subcmd,
        args,
        [package for package in checked if package.ok],
        message=f"{green('brew-guard')}: Checks completed. {action}",
        dry_run=_is_dry_run(parsed.flags),
    )


def cmd_upgrade(args: list[str]):
    parsed = _split_protected_args(args)
    if parsed.packages:
        cmd_install("upgrade", args)
        return

    real_brew = find_brew()
    force = _has_flag(parsed.flags, "--force", "-f")

    init()
    cfg = _load_config_or_exit()
    outdated = brew_outdated(_extract_outdated_args(parsed.flags))
    outdated_formulae = outdated.get("formulae", [])
    outdated_casks = outdated.get("casks", [])

    pending = [
        (formula.get("name", ""), "formula")
        for formula in outdated_formulae
        if formula.get("name", "")
    ] + [
        (cask.get("name", ""), "cask")
        for cask in outdated_casks
        if cask.get("name", "")
    ]

    if not pending:
        print(f"{bold('brew-guard')}: Everything up to date.")
        return

    print(f"{bold('brew-guard')}: Checking {len(pending)} outdated package(s)...\n")

    checked: list[PackageCheck] = []
    blocked: list[PackageCheck] = []
    clear: list[PackageCheck] = []

    for name, pkg_type in pending:
        print(f"{bold('brew-guard')}: Checking {bold(name)}...")
        result = _evaluate_package(name, cfg, force=force, requested_type=pkg_type)
        for line in result.lines:
            print(line)
        print(f"  Status: {result.status}")
        print()

        checked.append(result)
        if result.ok:
            clear.append(result)
        else:
            blocked.append(result)

    print(
        f"{bold('Summary')}: {green(str(len(clear)))} clear, "
        f"{red(str(len(blocked)))} blocked"
    )

    if force:
        _run_checked_command(
            real_brew,
            "upgrade",
            args,
            checked,
            message=f"{yellow('--force')}: Upgrading all {len(pending)} package(s)...",
            dry_run=_is_dry_run(parsed.flags),
        )

    if blocked:
        print(f"  Blocked packages were skipped. Override with: {dim('brew upgrade --force')}")

    if clear:
        _run_checked_command(
            real_brew,
            "upgrade",
            parsed.flags + [package.name for package in clear],
            clear,
            message=f"{green('brew-guard')}: Upgrading {len(clear)} clear package(s)...",
            dry_run=_is_dry_run(parsed.flags),
        )

    print()
    print(f"{red('brew-guard')}: All outdated packages are blocked. Nothing to upgrade.")
    sys.exit(1)


def cmd_status():
    lf = _load_lockfile_or_exit()
    if not lf.get("packages"):
        print("No lockfile found. Run: brew-guard setup")
        sys.exit(1)

    cfg = _load_config_or_exit()
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
            if mod_epoch is None:
                age_str = "?"
                status = yellow("unknown")
            else:
                age_days = int((now_ts - mod_epoch) / 86400)
                age_str = str(age_days)
                if age_days < quarantine_days:
                    status = red("QUARANTINE")
                else:
                    status = green("ok")

        rows.append((name, pkg_type, version, age_str, status))

    col_w = [
        max(len("PACKAGE"), max((len(row[0]) for row in rows), default=7)),
        max(len("TYPE"), max((len(row[1]) for row in rows), default=4)),
        max(len("VERSION"), max((len(row[2]) for row in rows), default=7)),
        max(len("AGE"), max((len(row[3]) for row in rows), default=3)),
    ]

    print(
        f"  {bold('PACKAGE'):<{col_w[0]+9}s} "
        f"{bold('TYPE'):<{col_w[1]+9}s} "
        f"{bold('VERSION'):<{col_w[2]+9}s} "
        f"{bold('AGE'):<{col_w[3]+9}s} "
        f"{bold('STATUS')}"
    )
    print(f"  {'─' * col_w[0]} {'─' * col_w[1]} {'─' * col_w[2]} {'─' * col_w[3]} {'─' * 12}")

    for name, pkg_type, version, age, status in rows:
        print(
            f"  {name:<{col_w[0]}s} "
            f"{dim(pkg_type):<{col_w[1]+9}s} "
            f"{version:<{col_w[2]}s} "
            f"{age:<{col_w[3]}s} "
            f"{status}"
        )


def cmd_audit():
    lf = _load_lockfile_or_exit()
    if not lf.get("packages"):
        print("No lockfile found. Run: brew-guard setup")
        sys.exit(1)

    cfg = _load_config_or_exit()
    print(f"{bold('brew-guard audit')}: Re-checking all installed packages...\n")

    issues = 0
    checked_count = 0

    for name, pkg in sorted(lf["packages"].items()):
        pkg_type = pkg.get("type", "formula")
        info = brew_info(name, is_cask=pkg_type == "cask")
        if not info:
            print(f"  {yellow('WARN')}: Cannot fetch brew info for {name}")
            continue

        checked_count += 1
        ok, lines, _ = check_hash_changes(name, info, pkg_type, force=False, cfg=cfg)
        if not ok:
            issues += 1
            for line in lines:
                print(line)

    print()
    if issues:
        print(
            f"{bold('Audit complete.')}: "
            f"{red(str(issues))} hash change(s) detected in {checked_count} packages"
        )
    else:
        print(f"{bold('Audit complete.')}: {green('No issues')} in {checked_count} packages")


def cmd_verify(name: str):
    if not name:
        print("Usage: brew-guard verify <package>")
        sys.exit(1)

    print(f"{bold('brew-guard verify')}: {bold(name)}\n")

    lf = _load_lockfile_or_exit()
    stored = lf.get("packages", {}).get(name)
    if not stored:
        print(f"  {yellow('NOT TRACKED')}: {name} not in lockfile")
        print("  Run: brew-guard setup")
        sys.exit(1)

    cfg = _load_config_or_exit()
    result = _evaluate_package(
        name,
        cfg,
        force=False,
        requested_type=stored.get("type", "formula"),
        cache_writes=False,
    )
    for line in result.lines:
        print(line)
    print(f"\n  Status: {result.status}")

    print(f"\n  {blue('Lockfile entry')}:")
    for key, value in sorted(stored.items()):
        val_str = str(value)
        if len(val_str) > 60:
            val_str = val_str[:57] + "..."
        print(f"    {dim(key)}: {val_str}")


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

    init()
    cfg = _load_config_or_exit()
    cfg["allowed"][name] = reason
    save_config(cfg)
    print(f"{green('Allowed')}: {bold(name)} ({dim(reason)})")
    audit_log(AUDIT_LOG, "ALLOW", name, reason)


def cmd_config(args: list[str]):
    action = args[0] if args else ""
    if action == "set":
        if len(args) < 3:
            print("Usage: brew-guard config set <key> <value>")
            sys.exit(1)

        init()
        cfg = _load_config_or_exit()
        key, raw_val = args[1], args[2]
        err = validate_config_key(key)
        if err:
            print(f"{red('Error')}: {err}")
            sys.exit(1)

        val, type_err = validate_config_value(key, raw_val)
        if type_err:
            print(f"{red('Error')}: {type_err}")
            sys.exit(1)

        cfg[key] = val
        save_config(cfg)
        print(f"Set {bold(key)} = {json.dumps(val)}")
        return

    cfg = _load_config_or_exit()
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
    else:
        print(json.dumps(cfg, indent=2))


def cmd_help():
    print(
        f"""{bold('brew-guard')}: Supply chain protection for Homebrew

{bold('Usage')}: brew-guard <command> [args]

{bold('Protected commands')}:
  install <pkg> [--force] [--cask]  Install with quarantine + hash checks
  upgrade [<pkg>] [--force]         Upgrade with the full verification pipeline

{bold('Management')}:
  setup                             Initialize and scan installed packages
  status                            Show all packages with age info
  audit                             Re-check all installed for hash changes
  verify <pkg>                      Deep-check single package
  allow <pkg> --reason '...'        Permanently bypass quarantine
  config [get|set] [key] [value]    View/change configuration

Help and plain brew passthrough commands do not create ~/.brew-guard files.

{bold('Config keys')}:
  quarantine_days {dim('(default: 3)')}               Days before formula update is trusted
  attestation_check {dim('(default: false)')}          Verify Sigstore attestations
  strict_attestation {dim('(default: false)')}         Block on attestation failure or timeout
  strict_no_check_casks {dim('(default: false)')}      Block casks with sha256:no_check
  block_on_date_resolution_error {dim('(default: true)')} Block if formula age cannot be verified
  block_on_lockfile_error {dim('(default: true)')}     Block if lockfile.json is invalid"""
    )


# ── Main ─────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        _run_passthrough(find_brew())

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
        _run_passthrough(find_brew(), subcmd, rest)
