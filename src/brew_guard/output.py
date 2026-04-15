"""Terminal colors and audit logging."""

from pathlib import Path


class C:
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[0;33m"
    BLUE = "\033[0;34m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def red(s: str) -> str:
    return f"{C.RED}{s}{C.RESET}"


def green(s: str) -> str:
    return f"{C.GREEN}{s}{C.RESET}"


def yellow(s: str) -> str:
    return f"{C.YELLOW}{s}{C.RESET}"


def blue(s: str) -> str:
    return f"{C.BLUE}{s}{C.RESET}"


def bold(s: str) -> str:
    return f"{C.BOLD}{s}{C.RESET}"


def dim(s: str) -> str:
    return f"{C.DIM}{s}{C.RESET}"


def audit_log(audit_log_path: Path, action: str, package: str, reason: str):
    from brew_guard.config import now_iso

    ts = now_iso()
    line = f"{ts}  {action:<20s} {package:<20s} {reason}\n"
    with open(audit_log_path, "a") as f:
        f.write(line)
