# brew-guard

Supply chain protection wrapper for Homebrew. Quarantines recently-modified packages and tracks SHA256 hashes to defend against supply chain attacks.

## What it does

brew-guard sits between you and `brew`, intercepting `install` and `upgrade` commands. Before any package is installed or upgraded, it:

1. **Quarantine check** — queries GitHub for when the formula was last modified. If the change is too recent (default: 3 days), the install is blocked.
2. **Hash tracking** — records SHA256 hashes of bottles, source tarballs, and formula files in a local lockfile. On upgrade, it detects hash changes and alerts you.
3. **Audit logging** — every decision (pass, block, force-override) is logged to `~/.brew-guard/cache/audit.log`.
4. **Strict failure handling** — if formula age or lockfile integrity cannot be verified, brew-guard blocks by default instead of silently degrading.

All other brew commands (search, list, info, etc.) pass through transparently.

## Threat model

### What brew-guard mitigates

- **Compromised formula commits** — a malicious change to a Homebrew formula is unlikely to survive community review for multiple days. The quarantine window gives the ecosystem time to catch it.
- **Malicious bottle replacements** — hash tracking detects if a bottle's SHA256 changes between your last install and an upgrade attempt.
- **Stealth cask modifications** — casks with `sha256 :no_check` can have their download URL swapped silently. brew-guard warns on these and can block them in strict mode.
- **Targeted time-of-install attacks** — if an attacker pushes a malicious update and you happen to install during that window, the quarantine blocks it.

### What brew-guard does NOT protect against

- A compromised `gh` CLI or GitHub API returning false dates
- Attacks on the Homebrew binary itself
- Packages that were already compromised before your first `brew-guard setup`
- Dependencies pulled during build (only top-level packages are checked)

The quarantine is a speed bump, not a firewall. It significantly raises the bar for opportunistic supply chain attacks while adding minimal friction to normal usage.

## How it works

```
You run:     brew install ripgrep
brew-guard:  Intercepts the command
             ├─ Queries GitHub: "when was ripgrep.rb last modified?"
             ├─ If < 3 days ago → BLOCKED (quarantine)
             ├─ If ≥ 3 days ago → checks lockfile for hash changes
             │   ├─ Hash changed → BLOCKED (possible compromise)
             │   └─ Hash unchanged or new package → PASSED
             └─ Updates lockfile, passes through to real brew
```

GitHub queries are cached for 1 hour to avoid rate limiting. The `gh` CLI handles authentication automatically. Read-only commands like `help` and plain brew passthroughs do not create `~/.brew-guard` state.

## Prerequisites

- **Python 3.10+**
- **Homebrew** ([brew.sh](https://brew.sh))
- **GitHub CLI** (`gh`) — used to query formula modification dates
  - Install: `brew install gh`
  - Authenticate: `gh auth login` (recommended — 5,000 req/hr vs 60/hr without)

## Installation

### With pipx (recommended)

```bash
pipx install brew-guard
```

### With pip

```bash
pip install brew-guard
```

### From source

```bash
git clone https://github.com/ricardoakrug/brew-guard.git
cd brew-guard
pip install -e .
```

## Quick start

```bash
# 1. Install
pipx install brew-guard

# 2. Run guided setup — checks prerequisites, adds shell alias, configures settings
brew-guard setup

# 3. Use brew as normal — brew-guard protects you transparently
brew install something
brew upgrade
```

Setup will walk you through:
- Verifying `gh` CLI is installed and authenticated
- Adding the shell alias (`alias brew='brew-guard'`) to your rc file
- Choosing your quarantine period and security settings
- Scanning all installed packages as a trusted baseline

## Commands

| Command | Description |
|---------|-------------|
| `brew install <pkg>` | Install with quarantine + hash checks |
| `brew upgrade [<pkg>]` | Upgrade with the full verification pipeline; blocked packages are skipped in bulk mode |
| `brew-guard setup` | Initialize lockfile with all currently installed packages |
| `brew-guard status` | Show all tracked packages with age and quarantine status |
| `brew-guard audit` | Re-check all installed packages for hash changes |
| `brew-guard verify <pkg>` | Deep-check a single package |
| `brew-guard allow <pkg> --reason '...'` | Permanently bypass quarantine for a package |
| `brew-guard config [get\|set] [key] [val]` | View or change configuration |

All other commands (e.g., `brew search`, `brew info`, `brew list`) pass through to brew unchanged.

### Overrides

- `--force` on any protected command bypasses quarantine, hash, attestation, and verification-failure blocks (logged)
- `brew-guard allow <pkg> --reason "..."` permanently whitelists a package

## Configuration

Stored at `~/.brew-guard/config.json`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `quarantine_days` | int | `3` | Days a formula must age before install is allowed |
| `attestation_check` | bool | `false` | Verify Sigstore attestations for bottles |
| `strict_attestation` | bool | `false` | Block on attestation failure or timeout (requires `attestation_check`) |
| `strict_no_check_casks` | bool | `false` | Block casks that have `sha256 :no_check` |
| `block_on_date_resolution_error` | bool | `true` | Block when formula age cannot be verified |
| `block_on_lockfile_error` | bool | `true` | Block when `lockfile.json` is invalid |
| `allowed` | object | `{}` | Package allowlist with reasons |

```bash
# Change quarantine to 7 days
brew-guard config set quarantine_days 7

# View current config
brew-guard config
```

## Data files

| Path | Purpose |
|------|---------|
| `~/.brew-guard/config.json` | Configuration |
| `~/.brew-guard/lockfile.json` | Package hashes and metadata |
| `~/.brew-guard/cache/formula_dates.json` | TTL cache for GitHub queries |
| `~/.brew-guard/cache/audit.log` | Audit trail of all decisions |

If `config.json` is invalid JSON, brew-guard stops and asks you to repair or replace it. If `lockfile.json` is invalid, brew-guard blocks by default unless `block_on_lockfile_error=false`. If the date cache is invalid, brew-guard recreates it automatically.

## Uninstall

```bash
# Remove the package
pipx uninstall brew-guard

# Remove the alias from your shell config (~/.zshrc, ~/.bashrc, etc.)
# Delete the line: alias brew='brew-guard'

# Optionally remove data files
rm -rf ~/.brew-guard
```

## License

MIT. See [LICENSE](LICENSE).
