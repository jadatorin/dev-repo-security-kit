# dev-repo-security-kit

**Harden your Windows dev machine and vet GitHub repos before you trust them**

![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![Git >= 2.46 recommended](https://img.shields.io/badge/Git-%3E%3D%202.46%20recommended-orange)
![License: MIT](https://img.shields.io/badge/License-MIT-green)

Two PowerShell scripts for Windows developers:

- **`hardening.ps1`** — applies defensive, per-user Git and package-manager configuration and optionally installs secret/vulnerability scanning tools.
- **`repo-check.ps1`** — assesses the risk of a repository before you clone it (URL mode) or after you clone it (local path mode).

No administrator elevation is required: every change is per-user.

---

## Why / Threat model

Cloning a repo is only the first step. The real attack chain is the code you run *after*:

- **Package install scripts** — `preinstall` / `postinstall` / `prepare` hooks in `package.json` execute arbitrary code the moment you run `npm install`. This is the primary malware delivery vector for npm, and the equivalent exists for pip (PEP 517 build backends), cargo (`build.rs`), and others.
- **Git submodule CVEs** — `CVE-2024-32002` (clone-time RCE via malicious submodules writing into `.git/hooks`, patched in Git >= 2.46.0) and `CVE-2022-39253` (`file://` protocol abuse). Clone without `--recurse-submodules` and review `.gitmodules` first.
- **Hooks written by postinstall** — a package install script can drop a hook into `.git/hooks` that runs on your next git operation.
- **Credential bait** — repos seeded with `.env`, `id_rsa`, `.npmrc` auth tokens, etc., hoping you'll reuse a "convenient" secret.
- **Editor tasks** — `.vscode/tasks.json` / `launch.json` can run shell commands. VS Code only executes tasks in Trusted Workspaces.

**Important:** git hooks are **not** transmitted when you clone a repository. The chain that actually bites people is package install scripts plus unpatched submodule handling — that is what this kit targets.

---

## Tools

| Tool | What it does | Switches | Exit codes |
|------|--------------|----------|------------|
| `hardening.ps1` | Hardens a Windows dev machine: Git config, install-script blocking, optional tool install | `-InstallTools`, `-NoHooksPath`, `-PipWheelsOnly`, `-DryRun` | `0` all good; `1` fatal (git missing/unparsable) |
| `repo-check.ps1` | Assesses repo risk before (`-Url`) or after (`-Path`) cloning | `-Url`, `-Path`, `-NoGitleaks`, `-NoOsv`, `-NoSemgrep` | URL mode: `0` PASS / `1` fail; Path mode: `0` PASS / `1` WARN / `2` FAIL |

---

## Quick start

### hardening.ps1

Review everything the script **would** change (no writes):

```powershell
.\hardening.ps1 -DryRun
```

Apply the hardening (Git config + npm/pnpm/yarn `ignore-scripts`; pip and cargo tooling are only recommended unless the matching switch is given):

```powershell
.\hardening.ps1
```

Apply hardening **without** touching global git hooks (`core.hooksPath` stays untouched):

```powershell
.\hardening.ps1 -NoHooksPath
```

Apply hardening **and** install `gitleaks` + `osv-scanner` via winget, plus set the global pip `only-binary=:all:` option:

```powershell
.\hardening.ps1 -InstallTools -PipWheelsOnly
```

### repo-check.ps1

Vet a remote URL **before** cloning (checks transport safety and reachability via `git ls-remote`):

```powershell
.\repo-check.ps1 -Url https://github.com/owner/repo
```

Assess a cloned repo (current directory is used when `-Path` is omitted):

```powershell
.\repo-check.ps1 -Path C:\dev\repo
```

Skip optional scanners you don't have or don't want:

```powershell
.\repo-check.ps1 -Path C:\dev\repo -NoGitleaks -NoOsv -NoSemgrep
```

---

## Exit codes

| Script | Mode | Code | Meaning |
|--------|------|------|---------|
| `hardening.ps1` | any | `0` | Completed successfully |
| `hardening.ps1` | any | `1` | Fatal — git not on PATH, or git version could not be parsed |
| `repo-check.ps1` | `-Url` | `0` | Transport is safe and repo is reachable |
| `repo-check.ps1` | `-Url` | `1` | Unsafe transport (aborted), unparseable URL, or repo unreachable |
| `repo-check.ps1` | `-Path` | `0` | PASS — nothing relevant found, repo looks low-risk |
| `repo-check.ps1` | `-Path` | `1` | WARN — review flagged items before trusting (VS Code tasks, binaries, minified files, Docker, incomplete tooling) |
| `repo-check.ps1` | `-Path` | `2` | FAIL — do **not** run installs/builds until reviewed (hooks, submodules, package scripts, `pyproject.toml`, `build.rs`, credential bait, secrets) |

Passing both `-Url` and `-Path` to `repo-check.ps1` exits with `1`.

---

## What `hardening.ps1` changes

Per-user configuration applied (or skipped, depending on switches and what's installed):

| Setting | Value | Applied when | Revert command |
|---------|-------|--------------|----------------|
| `git config --global core.hooksPath` | `/dev/null` | always, unless `-NoHooksPath` | `git config --global --unset core.hooksPath` |
| `git config --global protocol.file.allow` | `user` | always (blocks `file://` submodule abuse, CVE-2022-39253) | `git config --global --unset protocol.file.allow` |
| `git config --global --unset-all core.fsmonitor` | removed | only when a value is currently set | `git config --global core.fsmonitor <original-value>` |
| `npm config set ignore-scripts true` | `true` | if npm is installed | `npm config delete ignore-scripts` |
| `pnpm config set ignore-scripts true` | `true` | if pnpm is installed | `pnpm config delete ignore-scripts` |
| `yarn config set ignore-scripts true` | `true` | if yarn classic (v1) is installed | `yarn config delete ignore-scripts` |
| `pip config set global.only-binary ":all:"` | `:all:` | only with `-PipWheelsOnly`, if pip is installed | `pip config unset global.only-binary` |
| `cargo install cargo-audit --locked` | installed | only with `-InstallTools`, if cargo is installed | `cargo uninstall cargo-audit` |
| `winget install gitleaks.gitleaks` / `Google.OSV-Scanner` | installed | only with `-InstallTools` | `winget uninstall --id <id>` |

`hardening.ps1` deliberately does **not** touch `git config --global safe.directory` — setting it to `*` would disable the ownership protections behind CVE-2022-24765 / CVE-2022-29187.

It also verifies the git version up front (even in `-DryRun`): `git < 2.45.2` is flagged as **FAIL** (CVE-2024-32002, clone-time RCE), `>= 2.45.2` is the initial fix, `>= 2.46.0` is fully patched and recommended.

---

## Caveats (read these)

- **`ignore-scripts` breaks native builds.** Packages like `esbuild`, `sharp`, and `electron` rely on `postinstall` to fetch/build their binaries. When a trusted project needs them, run `npm rebuild <pkg>` for that package.
- **Global `core.hooksPath` disables all hooks** — including legitimate ones (husky, pre-commit, secret scanners). Use `-NoHooksPath` if you need project hooks.
- **pip cannot block builds globally.** pip has no equivalent of `ignore-scripts`; the script recommends `pip install --only-binary=:all: <pkg>` or `pipx`/venvs instead, and only sets the global option when you pass `-PipWheelsOnly`. Note that inside a virtualenv the setting applies to that venv only.
- **cargo has no flag to disable `build.rs`.** It always compiles and runs. Review `build.rs` manually or build in a sandbox.
- **yarn Berry (v2+)** doesn't honor classic `ignore-scripts`; set `enableScripts: false` in the project `.yarnrc.yml` instead.
- **`repo-check.ps1`** treats submodules, package scripts, `pyproject.toml`, `build.rs`, active hooks, and credential bait as FAIL conditions, but a WARN is *not* an automatic "unsafe" — review the flagged items.
- `osv-scanner` and `gitleaks` are optional; without them `repo-check.ps1` falls back to built-in regex scanning and notes the gap in its verdict.

---

## Requirements

- **Windows PowerShell 5.1+** (Windows PowerShell, preinstalled on Windows 10/11).
- **Git for Windows** — required by both scripts. `git >= 2.46.0` **recommended** (fully patched against CVE-2024-32002 clone-time RCE).
- **gitleaks / osv-scanner / semgrep** — optional, but enable real scanning in `repo-check.ps1`. Install gitleaks and osv-scanner with `.\hardening.ps1 -InstallTools` or `winget install <id>`; semgrep via `pipx install semgrep`.

---

## Security notes

- This kit **scans and hardens** — it is not an antivirus and cannot catch everything.
- SAST and regex scanning do not reliably detect **obfuscated malware**. Use a sandbox/VM for anything suspicious.
- **Never** use credentials found inside a cloned repository — treat them as hostile bait.
- Run untrusted code (install scripts, `build.rs`, docker builds, make targets) only in a sandbox or VM.
- Enable **Workspace Trust** in VS Code and trust only repositories you actually trust.
- Review `.gitmodules` *after* cloning and before any `git submodule update`.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Installation (single command)

An installer is included for Windows PowerShell 5.1:

```powershell
iex (irm https://raw.githubusercontent.com/jadatorin/dev-repo-security-kit/main/install.ps1)
```

Or download and run it manually:

```powershell
.\install.ps1
```

This installs `hardening.ps1` and `repo-check.ps1` to `$HOME\.dev-security-kit\`, validates their syntax with the PowerShell parser, and prints how to add the folder to your PATH. Re-run it any time to update. See `install.ps1` for the `-SkipPathNote` switch.
