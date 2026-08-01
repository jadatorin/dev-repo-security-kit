<#
.SYNOPSIS
    Hardens a Windows developer machine against malicious cloned repositories.

.DESCRIPTION
    Applies defensive per-user Git configuration, disables package-manager
    install/build scripts, optionally installs secret and OSV scanning tools,
    and prints a final status table with a revert command for every change.

    All changes are per-user: no administrator elevation required.

    Git version is ALWAYS checked first (even in -DryRun) because CVE-2024-32002
    lets a malicious submodule write into .git/hooks during clone, which is only
    fully patched in Git >= 2.46.0.

.PARAMETER InstallTools
    Install gitleaks and osv-scanner via winget (user scope when supported).
    Without this switch the script only recommends the tools.

.PARAMETER NoHooksPath
    Do NOT set a global core.hooksPath. By default the script sets
    core.hooksPath to /dev/null, which disables ALL git hooks globally.

.PARAMETER PipWheelsOnly
    Set the global pip option only-binary=:all: so pip never executes a
    package's build backend. Without this switch pip is only documented.

.PARAMETER DryRun
    Print every command the script WOULD run without changing anything.

.EXAMPLE
    .\hardening.ps1

.EXAMPLE
    .\hardening.ps1 -DryRun

.EXAMPLE
    .\hardening.ps1 -InstallTools -PipWheelsOnly

.EXAMPLE
    .\hardening.ps1 -NoHooksPath
#>
[CmdletBinding()]
param(
    [switch]$InstallTools,   # Install gitleaks and osv-scanner via winget (default: only warn)
    [switch]$NoHooksPath,    # Do NOT apply core.hooksPath globally (default: apply it with warning)
    [switch]$PipWheelsOnly,  # Apply global pip only-binary=:all: (default: only document it)
    [switch]$DryRun          # Print every action without changing anything
)

Set-StrictMode -Version 2.0

$script:results = New-Object System.Collections.Generic.List[object]

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

function Add-Result {
    param(
        [string]$Measure,
        [string]$Status,
        [string]$Detail,
        [string]$Revert = ''
    )
    $script:results.Add([pscustomobject]@{
        Measure = $Measure
        Status  = $Status
        Detail  = $Detail
        Revert  = $Revert
    })
}

function Write-Step {
    param([string]$Title)
    $pad = [Math]::Max(2, 74 - $Title.Length)
    Write-Host ''
    Write-Host ('--- ' + $Title + ('-' * $pad)) -ForegroundColor Cyan
}

function Get-GitVersion {
    $raw = git --version 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $raw) { return $null }
    if ($raw -match '(\d+)\.(\d+)(?:\.(\d+))?') {
        $build = 0
        if ($Matches[3]) { $build = [int]$Matches[3] }
        return [pscustomobject]@{
            Major = [int]$Matches[1]
            Minor = [int]$Matches[2]
            Build = $build
            Raw   = ($raw | Out-String).Trim()
        }
    }
    return $null
}

function Test-GitVersionAtLeast {
    param($Version, [int]$Major, [int]$Minor, [int]$Build)
    if ($Version.Major -gt $Major) { return $true }
    if ($Version.Major -lt $Major) { return $false }
    if ($Version.Minor -gt $Minor) { return $true }
    if ($Version.Minor -lt $Minor) { return $false }
    return ($Version.Build -ge $Build)
}

function Get-GitGlobal {
    param([string]$Name)
    $value = git config --global --get $Name 2>$null
    if ($LASTEXITCODE -ne 0) { return $null }
    return ($value | Out-String).Trim()
}

function Set-GitGlobal {
    param(
        [string]$Name,
        [string]$Value,
        [string]$Measure,
        [string]$Revert
    )
    $command = 'git config --global ' + $Name + ' ' + $Value
    if ($DryRun) {
        Write-Host ('DRYRUN: ' + $command) -ForegroundColor Cyan
        Add-Result -Measure $Measure -Status 'APPLIED' -Detail ($Value + ' (dry-run)') -Revert $Revert
        return
    }
    git config --global $Name $Value 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host ('[APPLIED] ' + $command) -ForegroundColor Green
        Add-Result -Measure $Measure -Status 'APPLIED' -Detail $Value -Revert $Revert
    }
    else {
        Write-Host ('[FAILED]  ' + $command) -ForegroundColor Red
        Write-Host '  Action: review the error above. This is usually a permissions or PATH issue.' -ForegroundColor Yellow
        Add-Result -Measure $Measure -Status 'FAILED' -Detail 'git config exited with error' -Revert $Revert
    }
}

function Install-WingetPackage {
    param([string]$Id, [string]$DisplayName)
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) {
        Write-Host ('WARNING: winget not found on PATH. Install ' + $DisplayName + ' manually.') -ForegroundColor Yellow
        Add-Result -Measure $DisplayName -Status 'RECOMMENDED' -Detail 'install manually (winget not available)' -Revert 'n/a'
        return
    }
    if ($DryRun) {
        Write-Host ('DRYRUN: winget install --id ' + $Id + ' --scope user --silent') -ForegroundColor Cyan
        Add-Result -Measure $DisplayName -Status 'APPLIED' -Detail ($Id + ' (dry-run)') -Revert ('winget uninstall --id ' + $Id)
        return
    }
    # Prefer --scope user; some packages only support machine scope, so fall back.
    winget install --id $Id --scope user --accept-source-agreements --accept-package-agreements --silent 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host ('NOTE: --scope user not supported for ' + $Id + '; retrying with default scope.') -ForegroundColor DarkGray
        winget install --id $Id --accept-source-agreements --accept-package-agreements --silent 2>&1 | Out-Null
    }
    if ($LASTEXITCODE -eq 0) {
        Write-Host ('[APPLIED] installed ' + $DisplayName + ' (' + $Id + ') via winget') -ForegroundColor Green
        Add-Result -Measure $DisplayName -Status 'APPLIED' -Detail ('winget install ' + $Id) -Revert ('winget uninstall --id ' + $Id)
    }
    else {
        Write-Host ('WARNING: winget could not install ' + $DisplayName + ' (' + $Id + ').') -ForegroundColor Yellow
        if ($DisplayName -eq 'osv-scanner') {
            Write-Host '  Searching for the correct package ID:' -ForegroundColor Yellow
            winget search osv-scanner 2>&1 | Out-Host
            Write-Host '  Manual install: https://github.com/google/osv-scanner/releases' -ForegroundColor Yellow
        }
        Add-Result -Measure $DisplayName -Status 'RECOMMENDED' -Detail ('manual install required (' + $Id + ')') -Revert 'n/a'
    }
}

# ---------------------------------------------------------------------------
# Git config section
# ---------------------------------------------------------------------------

function Invoke-HooksPathCheck {
    Write-Step 'GIT CONFIG: core.hooksPath'
    if ($NoHooksPath) {
        Write-Host '[-] core.hooksPath NOT applied because -NoHooksPath was used.' -ForegroundColor DarkGray
        Add-Result -Measure 'core.hooksPath' -Status 'SKIPPED' -Detail '-NoHooksPath requested' -Revert ''
        return
    }
    Write-Host 'WARNING: This disables ALL git hooks globally, including legitimate ones' -ForegroundColor Yellow
    Write-Host '         (husky, pre-commit, secret scanners). Repos cannot push hooks to you' -ForegroundColor Yellow
    Write-Host '         on clone; the real protection is blocking package install scripts' -ForegroundColor Yellow
    Write-Host '         (below) plus staying on patched Git.' -ForegroundColor Yellow
    $current = Get-GitGlobal 'core.hooksPath'
    if ($current -eq '/dev/null') {
        Write-Host ('[ALREADY SET] core.hooksPath = ' + $current) -ForegroundColor Cyan
        Add-Result -Measure 'core.hooksPath' -Status 'ALREADY SET' -Detail $current -Revert 'git config --global --unset core.hooksPath'
    }
    else {
        Set-GitGlobal -Name 'core.hooksPath' -Value '/dev/null' -Measure 'core.hooksPath' -Revert 'git config --global --unset core.hooksPath'
    }
}

function Invoke-ProtocolFileCheck {
    Write-Step 'GIT CONFIG: protocol.file.allow'
    # We intentionally do NOT touch safe.directory. Setting it to "*" disables the
    # ownership protection (CVE-2022-24765 / CVE-2022-29187 mitigations) entirely,
    # which is worse than the occasional 'dubious ownership' error on multi-user
    # machines. Leave it alone.
    $current = Get-GitGlobal 'protocol.file.allow'
    if ($current -eq 'user') {
        Write-Host '[ALREADY SET] protocol.file.allow = user' -ForegroundColor Cyan
        Add-Result -Measure 'protocol.file.allow' -Status 'ALREADY SET' -Detail 'user' -Revert 'git config --global --unset protocol.file.allow'
    }
    else {
        # Blocks local file:// submodule transports (CVE-2022-39253).
        Set-GitGlobal -Name 'protocol.file.allow' -Value 'user' -Measure 'protocol.file.allow' -Revert 'git config --global --unset protocol.file.allow'
    }
}

function Invoke-FsmonitorCheck {
    Write-Step 'GIT CONFIG: core.fsmonitor cleanup'
    # fsmonitor points git at an external hook (a watchman daemon or a custom
    # script) that executes on every file change. A stale or hijacked definition
    # is an avoidable executable-reference attack surface, so we clear it only
    # when something is actually configured (fresh Git installs ship with none).
    $current = Get-GitGlobal 'core.fsmonitor'
    if (-not $current) {
        Write-Host '[OK] core.fsmonitor is not defined globally - nothing to clean.' -ForegroundColor DarkGray
        Add-Result -Measure 'core.fsmonitor' -Status 'ALREADY SET' -Detail 'not defined' -Revert ''
    }
    else {
        Write-Host ('[-] core.fsmonitor was set to: ' + $current) -ForegroundColor Yellow
        if ($DryRun) {
            Write-Host 'DRYRUN: git config --global --unset-all core.fsmonitor' -ForegroundColor Cyan
            Add-Result -Measure 'core.fsmonitor' -Status 'APPLIED' -Detail 'unset (dry-run)' -Revert ('git config --global core.fsmonitor ' + $current)
        }
        else {
            git config --global --unset-all core.fsmonitor 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host '[APPLIED] git config --global --unset-all core.fsmonitor' -ForegroundColor Green
                Add-Result -Measure 'core.fsmonitor' -Status 'APPLIED' -Detail 'unset' -Revert ('git config --global core.fsmonitor ' + $current)
            }
            else {
                Write-Host ('[FAILED]  could not unset core.fsmonitor (was: ' + $current + ')') -ForegroundColor Yellow
                Add-Result -Measure 'core.fsmonitor' -Status 'FAILED' -Detail 'unset failed' -Revert ('git config --global core.fsmonitor ' + $current)
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Package install-script blocking section
# ---------------------------------------------------------------------------

function Invoke-PackageScriptBlocking {
    Write-Step 'PACKAGE INSTALL-SCRIPT BLOCKING'

    # --- npm ---
    $npm = Get-Command npm -ErrorAction SilentlyContinue
    if ($npm) {
        $current = (npm config get ignore-scripts 2>$null | Out-String).Trim()
        if ($DryRun) {
            Write-Host 'DRYRUN: npm config set ignore-scripts true' -ForegroundColor Cyan
            Add-Result -Measure 'npm ignore-scripts' -Status 'APPLIED' -Detail 'true (dry-run)' -Revert 'npm config delete ignore-scripts'
        }
        elseif ($current -eq 'true') {
            Write-Host '[ALREADY SET] npm ignore-scripts = true' -ForegroundColor Cyan
            Add-Result -Measure 'npm ignore-scripts' -Status 'ALREADY SET' -Detail 'true' -Revert 'npm config delete ignore-scripts'
        }
        else {
            npm config set ignore-scripts true 2>$null
            if ($LASTEXITCODE -eq 0) {
                $verify = (npm config get ignore-scripts 2>$null | Out-String).Trim()
                if ($verify -eq 'true') {
                    Write-Host '[APPLIED] npm config set ignore-scripts true' -ForegroundColor Green
                    Add-Result -Measure 'npm ignore-scripts' -Status 'APPLIED' -Detail 'true' -Revert 'npm config delete ignore-scripts'
                }
                else {
                    Write-Host 'WARNING: npm config set did not persist (verify output was "' + $verify + '").' -ForegroundColor Yellow
                    Add-Result -Measure 'npm ignore-scripts' -Status 'FAILED' -Detail 'not persisted' -Revert 'npm config delete ignore-scripts'
                }
            }
            else {
                Write-Host 'WARNING: npm config set ignore-scripts true failed. Check npm installation.' -ForegroundColor Yellow
                Add-Result -Measure 'npm ignore-scripts' -Status 'FAILED' -Detail 'npm config set failed' -Revert 'npm config delete ignore-scripts'
            }
        }
        Write-Host 'NOTE: Some packages require build scripts (esbuild, sharp, electron).' -ForegroundColor DarkGray
        Write-Host '      Run: npm rebuild <pkg> when a package needs its native build.' -ForegroundColor DarkGray
    }
    else {
        Write-Host '[-] npm not found on PATH - skipped.' -ForegroundColor DarkGray
        Add-Result -Measure 'npm ignore-scripts' -Status 'SKIPPED' -Detail 'npm not installed' -Revert ''
    }

    # --- pnpm ---
    $pnpm = Get-Command pnpm -ErrorAction SilentlyContinue
    if ($pnpm) {
        $current = (pnpm config get ignore-scripts 2>$null | Out-String).Trim()
        if ($DryRun) {
            Write-Host 'DRYRUN: pnpm config set ignore-scripts true' -ForegroundColor Cyan
            Add-Result -Measure 'pnpm ignore-scripts' -Status 'APPLIED' -Detail 'true (dry-run)' -Revert 'pnpm config delete ignore-scripts'
        }
        elseif ($current -eq 'true') {
            Write-Host '[ALREADY SET] pnpm ignore-scripts = true' -ForegroundColor Cyan
            Add-Result -Measure 'pnpm ignore-scripts' -Status 'ALREADY SET' -Detail 'true' -Revert 'pnpm config delete ignore-scripts'
        }
        else {
            pnpm config set ignore-scripts true 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host '[APPLIED] pnpm config set ignore-scripts true' -ForegroundColor Green
                Add-Result -Measure 'pnpm ignore-scripts' -Status 'APPLIED' -Detail 'true' -Revert 'pnpm config delete ignore-scripts'
            }
            else {
                Write-Host 'WARNING: pnpm config set ignore-scripts true failed.' -ForegroundColor Yellow
                Add-Result -Measure 'pnpm ignore-scripts' -Status 'FAILED' -Detail 'pnpm config set failed' -Revert 'pnpm config delete ignore-scripts'
            }
        }
    }
    else {
        Write-Host '[-] pnpm not found on PATH - skipped.' -ForegroundColor DarkGray
        Add-Result -Measure 'pnpm ignore-scripts' -Status 'SKIPPED' -Detail 'pnpm not installed' -Revert ''
    }

    # --- yarn (classic only) ---
    $yarn = Get-Command yarn -ErrorAction SilentlyContinue
    if ($yarn) {
        $yarnVersion = (yarn --version 2>$null | Out-String).Trim()
        if ($yarnVersion -match '^1\.') {
            $current = (yarn config get ignore-scripts 2>$null | Out-String).Trim()
            if ($DryRun) {
                Write-Host 'DRYRUN: yarn config set ignore-scripts true' -ForegroundColor Cyan
                Add-Result -Measure 'yarn ignore-scripts' -Status 'APPLIED' -Detail 'true (dry-run)' -Revert 'yarn config delete ignore-scripts'
            }
            elseif ($current -eq 'true') {
                Write-Host '[ALREADY SET] yarn ignore-scripts = true' -ForegroundColor Cyan
                Add-Result -Measure 'yarn ignore-scripts' -Status 'ALREADY SET' -Detail 'true' -Revert 'yarn config delete ignore-scripts'
            }
            else {
                yarn config set ignore-scripts true 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Write-Host '[APPLIED] yarn config set ignore-scripts true' -ForegroundColor Green
                    Add-Result -Measure 'yarn ignore-scripts' -Status 'APPLIED' -Detail 'true' -Revert 'yarn config delete ignore-scripts'
                }
                else {
                    Write-Host 'WARNING: yarn config set ignore-scripts true failed.' -ForegroundColor Yellow
                    Add-Result -Measure 'yarn ignore-scripts' -Status 'FAILED' -Detail 'yarn config set failed' -Revert 'yarn config delete ignore-scripts'
                }
            }
        }
        else {
            Write-Host ('NOTE: Yarn Berry detected (v' + $yarnVersion + '). Classic ignore-scripts config does not apply;') -ForegroundColor Yellow
            Write-Host '      set "enableScripts: false" in the project .yarnrc.yml instead.' -ForegroundColor Yellow
            Add-Result -Measure 'yarn enableScripts' -Status 'RECOMMENDED' -Detail 'Berry: enableScripts: false in .yarnrc.yml' -Revert 'remove enableScripts from .yarnrc.yml'
        }
    }
    else {
        Write-Host '[-] yarn not found on PATH - skipped.' -ForegroundColor DarkGray
        Add-Result -Measure 'yarn ignore-scripts' -Status 'SKIPPED' -Detail 'yarn not installed' -Revert ''
    }

    # --- pip ---
    $pip = Get-Command pip -ErrorAction SilentlyContinue
    if ($pip) {
        if ($PipWheelsOnly) {
            if ($DryRun) {
                Write-Host 'DRYRUN: pip config set global.only-binary ":all:"' -ForegroundColor Cyan
                Add-Result -Measure 'pip only-binary' -Status 'APPLIED' -Detail ':all: (dry-run)' -Revert 'pip config unset global.only-binary'
            }
            else {
                pip config set global.only-binary ':all:' 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Write-Host '[APPLIED] pip config set global.only-binary ":all:"' -ForegroundColor Green
                    Add-Result -Measure 'pip only-binary' -Status 'APPLIED' -Detail ':all:' -Revert 'pip config unset global.only-binary'
                }
                else {
                    Write-Host 'WARNING: pip config set failed. Manually add to %APPDATA%\pip\pip.ini under [global]:' -ForegroundColor Yellow
                    Write-Host '         only-binary = :all:' -ForegroundColor Yellow
                    Add-Result -Measure 'pip only-binary' -Status 'FAILED' -Detail 'pip config set failed' -Revert 'pip config unset global.only-binary'
                }
            }
            Write-Host 'TRADEOFF: Packages without a prebuilt wheel (e.g. some native builds) will fail' -ForegroundColor Yellow
            Write-Host '          to install. Undo with: pip config unset global.only-binary' -ForegroundColor Yellow
            Write-Host '          NOTE: inside a virtualenv this setting applies to that venv only.' -ForegroundColor DarkGray
        }
        else {
            Write-Host 'RECOMMENDED: pip cannot globally disable build execution.' -ForegroundColor Yellow
            Write-Host '      Prefer wheels: pip install --only-binary=:all: <pkg>' -ForegroundColor Yellow
            Write-Host '      Or use `pipx` for CLI tools and a dedicated venv for projects.' -ForegroundColor Yellow
            Add-Result -Measure 'pip only-binary' -Status 'RECOMMENDED' -Detail 'pip install --only-binary=:all: or pipx/venv' -Revert 'n/a'
        }
    }
    else {
        Write-Host '[-] pip not found on PATH - skipped.' -ForegroundColor DarkGray
        Add-Result -Measure 'pip only-binary' -Status 'SKIPPED' -Detail 'pip not installed' -Revert ''
    }

    # --- cargo ---
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if ($cargo) {
        if ($InstallTools) {
            if ($DryRun) {
                Write-Host 'DRYRUN: cargo install cargo-audit --locked' -ForegroundColor Cyan
                Add-Result -Measure 'cargo-audit' -Status 'APPLIED' -Detail 'installed (dry-run)' -Revert 'cargo uninstall cargo-audit'
            }
            else {
                Write-Host 'Installing cargo-audit (compiles from source, may take a few minutes)...' -ForegroundColor Cyan
                cargo install cargo-audit --locked 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-Host '[APPLIED] cargo install cargo-audit --locked' -ForegroundColor Green
                    Add-Result -Measure 'cargo-audit' -Status 'APPLIED' -Detail 'installed' -Revert 'cargo uninstall cargo-audit'
                }
                else {
                    Write-Host 'WARNING: cargo install cargo-audit failed. Install it manually.' -ForegroundColor Yellow
                    Add-Result -Measure 'cargo-audit' -Status 'FAILED' -Detail 'cargo install failed' -Revert 'cargo uninstall cargo-audit'
                }
            }
        }
        else {
            Write-Host 'RECOMMENDED: cargo-audit catches known vulnerable dependencies.' -ForegroundColor Yellow
            Write-Host '      Install with: cargo install cargo-audit --locked' -ForegroundColor Yellow
            Add-Result -Measure 'cargo-audit' -Status 'RECOMMENDED' -Detail 'cargo install cargo-audit --locked' -Revert 'cargo uninstall cargo-audit'
        }
        Write-Host 'NOTE: cargo always compiles and runs build.rs - there is NO flag to disable it.' -ForegroundColor DarkGray
        Write-Host '      Review build.rs manually or build in a sandbox.' -ForegroundColor DarkGray
    }
    else {
        Write-Host '[-] cargo not found on PATH - skipped.' -ForegroundColor DarkGray
        Add-Result -Measure 'cargo-audit' -Status 'SKIPPED' -Detail 'cargo not installed' -Revert ''
    }
}

# ---------------------------------------------------------------------------
# Security tools section
# ---------------------------------------------------------------------------

function Invoke-ToolsInstall {
    Write-Step 'SECURITY TOOLS'

    $gitleaks = Get-Command gitleaks -ErrorAction SilentlyContinue
    if ($gitleaks) {
        Write-Host ('[ALREADY INSTALLED] gitleaks at ' + $gitleaks.Source) -ForegroundColor Cyan
        Add-Result -Measure 'gitleaks' -Status 'ALREADY SET' -Detail ('found: ' + $gitleaks.Source) -Revert ''
    }
    elseif ($InstallTools) {
        Install-WingetPackage -Id 'gitleaks.gitleaks' -DisplayName 'gitleaks'
    }
    else {
        Write-Host 'RECOMMENDED: install gitleaks to scan cloned repos for secrets.' -ForegroundColor Yellow
        Write-Host '      winget install gitleaks.gitleaks --scope user' -ForegroundColor Yellow
        Add-Result -Measure 'gitleaks' -Status 'RECOMMENDED' -Detail 'winget install gitleaks.gitleaks --scope user' -Revert 'n/a'
    }

    $osv = Get-Command osv-scanner -ErrorAction SilentlyContinue
    if ($osv) {
        Write-Host ('[ALREADY INSTALLED] osv-scanner at ' + $osv.Source) -ForegroundColor Cyan
        Add-Result -Measure 'osv-scanner' -Status 'ALREADY SET' -Detail ('found: ' + $osv.Source) -Revert ''
    }
    elseif ($InstallTools) {
        Install-WingetPackage -Id 'Google.OSV-Scanner' -DisplayName 'osv-scanner'
    }
    else {
        Write-Host 'RECOMMENDED: install osv-scanner to scan lockfiles for known vulnerabilities.' -ForegroundColor Yellow
        Write-Host '      winget install Google.OSV-Scanner --scope user' -ForegroundColor Yellow
        Write-Host '      (if that ID is not found, see https://github.com/google/osv-scanner/releases)' -ForegroundColor DarkGray
        Add-Result -Measure 'osv-scanner' -Status 'RECOMMENDED' -Detail 'winget install Google.OSV-Scanner --scope user' -Revert 'n/a'
    }
}

# ---------------------------------------------------------------------------
# Summary section
# ---------------------------------------------------------------------------

function Show-Summary {
    Write-Host ''
    Write-Host '======================================================' -ForegroundColor Magenta
    Write-Host '                      SUMMARY' -ForegroundColor Magenta
    Write-Host '======================================================' -ForegroundColor Magenta

    foreach ($r in $script:results) {
        $color = switch ($r.Status) {
            'APPLIED'     { 'Green' }
            'ALREADY SET' { 'Cyan' }
            'SKIPPED'     { 'DarkGray' }
            'RECOMMENDED' { 'Yellow' }
            'PASS'        { 'Green' }
            'FAILED'      { 'Red' }
            default       { 'White' }
        }
        $measurePad = [Math]::Max(1, 24 - $r.Measure.Length)
        $statusPad  = [Math]::Max(1, 12 - $r.Status.Length)
        Write-Host ('[' + $r.Status + (' ' * $statusPad) + '] ' + $r.Measure + (' ' * $measurePad) + $r.Detail) -ForegroundColor $color
    }

    $reverts = @($script:results | Where-Object { $_.Revert -and $_.Revert -ne 'n/a' })
    if ($reverts.Count -gt 0) {
        Write-Host ''
        Write-Host 'REVERT COMMANDS:' -ForegroundColor Cyan
        foreach ($r in $reverts) {
            Write-Host ('  ' + $r.Measure + ': ' + $r.Revert) -ForegroundColor Cyan
        }
    }
    Write-Host '======================================================' -ForegroundColor Magenta
}

# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if (-not $gitCmd) {
    Write-Host 'ERROR: git was not found on PATH.' -ForegroundColor Red
    Write-Host '  Action: install Git for Windows from https://git-scm.com/download/win' -ForegroundColor Yellow
    Write-Host '         and re-run this script from a new terminal.' -ForegroundColor Yellow
    exit 1
}

if ($DryRun) {
    Write-Host 'DRY RUN MODE: no changes will be made. Commands are printed for review.' -ForegroundColor Magenta
}

Write-Step 'GIT VERSION CHECK (CVE-2024-32002)'
$gitVersion = Get-GitVersion
if (-not $gitVersion) {
    Write-Host 'ERROR: could not parse git version output.' -ForegroundColor Red
    Write-Host '  Action: run "git --version" and confirm git is installed correctly.' -ForegroundColor Yellow
    exit 1
}
Write-Host ('  git: ' + $gitVersion.Raw) -ForegroundColor White

$atLeast452 = Test-GitVersionAtLeast $gitVersion 2 45 2
$atLeast460 = Test-GitVersionAtLeast $gitVersion 2 46 0

if (-not $atLeast452) {
    Write-Host 'CRITICAL WARNING: git < 2.45.2 - vulnerable to CVE-2024-32002.' -ForegroundColor Red
    Write-Host '  Malicious submodules can write into .git/hooks during clone, giving' -ForegroundColor Red
    Write-Host '  remote code execution on a plain "git clone".' -ForegroundColor Red
    Write-Host '  Action: upgrade NOW to git >= 2.46.0 (fully patched).' -ForegroundColor Yellow
    Add-Result -Measure 'git version' -Status 'FAILED' -Detail ($gitVersion.Raw + ' - CVE-2024-32002') -Revert 'upgrade git to >= 2.46.0'
}
elseif ($atLeast460) {
    Write-Host '[PASS] git >= 2.46.0 - fully patched against clone-time RCE.' -ForegroundColor Green
    Add-Result -Measure 'git version' -Status 'PASS' -Detail $gitVersion.Raw -Revert ''
}
else {
    Write-Host '[PASS] git >= 2.45.2 - contains the initial CVE-2024-32002 fix.' -ForegroundColor Green
    Write-Host '  NOTE: 2.46.0 is the version with the complete follow-up fixes; upgrade when possible.' -ForegroundColor Yellow
    Add-Result -Measure 'git version' -Status 'PASS' -Detail ($gitVersion.Raw + ' (2.46.0 recommended)') -Revert ''
}

Invoke-HooksPathCheck
Invoke-ProtocolFileCheck
Invoke-FsmonitorCheck
Invoke-PackageScriptBlocking
Invoke-ToolsInstall
Show-Summary

Write-Host ''
Write-Host 'Done. Re-run with -DryRun to review, or -NoHooksPath to skip global hook disabling.' -ForegroundColor DarkGray
exit 0
