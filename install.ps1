<#
.SYNOPSIS
    Installs the dev-repo-security-kit scripts for the current user.

.DESCRIPTION
    Downloads hardening.ps1 and repo-check.ps1 from the dev-repo-security-kit
    repository (main branch) into $HOME\.dev-security-kit\ and validates the
    downloaded scripts with the PowerShell parser before reporting success.

    This is a per-user install: no administrator elevation required. It only
    writes files under the user's home directory.

    To update later, simply re-run this script. It overwrites the two scripts
    in place.

.PARAMETER SkipPathNote
    Do not print the PATH setup note at the end of the run.

.EXAMPLE
    .\install.ps1

.EXAMPLE
    .\install.ps1 -SkipPathNote
#>
[CmdletBinding()]
param(
    [switch]$SkipPathNote
)

Set-StrictMode -Version 2.0

$BaseUrl = 'https://raw.githubusercontent.com/jadatorin/dev-repo-security-kit/main'
$Files    = @('hardening.ps1', 'repo-check.ps1')
$Install  = Join-Path $HOME '.dev-security-kit'

function Test-ScriptSyntax {
    param([string]$FilePath)
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $FilePath,
        [ref]$tokens,
        [ref]$errors
    ) | Out-Null
    return @($errors).Count -eq 0
}

Write-Host 'dev-repo-security-kit installer' -ForegroundColor Cyan
Write-Host '===============================' -ForegroundColor Cyan
Write-Host ('Installing to: ' + $Install)
Write-Host ''

if (-not (Test-Path -LiteralPath $Install)) {
    New-Item -ItemType Directory -Path $Install | Out-Null
    Write-Host ('Created directory: ' + $Install) -ForegroundColor Green
}

$failures = New-Object System.Collections.Generic.List[string]

foreach ($file in $Files) {
    $url  = $BaseUrl + '/' + $file
    $dest = Join-Path $Install $file
    Write-Host ('Downloading ' + $file + ' ...')

    try {
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -ErrorAction Stop
    }
    catch {
        Write-Host ('ERROR: could not download ' + $url) -ForegroundColor Red
        Write-Host ('  ' + $_.Exception.Message) -ForegroundColor Yellow
        $failures.Add($file)
        continue
    }

    if (-not (Test-ScriptSyntax -FilePath $dest)) {
        Write-Host ('ERROR: syntax validation FAILED for ' + $file + ' - file was not installed.') -ForegroundColor Red
        $failures.Add($file)
        continue
    }

    Write-Host ('  OK: downloaded and syntax-checked (' + $dest + ')') -ForegroundColor Green
}

Write-Host ''

if ($failures.Count -gt 0) {
    Write-Host 'INSTALL INCOMPLETE - the following files could not be installed:' -ForegroundColor Red
    foreach ($f in $failures) {
        Write-Host ('  - ' + $f) -ForegroundColor Red
    }
    Write-Host '  Check your network / proxy, then re-run this script.' -ForegroundColor Yellow
    exit 1
}

Write-Host 'Install complete.' -ForegroundColor Green
Write-Host ''
Write-Host ('Installed scripts:') -ForegroundColor Cyan
Write-Host ('  ' + (Join-Path $Install 'hardening.ps1')) -ForegroundColor Cyan
Write-Host ('  ' + (Join-Path $Install 'repo-check.ps1')) -ForegroundColor Cyan
Write-Host ''
Write-Host 'How to run:' -ForegroundColor Cyan
Write-Host ('  & "' + (Join-Path $Install 'hardening.ps1') + '" -DryRun') -ForegroundColor White
Write-Host ('  & "' + (Join-Path $Install 'repo-check.ps1') + '" -Url https://github.com/owner/repo') -ForegroundColor White
Write-Host ('  & "' + (Join-Path $Install 'repo-check.ps1') + '" -Path C:\dev\repo') -ForegroundColor White
Write-Host ''
Write-Host 'How to update:' -ForegroundColor Cyan
Write-Host '  Re-run this installer at any time. It overwrites the two scripts in place.' -ForegroundColor White
Write-Host ''

if (-not $SkipPathNote) {
    Write-Host 'NOTE: add the install folder to your PATH so the scripts are callable from anywhere:' -ForegroundColor Yellow
    Write-Host ('  [Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";" + "' + $Install + '", "User")') -ForegroundColor Yellow
    Write-Host '  Then open a new terminal so the change takes effect.' -ForegroundColor Yellow
}

exit 0
