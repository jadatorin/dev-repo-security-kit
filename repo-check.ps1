<#
.SYNOPSIS
    Assesses the risk of a Git repository BEFORE cloning (URL) or AFTER cloning (local path).

.DESCRIPTION
    Checks transport/URL security, cloned-repo attack vectors (active hooks,
    submodules, VS Code tasks, package install scripts, Python build backends,
    build.rs, Docker, Makefile), suspicious/executable files, credential bait,
    minified/obfuscated source, secrets (gitleaks or built-in regex fallback),
    vulnerable dependencies (osv-scanner) and optional SAST (semgrep).

    Ends with a verdict: PASS (0), WARN (1) or FAIL (2).

.PARAMETER Url
    A remote repository URL to validate before cloning (https, ssh, git@...).

.PARAMETER Path
    A local repository folder. When omitted, the current directory is used.

.PARAMETER NoGitleaks
    Do not run gitleaks even if it is installed.

.PARAMETER NoOsv
    Do not run osv-scanner even if it is installed.

.PARAMETER NoSemgrep
    Do not run semgrep even if it is installed.

.EXAMPLE
    .\repo-check.ps1 -Url https://github.com/octocat/Hello-World

.EXAMPLE
    .\repo-check.ps1 -Path C:\dev\some-repo

.EXAMPLE
    .\repo-check.ps1

.EXAMPLE
    .\repo-check.ps1 -Url git@github.com:octocat/Hello-World.git -NoSemgrep
#>
[CmdletBinding(DefaultParameterSetName='Path')]
param(
    [Parameter(Mandatory=$true, ParameterSetName='Url')]
    [string]$Url,
    [Parameter(ParameterSetName='Path')]
    [string]$Path,
    [switch]$NoGitleaks,
    [switch]$NoOsv,
    [switch]$NoSemgrep
)

Set-StrictMode -Version 2.0

$script:findings = New-Object System.Collections.Generic.List[object]

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

function Write-Step {
    param([string]$Title)
    $pad = [Math]::Max(2, 74 - $Title.Length)
    Write-Host ''
    Write-Host ('--- ' + $Title + ('-' * $pad)) -ForegroundColor Cyan
}

function Add-Finding {
    param(
        [ValidateSet('HIGH','WARN','LOW','RECOMMENDED','INFO')]
        [string]$Level,
        [string]$Message
    )
    $script:findings.Add([pscustomobject]@{ Level = $Level; Message = $Message })
    switch ($Level) {
        'HIGH'        { Write-Host ('[HIGH]  ' + $Message) -ForegroundColor Red }
        'WARN'        { Write-Host ('[WARN]  ' + $Message) -ForegroundColor Yellow }
        'LOW'         { Write-Host ('[LOW]   ' + $Message) -ForegroundColor DarkYellow }
        'RECOMMENDED' { Write-Host ('[INFO]  ' + $Message) -ForegroundColor Magenta }
        'INFO'        { Write-Host ('[INFO]  ' + $Message) -ForegroundColor Cyan }
    }
}

function Get-RelPath {
    param([string]$Root, [string]$Full)
    if ($Full.StartsWith($Root, [System.StringComparison]::OrdinalIgnoreCase)) {
        $rel = $Full.Substring($Root.Length)
        if ($rel.StartsWith('\')) { $rel = $rel.Substring(1) }
        return $rel
    }
    return [System.IO.Path]::GetFileName($Full)
}

function Test-SingleLongLine {
    param([string]$FilePath, [int]$Threshold = 2000)
    $reader = [System.IO.StreamReader]::new($FilePath)
    try {
        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            if ($line.Length -gt $Threshold) { return $true }
        }
    }
    catch {
        return $false
    }
    finally {
        $reader.Dispose()
    }
    return $false
}

function Show-Summary {
    Write-Host ''
    Write-Host '======================================================' -ForegroundColor Magenta
    Write-Host '                      SUMMARY' -ForegroundColor Magenta
    Write-Host '======================================================' -ForegroundColor Magenta
    if ($script:findings.Count -eq 0) {
        Write-Host '  (no findings recorded)' -ForegroundColor DarkGray
    }
    foreach ($f in $script:findings) {
        $color = switch ($f.Level) {
            'HIGH'        { 'Red' }
            'WARN'        { 'Yellow' }
            'LOW'         { 'DarkYellow' }
            'RECOMMENDED' { 'Magenta' }
            default       { 'Cyan' }
        }
        Write-Host ('  [' + $f.Level.PadRight(12) + '] ' + $f.Message) -ForegroundColor $color
    }
    Write-Host '======================================================' -ForegroundColor Magenta
}

# ---------------------------------------------------------------------------
# URL mode
# ---------------------------------------------------------------------------

function New-RepoIdentity {
    param([string]$HostPart, [string]$PathPart)
    $hostOnly = ($HostPart -split ':')[0]
    $pathOnly = $PathPart.TrimEnd('/')
    if ($pathOnly -match '^(?<owner>[^/]+)/(?<repo>[^/]+)$') {
        $repoName = $Matches['repo'] -replace '\.git$', ''
        return [pscustomobject]@{ Host = $hostOnly; Owner = $Matches['owner']; Repo = $repoName }
    }
    return $null
}

function Get-RepoIdentity {
    param([string]$InputUrl)
    $s = $InputUrl.Trim()
    if ($s -match '^git@([^:]+):(.+)$') {
        return New-RepoIdentity -HostPart $Matches[1] -PathPart $Matches[2]
    }
    if ($s -match '^[a-zA-Z][a-zA-Z0-9+.\-]*://([^/]+)/(.+)$') {
        return New-RepoIdentity -HostPart $Matches[1] -PathPart $Matches[2]
    }
    if ($s -match '^([^/]+)/(.+)$') {
        return New-RepoIdentity -HostPart $Matches[1] -PathPart $Matches[2]
    }
    return $null
}

function Test-UrlScheme {
    param([string]$InputUrl)
    if ($InputUrl -match '^file:') {
        Add-Finding 'HIGH' 'file:// transport is rejected: local path clones can trigger CVE-2022-39253-style abuse.'
        return $false
    }
    if ($InputUrl -match '^git:') {
        Add-Finding 'HIGH' 'git:// transport is rejected: unauthenticated and vulnerable to MITM attacks.'
        return $false
    }
    if ($InputUrl -match '^https://') {
        Add-Finding 'INFO' 'https transport - encrypted.'
    }
    elseif ($InputUrl -match '^http://') {
        Add-Finding 'WARN' 'http:// is unencrypted (MITM risk). Rewrite the URL to https:// before cloning.'
    }
    elseif ($InputUrl -match '^git@' -or $InputUrl -match '^(ssh|git\+ssh|ssh\+git)://') {
        Add-Finding 'WARN' 'SSH transport detected - ensure your SSH key is passphrase-protected and the host is trusted.'
    }
    if ($InputUrl -match '^[a-zA-Z][a-zA-Z0-9+.\-]*://[^/]+@') {
        Add-Finding 'WARN' 'The URL embeds credentials (user@). Prefer a credential helper; embedded credentials can leak.'
    }
    return $true
}

function Invoke-UrlCheck {
    param([string]$InputUrl)
    Write-Step ('URL CHECK: ' + $InputUrl)

    if (-not (Test-UrlScheme $InputUrl)) {
        Write-Host ''
        Write-Host ('ABORTED: unsafe transport for ' + $InputUrl) -ForegroundColor Red
        exit 1
    }

    $identity = Get-RepoIdentity -InputUrl $InputUrl
    if (-not $identity) {
        Write-Host 'ERROR: could not parse owner/repo from the URL.' -ForegroundColor Red
        Write-Host '  Expected: https://host/owner/repo  (or ssh, or git@host:owner/repo.git)' -ForegroundColor Yellow
        exit 1
    }
    Write-Host ('  host  : ' + $identity.Host) -ForegroundColor White
    Write-Host ('  owner : ' + $identity.Owner) -ForegroundColor White
    Write-Host ('  repo  : ' + $identity.Repo) -ForegroundColor White

    Write-Host ''
    Write-Host 'Checking remote repository availability with git ls-remote...' -ForegroundColor Cyan
    $output = git ls-remote $InputUrl 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host '[OK] repository is reachable.' -ForegroundColor Green
        Add-Finding 'INFO' 'repository exists and is accessible.'
    }
    else {
        Write-Host '[FAIL] repository is NOT reachable.' -ForegroundColor Red
        $errText = ($output | Out-String).Trim()
        if ($errText) {
            $errText -split "`r?`n" | ForEach-Object {
                if ($_) { Write-Host ('  ' + $_) -ForegroundColor Yellow }
            }
        }
        Write-Host '  Check the URL, your network, and your SSH key / credentials.' -ForegroundColor Yellow
        Write-Host ''
        Show-Summary
        Write-Host ('VERDICT: FAIL (exit 1) - repository not reachable: ' + $InputUrl) -ForegroundColor Red
        exit 1
    }

    Write-Host ''
    Write-Host 'WARNING: Do NOT clone with --recurse-submodules unless you trust the repo.' -ForegroundColor Yellow
    Write-Host '         CVE-2024-32002: malicious submodules can run code during clone.' -ForegroundColor Yellow
    Write-Host '         Review .gitmodules AFTER cloning before git submodule update.' -ForegroundColor Yellow
    Add-Finding 'INFO' 'reminder: avoid --recurse-submodules on untrusted repos (CVE-2024-32002).'

    Show-Summary
    Write-Host ''
    Write-Host ('VERDICT: PASS (exit 0) - reachable and transport safe: ' + $identity.Host + '/' + $identity.Owner + '/' + $identity.Repo) -ForegroundColor Green
    exit 0
}

# ---------------------------------------------------------------------------
# Path mode
# ---------------------------------------------------------------------------

function Invoke-RegexSecretScan {
    param([string]$Root, $Files)
    $patterns = @(
        @{ Name = 'AWS Access Key';     Regex = 'AKIA[0-9A-Z]{16}' },
        @{ Name = 'GitHub Token';       Regex = 'gh[pousr]_[A-Za-z0-9]{36,}' },
        @{ Name = 'Private Key Header'; Regex = '-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----' }
    )
    $total = 0
    $scanned = 0
    foreach ($f in $Files) {
        if ($scanned -ge 500) { break }
        if ($f.Length -gt 1MB) { continue }
        $scanned++
        $content = ''
        try {
            $content = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
        }
        catch {
            continue
        }
        foreach ($p in $patterns) {
            $matches = [regex]::Matches($content, $p.Regex)
            if ($matches.Count -gt 0) {
                $total += $matches.Count
                $rel = Get-RelPath -Root $Root -Full $f.FullName
                Add-Finding 'HIGH' ('Possible ' + $p.Name + ' in ' + $rel + ' (count: ' + $matches.Count + ') [REDACTED]')
            }
        }
    }
    if ($total -eq 0) {
        Add-Finding 'INFO' 'regex fallback: no high-entropy credential patterns matched.'
    }
    return $total
}

function Invoke-PathCheck {
    param([string]$RepoPath)
    Write-Step ('PATH CHECK: ' + $RepoPath)

    # 1. Confirm it is a Git repository (may be a file in linked worktrees).
    $gitEntry = Join-Path $RepoPath '.git'
    $isRepo = (Test-Path -LiteralPath $gitEntry -PathType Container) -or
              (Test-Path -LiteralPath $gitEntry -PathType Leaf)
    if (-not $isRepo) {
        Write-Host ('ERROR: ' + $RepoPath + ' is not a Git repository (.git missing).') -ForegroundColor Red
        Write-Host '  If you meant to check a remote, use -Url instead.' -ForegroundColor Yellow
        exit 2
    }

    # 2. Active hooks (exclude *.sample and sample* files).
    Write-Step 'ACTIVE GIT HOOKS'
    $hookCount = 0
    $hooksDir = Join-Path $RepoPath '.git\hooks'
    if (Test-Path -LiteralPath $hooksDir) {
        $hooks = @(Get-ChildItem -LiteralPath $hooksDir -File -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -notlike '*.sample' -and $_.Name -notlike 'sample*' })
        $hookCount = $hooks.Count
        if ($hookCount -gt 0) {
            Add-Finding 'HIGH' ('Active git hooks found (' + $hookCount + '): ' + (($hooks | ForEach-Object { $_.Name }) -join ', '))
            Write-Host '  Who installed them? A package postinstall hook is the usual suspect.' -ForegroundColor Yellow
        }
        else {
            Add-Finding 'INFO' 'no active git hooks (only *.sample files).'
        }
    }
    else {
        Add-Finding 'INFO' 'no hooks directory present.'
    }

    # 3. Submodules.
    Write-Step 'SUBMODULES'
    $submoduleCount = 0
    $gitmodulesPath = Join-Path $RepoPath '.gitmodules'
    if (Test-Path -LiteralPath $gitmodulesPath) {
        $submodules = New-Object System.Collections.Generic.List[object]
        $currentSub = $null
        foreach ($line in (Get-Content -LiteralPath $gitmodulesPath)) {
            if ($line -match '^\[submodule\s+"(?<name>[^"]+)"\]') {
                $currentSub = [pscustomobject]@{ Name = $Matches['name']; Path = ''; Url = '' }
                $submodules.Add($currentSub)
            }
            elseif ($currentSub -and $line -match '^\s*path\s*=\s*(?<path>.+)$') {
                $currentSub.Path = $Matches['path']
            }
            elseif ($currentSub -and $line -match '^\s*url\s*=\s*(?<url>.+)$') {
                $currentSub.Url = $Matches['url']
            }
        }
        $submoduleCount = $submodules.Count
        Add-Finding 'HIGH' ('Submodules declared in .gitmodules (' + $submoduleCount + '):')
        foreach ($sm in $submodules) {
            Write-Host ('    - ' + $sm.Path + '  ->  ' + $sm.Url) -ForegroundColor Yellow
        }
        Write-Host '  WARNING: review every submodule URL and its contents BEFORE git submodule update.' -ForegroundColor Yellow
    }
    else {
        Add-Finding 'INFO' 'no .gitmodules file.'
    }

    # 4. VS Code task / launch vectors.
    Write-Step 'EDITOR EXECUTION VECTORS'
    $vsCodeKeys = New-Object System.Collections.Generic.List[string]
    foreach ($file in @('tasks.json', 'launch.json')) {
        $filePath = Join-Path $RepoPath ('.vscode\' + $file)
        if (Test-Path -LiteralPath $filePath) {
            $content = Get-Content -LiteralPath $filePath -Raw -ErrorAction SilentlyContinue
            if ($content) {
                foreach ($key in @('preLaunchTask', 'dependsOn', 'command', 'script')) {
                    if ($content -match ('"' + $key + '"')) {
                        $vsCodeKeys.Add($file + ':' + $key)
                    }
                }
            }
        }
    }
    if ($vsCodeKeys.Count -gt 0) {
        Add-Finding 'WARN' ('VS Code task execution vectors: ' + ($vsCodeKeys -join ', '))
        Write-Host '  VS Code only runs tasks in Trusted Workspaces - enable Workspace Trust' -ForegroundColor Yellow
        Write-Host '  ONLY for repos you trust.' -ForegroundColor Yellow
    }
    else {
        Add-Finding 'INFO' 'no VS Code task/launch execution vectors found.'
    }

    # 5. Package install/build script vectors.
    Write-Step 'PACKAGE INSTALL-SCRIPT VECTORS'
    $pkgScriptCount = 0
    $pkgJsonPath = Join-Path $RepoPath 'package.json'
    if (Test-Path -LiteralPath $pkgJsonPath) {
        try {
            $pkg = Get-Content -LiteralPath $pkgJsonPath -Raw -ErrorAction Stop | ConvertFrom-Json
            $scriptNames = @()
            if ($pkg.PSObject.Properties['scripts']) {
                $scriptNames = @($pkg.scripts.PSObject.Properties.Name)
            }
            foreach ($key in @('preinstall', 'postinstall', 'prepare', 'prepublish', 'install', 'prebuild', 'postbuild')) {
                if ($scriptNames -contains $key) {
                    $scriptText = [string]$pkg.scripts.$key
                    if ($scriptText.Length -gt 160) { $scriptText = $scriptText.Substring(0, 160) + '...' }
                    $pkgScriptCount++
                    Add-Finding 'HIGH' ('package.json script "' + $key + '" present: ' + $scriptText)
                }
            }
            if ($pkgScriptCount -eq 0) {
                Add-Finding 'INFO' 'package.json has no install/build lifecycle scripts.'
            }
        }
        catch {
            Add-Finding 'WARN' 'package.json could not be parsed (malformed JSON?).'
        }
    }
    foreach ($f in @('pnpm-workspace.yaml', 'yarn.lock')) {
        if (Test-Path -LiteralPath (Join-Path $RepoPath $f)) {
            Add-Finding 'INFO' ($f + ' present (package manager workspace).')
        }
    }
    foreach ($f in @('pyproject.toml', 'setup.py', 'setup.cfg')) {
        if (Test-Path -LiteralPath (Join-Path $RepoPath $f)) {
            if ($f -eq 'pyproject.toml') {
                Add-Finding 'HIGH' 'pyproject.toml found - pip executes its build backend (PEP 517) at install time.'
                Write-Host '    If this repo is NOT from a trusted source, use: pip install --only-binary=:all: <pkg>' -ForegroundColor Yellow
            }
            else {
                Add-Finding 'WARN' ($f + ' found - installing this package may execute arbitrary code.')
            }
        }
    }
    if (Test-Path -LiteralPath (Join-Path $RepoPath 'build.rs')) {
        Add-Finding 'HIGH' 'build.rs found - cargo compiles AND runs it on every build.'
        Write-Host '    Review it manually or build in a sandbox; there is no flag to disable it.' -ForegroundColor Yellow
    }
    foreach ($f in @('Dockerfile', 'docker-compose.yml', 'docker-compose.yaml')) {
        if (Test-Path -LiteralPath (Join-Path $RepoPath $f)) {
            Add-Finding 'WARN' ($f + ' found - "docker build" executes RUN instructions. Build untrusted repos in a sandbox.')
        }
    }
    if (Test-Path -LiteralPath (Join-Path $RepoPath 'Makefile')) {
        Add-Finding 'LOW' 'Makefile found - runs only when you explicitly run make. Review targets first.'
    }

    # 6. Suspicious / executable file scan.
    # We enumerate with -Force so hidden bait files (.env, .npmrc) are visible,
    # then drop .git and node_modules to keep the scan fast and relevant.
    Write-Step 'SUSPICIOUS / EXECUTABLE FILE SCAN'
    $allFiles = @(Get-ChildItem -LiteralPath $RepoPath -Recurse -File -Force -ErrorAction SilentlyContinue |
                  Where-Object { $_.FullName -notlike '*\.git\*' -and $_.FullName -notlike '*\node_modules\*' })

    $binaryExtensions = @('.exe', '.dll', '.scr', '.com')
    $scriptExtensions = @('.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.sh')
    $execExtensions = @($binaryExtensions + $scriptExtensions)

    $execFiles = @($allFiles | Where-Object { $execExtensions -contains $_.Extension.ToLowerInvariant() })
    $binaryCount = @($execFiles | Where-Object { $binaryExtensions -contains $_.Extension.ToLowerInvariant() }).Count
    $execCount = $execFiles.Count

    if ($execCount -gt 0) {
        Add-Finding 'WARN' ('Executable/script files found in tree: ' + $execCount)
        $rootExec = @($execFiles | Where-Object { -not (Get-RelPath -Root $RepoPath -Full $_.FullName).Contains('\') })
        if ($rootExec.Count -gt 0) {
            Write-Host '  At repository root:' -ForegroundColor Yellow
            foreach ($f in $rootExec) {
                $rel = Get-RelPath -Root $RepoPath -Full $f.FullName
                $kb = [math]::Round($f.Length / 1KB, 1)
                Write-Host ('    - ' + $rel + '  (' + $kb + ' KB)') -ForegroundColor Yellow
            }
        }
        $nonRootExec = @($execFiles | Where-Object { (Get-RelPath -Root $RepoPath -Full $_.FullName).Contains('\') })
        if ($nonRootExec.Count -gt 0) {
            if ($nonRootExec.Count -gt 10) {
                $top = @($nonRootExec | Sort-Object Length -Descending | Select-Object -First 10)
                Write-Host ('  Top 10 of ' + $nonRootExec.Count + ' non-root by size:' ) -ForegroundColor Yellow
                foreach ($f in $top) {
                    $rel = Get-RelPath -Root $RepoPath -Full $f.FullName
                    $kb = [math]::Round($f.Length / 1KB, 1)
                    Write-Host ('    - ' + $rel + '  (' + $kb + ' KB)') -ForegroundColor Yellow
                }
            }
            else {
                Write-Host '  In subdirectories:' -ForegroundColor Yellow
                foreach ($f in $nonRootExec) {
                    $rel = Get-RelPath -Root $RepoPath -Full $f.FullName
                    $kb = [math]::Round($f.Length / 1KB, 1)
                    Write-Host ('    - ' + $rel + '  (' + $kb + ' KB)') -ForegroundColor Yellow
                }
            }
        }
    }
    else {
        Add-Finding 'INFO' 'no executable/script files found in tree.'
    }

    # 6b. Credential bait files.
    $baitFound = New-Object System.Collections.Generic.List[object]
    foreach ($f in $allFiles) {
        $ext = $f.Extension.ToLowerInvariant()
        $isBait = ($f.Name -eq '.env') -or ($f.Name -eq 'id_rsa') -or ($f.Name -eq 'id_ed25519') -or
                  ($f.Name -eq 'credentials.json') -or ($ext -in @('.pem', '.key', '.pfx'))
        if ($isBait) { $baitFound.Add($f) }
    }
    foreach ($f in @($allFiles | Where-Object { $_.Name -eq '.npmrc' })) {
        $content = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -and ($content -match '_authToken' -or $content -match '(?im)^\s*_auth\s*=')) {
            $baitFound.Add($f)
        }
    }
    $credBaitCount = $baitFound.Count
    if ($credBaitCount -gt 0) {
        Add-Finding 'HIGH' ('Potential credential bait files found: ' + $credBaitCount)
        foreach ($f in $baitFound) {
            $rel = Get-RelPath -Root $RepoPath -Full $f.FullName
            $kb = [math]::Round($f.Length / 1KB, 1)
            Write-Host ('    - ' + $rel + '  (' + $kb + ' KB)') -ForegroundColor Red
        }
        Write-Host '  Never use credentials found inside a cloned repository - treat them as hostile.' -ForegroundColor Yellow
    }

    # 6c. Minified / obfuscated source (single line over 2000 chars).
    $minifiedCount = 0
    $minified = New-Object System.Collections.Generic.List[object]
    foreach ($f in @($allFiles | Where-Object { $_.Extension.ToLowerInvariant() -in @('.js', '.py') -and $_.Length -lt 5MB })) {
        if (Test-SingleLongLine -FilePath $f.FullName -Threshold 2000) {
            $minified.Add($f)
        }
    }
    $minifiedCount = $minified.Count
    if ($minifiedCount -gt 0) {
        Add-Finding 'WARN' ('Possible obfuscated/minified source files: ' + $minifiedCount)
        $top5 = @($minified | Select-Object -First 5)
        foreach ($f in $top5) {
            $rel = Get-RelPath -Root $RepoPath -Full $f.FullName
            Write-Host ('    - ' + $rel) -ForegroundColor Yellow
        }
        if ($minifiedCount -gt 5) {
            Write-Host ('    ... and ' + ($minifiedCount - 5) + ' more.') -ForegroundColor DarkGray
        }
    }

    if (Test-Path -LiteralPath (Join-Path $RepoPath 'npm-shrinkwrap.json')) {
        Add-Finding 'INFO' 'npm-shrinkwrap.json present (supply-chain pinning). Verify it matches package.json.'
    }

    # 7. Secrets.
    Write-Step 'SECRET SCANNING'
    $secretFindings = 0
    $gitleaks = Get-Command gitleaks -ErrorAction SilentlyContinue
    if ($gitleaks -and -not $NoGitleaks) {
        Write-Host 'Running: gitleaks detect --source <path> --no-banner --redact' -ForegroundColor Cyan
        $output = & gitleaks detect --source $RepoPath --no-banner --redact 2>&1
        if ($LASTEXITCODE -eq 1) {
            $secretFindings++
            Add-Finding 'HIGH' 'gitleaks reported leaked secrets (output is redacted).'
            $output | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor Red }
        }
        elseif ($LASTEXITCODE -eq 0) {
            Add-Finding 'INFO' 'gitleaks: no known secrets detected.'
        }
        else {
            Add-Finding 'WARN' ('gitleaks exited with code ' + $LASTEXITCODE + ' (unsupported flag or error).')
            $output | Select-Object -First 20 | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor Yellow }
        }
    }
    elseif (-not $NoGitleaks) {
        Write-Host 'gitleaks not installed - running built-in regex fallback scan...' -ForegroundColor Yellow
        $secretFindings = Invoke-RegexSecretScan -Root $RepoPath -Files $allFiles
    }
    else {
        Add-Finding 'INFO' 'secret scanning skipped (-NoGitleaks).'
    }

    # 8. Dependencies via osv-scanner.
    Write-Step 'DEPENDENCY SCAN (osv-scanner)'
    $depsVulnCount = 0
    $osv = Get-Command osv-scanner -ErrorAction SilentlyContinue
    $lockfiles = New-Object System.Collections.Generic.List[string]
    foreach ($lf in @('package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'poetry.lock', 'Cargo.lock')) {
        $lfPath = Join-Path $RepoPath $lf
        if (Test-Path -LiteralPath $lfPath) { $lockfiles.Add($lfPath) }
    }
    foreach ($rf in @($allFiles | Where-Object { $_.Name -match '^requirements.*\.txt$' })) {
        $content = Get-Content -LiteralPath $rf.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -and $content -match '--hash=') { $lockfiles.Add($rf.FullName) }
    }
    if ($osv -and -not $NoOsv) {
        if ($lockfiles.Count -eq 0) {
            Add-Finding 'INFO' 'no supported lockfiles found - dependency scan skipped.'
        }
        foreach ($lf in $lockfiles) {
            Write-Host ('Scanning: ' + $lf) -ForegroundColor Cyan
            $out = & osv-scanner scan -r $lf 2>&1
            $text = ($out | Out-String)
            if ($text -match '(?i)no vulnerabilities|no issues found|no known vulnerabilities') {
                Add-Finding 'INFO' ('osv-scanner: no vulnerabilities in ' + (Split-Path $lf -Leaf) + '.')
            }
            elseif ($text -match '(?i)vulnerabilit') {
                $depsVulnCount++
                Add-Finding 'WARN' ('osv-scanner: vulnerabilities found in ' + (Split-Path $lf -Leaf) + '.')
                $out | Select-Object -Last 40 | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor Yellow }
            }
            else {
                Add-Finding 'INFO' ('osv-scanner scan finished for ' + (Split-Path $lf -Leaf) + '.')
            }
        }
    }
    elseif (-not $NoOsv) {
        Add-Finding 'RECOMMENDED' 'osv-scanner not installed - install it to scan lockfiles: winget install Google.OSV-Scanner --scope user'
    }

    # 9. SAST via semgrep.
    Write-Step 'SAST (semgrep)'
    $semgrep = Get-Command semgrep -ErrorAction SilentlyContinue
    if ($semgrep -and -not $NoSemgrep) {
        Write-Host 'Running: semgrep scan --config=auto --quiet (may need network to fetch rules)' -ForegroundColor Cyan
        $out = & semgrep scan --config=auto --quiet 2>&1
        if ($LASTEXITCODE -eq 1) {
            Add-Finding 'WARN' 'semgrep reported findings - review them.'
            $out | Select-Object -Last 30 | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor Yellow }
        }
        elseif ($LASTEXITCODE -eq 0) {
            Add-Finding 'INFO' 'semgrep: no findings.'
        }
        else {
            Add-Finding 'WARN' ('semgrep exited with code ' + $LASTEXITCODE + ' - registry rules may need login; use --config p/default or authenticate with "semgrep login".')
            $out | Select-Object -First 20 | ForEach-Object { Write-Host ('  ' + $_) -ForegroundColor Yellow }
        }
    }
    elseif (-not $NoSemgrep) {
        Add-Finding 'RECOMMENDED' 'semgrep not installed - install it for SAST: pipx install semgrep'
    }

    # 10. Summary and verdict.
    Write-Step 'VERDICT'
    $highCount = @($script:findings | Where-Object { $_.Level -eq 'HIGH' }).Count
    $warnCount  = @($script:findings | Where-Object { $_.Level -in @('WARN', 'LOW') }).Count

    $gitleaksMissing = -not (Get-Command gitleaks -ErrorAction SilentlyContinue)
    $osvMissing      = -not (Get-Command osv-scanner -ErrorAction SilentlyContinue)
    $scanningIncomplete = ($gitleaksMissing -and -not $NoGitleaks) -or ($osvMissing -and -not $NoOsv)

    $pyProjectFound = Test-Path -LiteralPath (Join-Path $RepoPath 'pyproject.toml')
    $buildRsFound   = Test-Path -LiteralPath (Join-Path $RepoPath 'build.rs')
    $dockerFound = (Test-Path -LiteralPath (Join-Path $RepoPath 'Dockerfile')) -or
                   (Test-Path -LiteralPath (Join-Path $RepoPath 'docker-compose.yml')) -or
                   (Test-Path -LiteralPath (Join-Path $RepoPath 'docker-compose.yaml'))

    Write-Host 'Summary counts:' -ForegroundColor Magenta
    Write-Host ('  active hooks           : ' + $hookCount) -ForegroundColor White
    Write-Host ('  submodules             : ' + $submoduleCount) -ForegroundColor White
    Write-Host ('  package scripts        : ' + $pkgScriptCount) -ForegroundColor White
    Write-Host ('  suspicious files       : ' + ($execCount + $credBaitCount + $minifiedCount)) -ForegroundColor White
    Write-Host ('  secrets                : ' + $secretFindings) -ForegroundColor White
    Write-Host ('  dependency vulns       : ' + $depsVulnCount) -ForegroundColor White

    Write-Host ''
    Write-Host '========================================================' -ForegroundColor Magenta
    Write-Host '                          VERDICT' -ForegroundColor Magenta
    Write-Host '========================================================' -ForegroundColor Magenta

    $failReasons = New-Object System.Collections.Generic.List[string]
    if ($hookCount -gt 0) { $failReasons.Add('active git hooks (' + $hookCount + ')') }
    if ($submoduleCount -gt 0) { $failReasons.Add('submodules declared but unreviewed') }
    if ($pkgScriptCount -gt 0) { $failReasons.Add('package.json install/build scripts (' + $pkgScriptCount + ')') }
    if ($pyProjectFound) { $failReasons.Add('pyproject.toml (PEP 517 build backend)') }
    if ($buildRsFound) { $failReasons.Add('build.rs') }
    if ($credBaitCount -gt 0) { $failReasons.Add('credential bait files (' + $credBaitCount + ')') }
    if ($secretFindings -gt 0) { $failReasons.Add('secrets detected (' + $secretFindings + ')') }

    if ($failReasons.Count -gt 0) {
        Write-Host ('FAIL (exit 2): ' + ($failReasons -join '; ')) -ForegroundColor Red
        Write-Host '  Do NOT run install scripts or builds from this repo until these are reviewed.' -ForegroundColor Red
        exit 2
    }

    $warnReasons = New-Object System.Collections.Generic.List[string]
    if ($vsCodeKeys.Count -gt 0) { $warnReasons.Add('VS Code task execution vectors') }
    if ($binaryCount -gt 0) { $warnReasons.Add('binary files (' + $binaryCount + ')') }
    if ($minifiedCount -gt 0) { $warnReasons.Add('minified/obfuscated files (' + $minifiedCount + ')') }
    if ($dockerFound) { $warnReasons.Add('Dockerfile (RUN executes at build)') }
    if ($scanningIncomplete) { $warnReasons.Add('scanning tools not fully installed') }

    if ($warnReasons.Count -gt 0) {
        Write-Host ('WARN (exit 1): ' + ($warnReasons -join '; ')) -ForegroundColor Yellow
        Write-Host '  No immediate FAIL conditions, but review the flagged items before trusting this repo.' -ForegroundColor Yellow
        exit 1
    }

    Write-Host 'PASS (exit 0): nothing relevant found - the repo looks low-risk.' -ForegroundColor Green
    exit 0
}

# ---------------------------------------------------------------------------
# Main dispatch
# ---------------------------------------------------------------------------

$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if (-not $gitCmd) {
    Write-Host 'ERROR: git was not found on PATH. git is required for ls-remote and repo checks.' -ForegroundColor Red
    Write-Host '  Action: install Git for Windows from https://git-scm.com/download/win' -ForegroundColor Yellow
    exit 1
}

if ($Url -and $Path) {
    Write-Host 'ERROR: use either -Url OR -Path, not both.' -ForegroundColor Red
    exit 1
}

if ($Url) {
    Invoke-UrlCheck -InputUrl $Url
}
else {
    if (-not $Path) { $Path = (Get-Location).Path }
    Invoke-PathCheck -RepoPath $Path
}
