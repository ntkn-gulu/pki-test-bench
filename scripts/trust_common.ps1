# trust_common.ps1 - shared helpers for install_root / remove_root / trust_status / reset_demo.
# Dot-source it:  . "$PSScriptRoot\trust_common.ps1"
# ASCII only on purpose: Windows PowerShell 5.1 reads BOM-less scripts as ANSI.

$ErrorActionPreference = 'Stop'

$REPO_DIR      = Split-Path -Parent $PSScriptRoot
$ROOT_CERT     = Join-Path $REPO_DIR 'pki\root\rootCA.crt'
$G16_ORG       = 'O=TDTU N05 Group 16'          # every G16 certificate has this in its subject
$BENCH_PORTS   = 8443..8449
$FIREFOX_PROFS = Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'

# ---------------------------------------------------------------- output ----
function Write-Title([string]$text)  { Write-Host ""; Write-Host "==> $text" -ForegroundColor Cyan }
function Write-Ok([string]$text)     { Write-Host "[OK] " -ForegroundColor Green -NoNewline; Write-Host $text }
function Write-Fail([string]$text)   { Write-Host "[FAIL] " -ForegroundColor Red -NoNewline; Write-Host $text }
function Write-Info([string]$text)   { Write-Host "     $text" -ForegroundColor DarkGray }
function Write-Cmd([string]$text)    { Write-Host "PS> $text" -ForegroundColor Yellow }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------- certificates ----
function Get-RootFile {
    if (-not (Test-Path $ROOT_CERT)) {
        throw "pki\root\rootCA.crt not found. Run scripts/01_root_ca.sh first."
    }
    return New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $ROOT_CERT
}

# "A5D3ECD0F8C5..." -> "A5D3ECD0 F8C5924B ..." (the way the Windows security dialog prints it)
function Format-Thumbprint([string]$hex) {
    return (($hex -split '(.{8})') | Where-Object { $_ }) -join ' '
}

function Get-Sha256([Security.Cryptography.X509Certificates.X509Certificate2]$cert) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $hash = $sha.ComputeHash($cert.RawData)
    return (($hash | ForEach-Object { $_.ToString('X2') }) -join ':')
}

# Every G16 certificate in the Windows stores that matter for TLS.
function Get-G16WindowsCerts {
    $stores = 'Cert:\CurrentUser\Root', 'Cert:\LocalMachine\Root', 'Cert:\CurrentUser\CA', 'Cert:\LocalMachine\CA'
    foreach ($store in $stores) {
        Get-ChildItem $store | Where-Object { $_.Subject -like "*$G16_ORG*" } | ForEach-Object {
            [pscustomobject]@{
                Store      = $store.Replace('Cert:\', '')
                Subject    = $_.Subject
                Thumbprint = $_.Thumbprint
                Path       = "$store\$($_.Thumbprint)"
            }
        }
    }
}

# ---------------------------------------------------------------- Firefox ----
# Firefox has its own NSS trust store (cert9.db in every profile). Since Firefox 120 it ALSO
# imports roots that a user added to the Windows store, unless the pref below is false.
function Get-FirefoxProfiles {
    if (-not (Test-Path $FIREFOX_PROFS)) { return @() }
    return Get-ChildItem $FIREFOX_PROFS -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'cert9.db') }
}

function Get-FirefoxEnterpriseRoots([string]$profile_dir) {
    foreach ($file in 'user.js', 'prefs.js') {
        $path = Join-Path $profile_dir $file
        if (Test-Path $path) {
            $line = Select-String -Path $path -Pattern 'security\.enterprise_roots\.enabled' | Select-Object -Last 1
            if ($line) {
                if ($line.Line -match 'true') { return "ON (set in $file)" } else { return "OFF (set in $file)" }
            }
        }
    }
    return 'ON (Firefox default)'
}

# Read a file even while Firefox has it open.
function Read-SharedBytes([string]$path) {
    $stream = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
    try {
        $buffer = New-Object byte[] $stream.Length
        [void]$stream.Read($buffer, 0, $buffer.Length)
        return ,$buffer
    }
    finally { $stream.Dispose() }
}

# Best effort: look for a slice of the root's public key inside cert9.db (an SQLite file).
# Only the root itself contains its public key, so a match means "imported by hand".
function Test-FirefoxHasRoot([string]$profile_dir, [Security.Cryptography.X509Certificates.X509Certificate2]$root) {
    $key = $root.PublicKey.EncodedKeyValue.RawData
    $needle = [BitConverter]::ToString($key, 64, 32)
    $haystack = [BitConverter]::ToString((Read-SharedBytes (Join-Path $profile_dir 'cert9.db')))
    return $haystack.Contains($needle)
}

# Exceptions the user created with "Accept the Risk and Continue" (kept until deleted).
function Get-FirefoxBenchExceptions([string]$profile_dir) {
    $path = Join-Path $profile_dir 'cert_override.txt'
    if (-not (Test-Path $path)) { return @() }
    $pattern = '^(localhost|127\.0\.0\.1|\[::1\]):(' + ($BENCH_PORTS -join '|') + ')[:\s]'
    return @(Get-Content $path | Where-Object { $_ -match $pattern })
}

function Test-FirefoxRunning { return [bool](Get-Process firefox -ErrorAction SilentlyContinue) }

# ------------------------------------------------------------------ status ----
function Show-TrustStatus {
    $root = $null
    if (Test-Path $ROOT_CERT) { $root = Get-RootFile }

    Write-Title 'Trust status of the G16 Root CA'
    if ($root) {
        Write-Info "pki\root\rootCA.crt  $($root.Subject)"
        Write-Info "SHA-1 thumbprint     $(Format-Thumbprint $root.Thumbprint)"
    } else {
        Write-Info 'pki\root\rootCA.crt  (not generated)'
    }

    Write-Host ""
    Write-Host "  Windows certificate stores (used by Edge, Chrome, curl/Schannel)"
    $win = @(Get-G16WindowsCerts)
    if ($win.Count -eq 0) {
        Write-Host "    no G16 certificate installed" -ForegroundColor DarkGray
    }
    foreach ($c in $win) {
        $tag = ''
        if ($root -and $c.Thumbprint -eq $root.Thumbprint) { $tag = '  <- this pki\root\rootCA.crt' }
        elseif ($c.Store -like '*Root') { $tag = '  <- OLD root from an earlier run' }
        Write-Host ("    {0,-20} {1}  {2}{3}" -f $c.Store, ($c.Subject -replace ', O=.*$', ''), $c.Thumbprint.Substring(0, 8), $tag)
    }
    $edge_trusts = $root -and ($win | Where-Object { $_.Store -like '*Root' -and $_.Thumbprint -eq $root.Thumbprint })

    Write-Host ""
    Write-Host "  Firefox (own NSS store per profile)"
    $profiles = @(Get-FirefoxProfiles)
    if ($profiles.Count -eq 0) { Write-Host "    no Firefox profile found" -ForegroundColor DarkGray }
    foreach ($p in $profiles) {
        $imported = $false
        if ($root) { $imported = Test-FirefoxHasRoot $p.FullName $root }
        $enterprise = Get-FirefoxEnterpriseRoots $p.FullName
        $exceptions = @(Get-FirefoxBenchExceptions $p.FullName)
        $via = @()
        if ($imported) { $via += 'imported in NSS store' }
        if ($edge_trusts -and $enterprise -like 'ON*') { $via += 'Windows root import' }
        $verdict = if ($via.Count) { 'trusts G16 via ' + ($via -join ' + ') } else { 'does NOT trust G16' }
        Write-Host "    $($p.Name)"
        Write-Host "      NSS store: $(if ($imported) { 'G16 Root imported' } else { 'G16 Root not imported' })"
        Write-Host "      'trust third-party roots you install' (security.enterprise_roots.enabled): $enterprise"
        Write-Host "      saved exceptions for Test Bench ports: $($exceptions.Count)"
        Write-Host "      => $verdict" -ForegroundColor $(if ($via.Count) { 'Green' } else { 'Yellow' })
    }

    Write-Host ""
    if ($edge_trusts) { Write-Ok 'Edge trusts the G16 Root CA (it is in the Windows Root store).' }
    else { Write-Host '  Edge does NOT trust the G16 Root CA.' -ForegroundColor Yellow }
}
