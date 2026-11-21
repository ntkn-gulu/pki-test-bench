# Put the laptop back into a CLEAN state before a rehearsal or the live demo.
#
#   1. stop serve.py if it is running on 8443-8449
#   2. remove every G16 certificate from the Windows stores
#   3. delete Firefox exceptions ("Accept the Risk and Continue") for the Test Bench ports
#   4. delete pki/ (all keys and certificates) so scripts 01-05 start from zero
#
# Run from Git Bash:   scripts/trust.sh reset [-DryRun] [-KeepPki] [-Force]
# or PowerShell:       powershell -ExecutionPolicy Bypass -File scripts\reset_demo.ps1 -DryRun
#
#   -DryRun   only show what would be done
#   -KeepPki  keep pki/ (only clean the trust stores and the browsers)
#   -Force    do not ask before stopping the server or deleting pki/

param([switch]$DryRun, [switch]$KeepPki, [switch]$Force)

. "$PSScriptRoot\trust_common.ps1"

function Confirm-Step([string]$question) {
    if ($Force) { return $true }
    return ((Read-Host "  $question [y/N]") -match '^(y|yes)$')
}

if ($DryRun) { Write-Host "`n  DRY RUN - nothing will be changed" -ForegroundColor Yellow }

# ---- 1. server ---------------------------------------------------------------
Write-Title '1/4  Stop serve.py'
$listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
               Where-Object { $BENCH_PORTS -contains $_.LocalPort } |
               Select-Object -ExpandProperty OwningProcess -Unique)
if ($listeners.Count -eq 0) { Write-Ok 'No program listens on 8443-8449.' }
foreach ($process_id in $listeners) {
    $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$process_id"
    if ($proc.CommandLine -notmatch 'serve\.py') {
        Write-Fail "Port in use by another program (PID $process_id): $($proc.CommandLine)"
        continue
    }
    Write-Info "PID $process_id  $($proc.CommandLine)"
    if ($DryRun) { Write-Info 'would stop it'; continue }
    if (Confirm-Step "Stop this serve.py?") {
        Stop-Process -Id $process_id -Force
        $launcher = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.ParentProcessId)" -ErrorAction SilentlyContinue
        if ($launcher -and $launcher.CommandLine -match 'serve\.py') { Stop-Process -Id $launcher.ProcessId -Force -ErrorAction SilentlyContinue }
        Write-Ok "stopped PID $process_id"
    }
}

# ---- 2. Windows trust stores -----------------------------------------------------
Write-Title '2/4  Remove G16 certificates from Windows'
if ($DryRun) {
    $found = @(Get-G16WindowsCerts)
    if ($found.Count -eq 0) { Write-Ok 'Nothing installed.' }
    foreach ($c in $found) { Write-Info "would remove $($c.Store): $($c.Subject)" }
}
else {
    & "$PSScriptRoot\remove_root.ps1"
}

# ---- 3. Firefox exceptions ---------------------------------------------------------
Write-Title '3/4  Firefox exceptions for the Test Bench ports'
foreach ($p in @(Get-FirefoxProfiles)) {
    $exceptions = @(Get-FirefoxBenchExceptions $p.FullName)
    if ($exceptions.Count -eq 0) { Write-Ok "$($p.Name): none"; continue }
    Write-Info "$($p.Name): $($exceptions.Count) exception(s)"
    if ($DryRun) { Write-Info 'would remove them (backup: cert_override.txt.g16bak)'; continue }
    if (Test-FirefoxRunning) {
        Write-Fail 'Firefox is running and would write the file back. Close Firefox and run reset again.'
        continue
    }
    $file = Join-Path $p.FullName 'cert_override.txt'
    Copy-Item $file "$file.g16bak" -Force
    $keep = Get-Content $file | Where-Object { $exceptions -notcontains $_ }
    Set-Content -Path $file -Value $keep -Encoding UTF8
    Write-Ok "removed $($exceptions.Count) exception(s), backup in cert_override.txt.g16bak"
}

# ---- 4. pki/ -------------------------------------------------------------------------
Write-Title '4/4  Delete pki/ (keys and certificates)'
$pki = Join-Path $REPO_DIR 'pki'
if ($KeepPki) { Write-Info 'kept (-KeepPki)' }
elseif (-not (Test-Path $pki)) { Write-Ok 'pki/ does not exist.' }
elseif ($DryRun) { Write-Info "would delete $pki" }
elseif (Confirm-Step "Delete $pki (all private keys, cannot be undone)?") {
    Remove-Item $pki -Recurse -Force
    Write-Ok 'pki/ deleted.'
}
else { Write-Info 'kept.' }

Write-Title 'Clean state - before you start'
Write-Host "  * Close Edge AND Firefox completely (Edge: also check the tray icon / startup boost)."
Write-Host "  * Firefox: if you imported the root by hand, delete it (Authorities tab), see remove_root output."
Write-Host "  * Then: scripts/01..05  ->  py server/serve.py  ->  https://localhost:8443 (warning expected)."
