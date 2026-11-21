# Phase 9 - Remove every G16 certificate from the Windows trust stores.
# After this, https://localhost:8443 shows NET::ERR_CERT_AUTHORITY_INVALID again:
# the trust came from the trust store, not from the server (midterm 7.3: remove the root after the demo).
#
# Run from Git Bash:   scripts/trust.sh remove
# or PowerShell:       powershell -ExecutionPolicy Bypass -File scripts\remove_root.ps1
#
# It removes by subject (O=TDTU N05 Group 16), so roots from older runs are removed too.
# Windows asks for confirmation for each root in CurrentUser\Root.
# LocalMachine stores need an admin PowerShell; they are only touched if something is there.

. "$PSScriptRoot\trust_common.ps1"

Write-Title 'Phase 9: remove the G16 Root CA from Windows'

$found = @(Get-G16WindowsCerts)
if ($found.Count -eq 0) {
    Write-Ok 'No G16 certificate in the Windows stores (nothing to remove).'
}
$failed = 0
foreach ($c in $found) {
    if ($c.Store -like 'LocalMachine*' -and -not (Test-Admin)) {
        Write-Fail "$($c.Store): $($c.Subject) - needs an admin PowerShell to remove."
        $failed++
        continue
    }
    Write-Cmd "Remove-Item Cert:\$($c.Store)\$($c.Thumbprint)"
    try {
        Remove-Item $c.Path
        if (Test-Path $c.Path) { throw 'still there (did you click No?)' }
        Write-Ok "removed from $($c.Store): $($c.Subject -replace ', O=.*$', '')"
    }
    catch {
        Write-Fail "$($c.Store): $($_.Exception.Message)"
        $failed++
    }
}

Write-Title 'Firefox (manual, only if you imported the root there)'
Write-Host "  Settings > Privacy & Security > Certificates > View Certificates"
Write-Host "    Authorities tab: 'TDTU N05 Group 16' > G16 Root CA > Delete or Distrust"
Write-Host "    Servers tab:     delete exceptions for localhost:8443-8449 (or run scripts/trust.sh reset)"
Write-Host "  Restart Edge and Firefox so they forget cached TLS sessions."

Show-TrustStatus
if ($failed) { exit 1 }
