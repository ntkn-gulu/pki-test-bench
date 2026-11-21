# Phase 7 - Install the G16 Root CA into the Windows trust store (CurrentUser\Root).
#
# Run from Git Bash:   scripts/trust.sh install
# or PowerShell:       powershell -ExecutionPolicy Bypass -File scripts\install_root.ps1
#
# Windows shows a "Security Warning" with the SHA-1 thumbprint before it adds a root.
# Compare it with the thumbprint printed below before clicking Yes (midterm 7.3).
# CurrentUser\Root needs no admin rights and is enough for Edge (and Firefox through
# its "third-party roots" import). Firefox's own store is a manual step, printed at the end.

. "$PSScriptRoot\trust_common.ps1"

$root = Get-RootFile

Write-Title 'Phase 7: install the G16 Root CA (Windows, current user)'
Write-Info "file         pki\root\rootCA.crt"
Write-Info "subject      $($root.Subject)"
Write-Info "valid        $($root.NotBefore.ToString('yyyy-MM-dd')) -> $($root.NotAfter.ToString('yyyy-MM-dd'))"
Write-Info "SHA-256      $(Get-Sha256 $root)"
Write-Host ""
Write-Host "  SHA-1 thumbprint   " -NoNewline
Write-Host (Format-Thumbprint $root.Thumbprint) -ForegroundColor Green
Write-Host "  -> Windows will now ask for confirmation. Check that the thumbprint matches, then click Yes."

$already = Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Thumbprint -eq $root.Thumbprint }
if ($already) {
    Write-Ok 'Already installed in CurrentUser\Root (nothing to do).'
}
else {
    Write-Cmd "Import-Certificate -FilePath pki\root\rootCA.crt -CertStoreLocation Cert:\CurrentUser\Root"
    try {
        Import-Certificate -FilePath $ROOT_CERT -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
    }
    catch {
        Write-Fail "Not installed: $($_.Exception.Message)"
        Write-Info 'If you clicked "No" in the Windows dialog, run the script again.'
        exit 1
    }
    $check = Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Thumbprint -eq $root.Thumbprint }
    if (-not $check) { Write-Fail 'The certificate is not in CurrentUser\Root.'; exit 1 }
    Write-Ok "G16 Root CA is now a trust anchor for this Windows user."
}

$old = @(Get-G16WindowsCerts | Where-Object { $_.Store -like '*Root' -and $_.Thumbprint -ne $root.Thumbprint })
if ($old.Count) {
    Write-Host ""
    Write-Host "  Note: $($old.Count) OLD G16 root(s) from an earlier run are still installed. Clean up with: scripts/trust.sh remove" -ForegroundColor Yellow
}

Write-Title 'Next'
Write-Host "  Edge     reload https://localhost:8443  (close Edge completely first if it still shows the warning)"
Write-Host "           Lock icon -> 'Connection is secure' -> certificate icon: G16 Root CA > G16 Intermediate CA > localhost"
Write-Host "  Firefox  Settings > Privacy & Security > Certificates:"
Write-Host "             'Allow Firefox to automatically trust third-party root certificates you install'"
Write-Host "             ON  -> Firefox already trusts G16 (it imports roots added to Windows)."
Write-Host "             OFF -> Firefox uses only its own store: View Certificates > Authorities > Import..."
Write-Host "                    > pki\root\rootCA.crt > tick 'Trust this CA to identify websites'."
Write-Host "  Check    scripts/trust.sh status"
