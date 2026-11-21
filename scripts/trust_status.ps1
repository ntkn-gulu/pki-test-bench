# Show where the G16 Root CA is trusted right now: Windows stores (Edge) and every Firefox profile.
# Read-only. Run from Git Bash: scripts/trust.sh status

. "$PSScriptRoot\trust_common.ps1"
Show-TrustStatus
