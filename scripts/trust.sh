#!/usr/bin/env bash
# Git Bash front end for the PowerShell trust-store scripts.
#   scripts/trust.sh install            Phase 7: add G16 Root CA to Windows (CurrentUser\Root)
#   scripts/trust.sh status             where is G16 trusted right now (Windows + Firefox)
#   scripts/trust.sh remove             Phase 9: remove every G16 certificate from Windows
#   scripts/trust.sh reset [options]    clean state for a rehearsal (-DryRun -KeepPki -Force)
set -euo pipefail
dir="$(cd "$(dirname "$0")" && (pwd -W 2>/dev/null || pwd))"

case "${1:-}" in
    install) script=install_root.ps1 ;;
    status)  script=trust_status.ps1 ;;
    remove)  script=remove_root.ps1 ;;
    reset)   script=reset_demo.ps1 ;;
    *) echo "usage: scripts/trust.sh install|status|remove|reset [-DryRun] [-KeepPki] [-Force]"; exit 2 ;;
esac
shift
# Bypass only for this one process: the machine policy is not changed.
exec powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$dir/$script" "$@"
