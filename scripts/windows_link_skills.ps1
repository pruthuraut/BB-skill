# Windows-only helper: makes .claude/skills point at .agents/skills.
#
# The repo stores .claude/skills as a git symlink (works natively on Linux/macOS).
# On Windows with core.symlinks=false, git checks it out as a plain text file
# containing "../.agents/skills", so Claude Code cannot see the skills.
#
# This script replaces that placeholder with a directory junction (no admin or
# Developer Mode required) and marks it skip-worktree so git never tries to
# commit the Windows-local change. Linux checkouts are unaffected.
#
# Usage (from repo root or anywhere):  powershell -ExecutionPolicy Bypass -File scripts\windows_link_skills.ps1

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$link     = Join-Path $repoRoot '.claude\skills'
$target   = Join-Path $repoRoot '.agents\skills'

if (-not (Test-Path $target -PathType Container)) {
    throw "Target directory not found: $target"
}

if (Test-Path $link) {
    $item = Get-Item $link -Force
    if ($item.LinkType -in @('Junction', 'SymbolicLink')) {
        Write-Host "[=] $link is already a $($item.LinkType) -> $($item.Target)"
        exit 0
    }
    if ($item.PSIsContainer) {
        throw "$link is a real directory, not a placeholder. Refusing to remove it."
    }
    # Placeholder text file written by git when symlinks are disabled.
    Remove-Item $link -Force
}

New-Item -ItemType Junction -Path $link -Target $target | Out-Null
Write-Host "[+] Created junction $link -> $target"

# Keep git from reporting/committing the Windows-local replacement.
git -C $repoRoot update-index --skip-worktree .claude/skills
Write-Host "[+] Marked .claude/skills as skip-worktree (Linux symlink in repo is untouched)."
