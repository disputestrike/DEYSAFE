param(
  [string]$Target = "C:\Users\benxp\OneDrive\Desktop\DEYSAFE-main"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot ".git"))) {
  throw "This script must be run from inside the DEYSAFE Git repository."
}

$targetFull = [System.IO.Path]::GetFullPath($Target)
if (-not (Test-Path -LiteralPath $targetFull)) {
  New-Item -ItemType Directory -Force -Path $targetFull | Out-Null
}
if (-not (Test-Path -LiteralPath $targetFull -PathType Container)) {
  throw "Mirror target is not a directory: $targetFull"
}

$dirty = git -C $RepoRoot status --porcelain
if ($dirty) {
  throw "Working tree has uncommitted changes. Commit first, then sync so the mirror matches GitHub."
}

$branch = (git -C $RepoRoot rev-parse --abbrev-ref HEAD).Trim()
$commit = (git -C $RepoRoot rev-parse HEAD).Trim()
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("deysafe-archive-{0}.tar" -f $PID)

try {
  git -C $RepoRoot archive --format=tar -o $tmp HEAD
  tar -xf $tmp -C $targetFull
} finally {
  if (Test-Path -LiteralPath $tmp) {
    Remove-Item -LiteralPath $tmp -Force
  }
}

$stamp = (Get-Date).ToUniversalTime().ToString("o")
$marker = @"
DeySafe desktop mirror
Source: $RepoRoot
Branch: $branch
Commit: $commit
SyncedAtUtc: $stamp
Mode: tracked-files overlay from Git HEAD; existing target-only files are preserved.
"@
Set-Content -LiteralPath (Join-Path $targetFull ".deysafe-mirror.txt") -Value $marker -Encoding UTF8

Write-Output "Synced DEYSAFE $branch@$commit to $targetFull"
