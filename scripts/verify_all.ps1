param(
  [int]$BasePort = 4530,
  [string]$OperatorToken = "secgate-test-token",
  [string]$DatabaseUrl = "",
  [switch]$Postgres
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
Set-Location $RepoRoot

$gates = @(
  "validate.py",
  "validate_security.py",
  "validate_response.py",
  "validate_quality.py",
  "validate_product.py"
)

$envKeys = @(
  "HOST",
  "PORT",
  "OPERATOR_TOKEN",
  "DEMO_MODE",
  "DATABASE_URL",
  "DEYSAFE_REQUIRE_POSTGRES",
  "DEYSAFE_INGEST_MINUTES",
  "DEYSAFE_BROADCAST_SIM",
  "DEYSAFE_ROAD_ROUTING",
  "DEYSAFE_ROAD_ROUTING_URL"
)
$oldEnv = @{}
foreach ($key in $envKeys) {
  $oldEnv[$key] = [Environment]::GetEnvironmentVariable($key, "Process")
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logDir = Join-Path $RepoRoot ".verify-logs"
$backupData = Join-Path $RepoRoot ".verify-data-backup-$stamp"
$dataDir = Join-Path $RepoRoot "data"
$server = $null

function Restore-Environment {
  foreach ($key in $envKeys) {
    if ($null -eq $oldEnv[$key]) {
      [Environment]::SetEnvironmentVariable($key, $null, "Process")
    } else {
      [Environment]::SetEnvironmentVariable($key, $oldEnv[$key], "Process")
    }
  }
}

function Stop-Server {
  if ($script:server -and -not $script:server.HasExited) {
    Stop-Process -Id $script:server.Id -Force
    $script:server.WaitForExit()
  }
  $script:server = $null
}

function Wait-Health($url) {
  for ($i = 0; $i -lt 80; $i++) {
    try {
      $r = Invoke-WebRequest -UseBasicParsing -Uri "$url/api/health" -TimeoutSec 2
      if ($r.StatusCode -eq 200) {
        return
      }
    } catch {
      Start-Sleep -Milliseconds 300
    }
  }
  throw "Server did not become ready at $url"
}

if ($Postgres -and -not $DatabaseUrl) {
  $DatabaseUrl = $oldEnv["DATABASE_URL"]
}
if ($Postgres -and -not $DatabaseUrl) {
  throw "Postgres verification needs -DatabaseUrl or an existing DATABASE_URL env var. Use a disposable DB; gates write test data."
}

New-Item -ItemType Directory -Force -Path $logDir | Out-Null

if (Test-Path -LiteralPath $backupData) {
  throw "Backup path already exists: $backupData"
}
if (Test-Path -LiteralPath $dataDir) {
  Move-Item -LiteralPath $dataDir -Destination $backupData
}

$results = @()

try {
  for ($idx = 0; $idx -lt $gates.Count; $idx++) {
    $gate = $gates[$idx]
    $port = $BasePort + $idx
    $baseUrl = "http://127.0.0.1:$port"
    $safeGate = $gate -replace "[^A-Za-z0-9_.-]", "_"

    if (Test-Path -LiteralPath $dataDir) {
      Remove-Item -LiteralPath $dataDir -Recurse -Force
    }

    $env:HOST = "127.0.0.1"
    $env:PORT = [string]$port
    $env:OPERATOR_TOKEN = $OperatorToken
    $env:DEMO_MODE = "1"
    if ($Postgres) {
      $env:DATABASE_URL = $DatabaseUrl
      $env:DEYSAFE_REQUIRE_POSTGRES = "1"
    } else {
      $env:DATABASE_URL = ""
      $env:DEYSAFE_REQUIRE_POSTGRES = ""
    }
    $env:DEYSAFE_INGEST_MINUTES = "0"
    $env:DEYSAFE_BROADCAST_SIM = "1"
    $env:DEYSAFE_ROAD_ROUTING = "0"
    $env:DEYSAFE_ROAD_ROUTING_URL = ""

    $serverOut = Join-Path $logDir "$safeGate.server.out.log"
    $serverErr = Join-Path $logDir "$safeGate.server.err.log"
    $gateLog = Join-Path $logDir "$safeGate.gate.log"

    $script:server = Start-Process -FilePath python -ArgumentList "engine/api.py" `
      -WorkingDirectory $RepoRoot -WindowStyle Hidden -PassThru `
      -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr

    try {
      Wait-Health $baseUrl
      if ($Postgres) {
        $h = Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/api/health" -TimeoutSec 5
        $hj = $h.Content | ConvertFrom-Json
        if ($hj.database.backend -ne "postgres") {
          throw "Expected Postgres backend, got '$($hj.database.backend)'"
        }
      }
      Write-Output ""
      Write-Output "===== RUN $gate on $baseUrl ====="
      $output = & python $gate $baseUrl 2>&1
      $code = $LASTEXITCODE
      $output | Tee-Object -FilePath $gateLog
      $results += [pscustomobject]@{ Gate = $gate; ExitCode = $code }
    } finally {
      Stop-Server
    }
  }
} finally {
  Stop-Server
  if (Test-Path -LiteralPath $dataDir) {
    Remove-Item -LiteralPath $dataDir -Recurse -Force
  }
  if (Test-Path -LiteralPath $backupData) {
    Move-Item -LiteralPath $backupData -Destination $dataDir
  }
  Restore-Environment
}

Write-Output ""
Write-Output "===== GATE EXIT CODES ====="
foreach ($r in $results) {
  Write-Output ("{0}={1}" -f $r.Gate, $r.ExitCode)
}

$failed = @($results | Where-Object { $_.ExitCode -ne 0 })
if ($failed.Count -gt 0) {
  exit 1
}
exit 0
