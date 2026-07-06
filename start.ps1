#!/usr/bin/env pwsh
<#
.SYNOPSIS
    One-command startup for VulnGuard AI.
    Installs dependencies, initialises the database, and starts the server.

.PARAMETER Port
    HTTP port for the dashboard (default: 8080).

.PARAMETER NoBrowser
    Skip auto-opening the browser.

.PARAMETER Reset
    Drop and recreate all database tables. WARNING: destroys all stored data.

.EXAMPLE
    .\start.ps1                   # normal start
    .\start.ps1 -Reset            # wipe DB and reseed from sample data
    .\start.ps1 -Port 9090        # use a different port
    .\start.ps1 -NoBrowser        # headless / CI mode
#>
param(
    [int]$Port      = 8080,
    [switch]$NoBrowser,
    [switch]$Reset
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Helper functions ──────────────────────────────────────────────────────
function Write-Step   { param($n,$msg) Write-Host ""; Write-Host "  [$n] $msg" -ForegroundColor Cyan }
function Write-OK     { param($msg)    Write-Host "      OK  $msg" -ForegroundColor Green }
function Write-Warn   { param($msg)    Write-Host "      !!  $msg" -ForegroundColor Yellow }
function Write-Err    { param($msg)    Write-Host "      ERR $msg" -ForegroundColor Red }

# ── Banner ────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ============================================" -ForegroundColor Magenta
Write-Host "    VulnGuard AI  v2.0  --  Startup Script  " -ForegroundColor Magenta
Write-Host "  ============================================" -ForegroundColor Magenta

# ── Step 1: Python ────────────────────────────────────────────────────────
Write-Step 1 "Checking Python 3.11+..."

$python = $null
foreach ($c in @('python', 'python3', 'python3.12', 'python3.11')) {
    try {
        $ver = & $c --version 2>&1
        if ($ver -match 'Python 3\.(\d+)' -and [int]$Matches[1] -ge 11) {
            $python = $c; break
        }
    } catch {}
}
if (-not $python) {
    Write-Err 'Python 3.11+ not found in PATH.'
    Write-Host '  Install from: https://www.python.org/downloads/' -ForegroundColor DarkGray
    exit 1
}
Write-OK "$(& $python --version)"

# ── Step 2: Virtual environment ───────────────────────────────────────────
Write-Step 2 "Virtual environment..."

$root    = $PSScriptRoot
$venvDir = Join-Path $root '.venv'
$pip     = Join-Path $venvDir 'Scripts\pip.exe'
$py      = Join-Path $venvDir 'Scripts\python.exe'
$uvicorn = Join-Path $venvDir 'Scripts\uvicorn.exe'

if (-not (Test-Path $venvDir)) {
    Write-Host '      Creating .venv ...' -ForegroundColor DarkGray
    & $python -m venv $venvDir
    Write-OK '.venv created.'
} else {
    Write-OK '.venv already exists.'
}

# ── Step 3: Dependencies ──────────────────────────────────────────────────
Write-Step 3 "Installing / verifying dependencies..."

$reqFile = Join-Path $root 'requirements.txt'
& $pip install --quiet -r $reqFile
if ($LASTEXITCODE -ne 0) {
    Write-Err 'pip install failed. Check requirements.txt and network access.'
    exit 1
}
Write-OK 'Dependencies ready.'

# ── Step 4: Load .env ─────────────────────────────────────────────────────
Write-Step 4 "Loading .env..."

$envFile = Join-Path $root '.env'
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -eq '' -or $line.StartsWith('#')) { return }
        $idx = $line.IndexOf('=')
        if ($idx -lt 1) { return }
        $name  = $line.Substring(0, $idx).Trim()
        $value = $line.Substring($idx + 1).Trim()
        $ci    = $value.IndexOf(' #')
        if ($ci -gt 0) { $value = $value.Substring(0, $ci).Trim() }
        [System.Environment]::SetEnvironmentVariable($name, $value, 'Process')
    }
    Write-OK '.env loaded.'
} else {
    Write-Warn '.env not found -- using defaults (postgres:postgres@localhost:5432/vulndb).'
}

# Show resolved config
$dbUrl = if ($env:DATABASE_URL) { $env:DATABASE_URL } else { 'postgresql://postgres:postgres@localhost:5432/vulndb' }
$llm   = if ($env:LLM_PROVIDER)  { $env:LLM_PROVIDER }  else { 'anthropic' }
$dry   = if ($env:DRY_RUN -eq '1') { 'YES (no real patching)' } else { 'no' }
Write-Host "      Database : $dbUrl"  -ForegroundColor DarkGray
Write-Host "      LLM      : $llm"   -ForegroundColor DarkGray
Write-Host "      DRY_RUN  : $dry"   -ForegroundColor DarkGray

# ── Step 5: PostgreSQL service (Windows) ──────────────────────────────────
Write-Step 5 "Checking PostgreSQL service..."

$pgStarted = $false
foreach ($pat in @('postgresql*', 'PostgreSQL*')) {
    $svc = Get-Service -Name $pat -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($svc) {
        if ($svc.Status -ne 'Running') {
            Write-Host "      Starting service '$($svc.Name)'..." -ForegroundColor DarkGray
            try {
                Start-Service $svc.Name -ErrorAction Stop
                Write-OK "PostgreSQL service '$($svc.Name)' started."
                $pgStarted = $true
            } catch {
                Write-Warn "Could not start '$($svc.Name)' automatically (may need admin)."
                Write-Warn 'Run as Administrator or start PostgreSQL manually, then retry.'
            }
        } else {
            Write-OK "Service '$($svc.Name)' is running."
            $pgStarted = $true
        }
        break
    }
}
if (-not $pgStarted) {
    Write-Warn 'No PostgreSQL Windows service found. Assuming it is running (Docker / WSL / manual).'
}

# ── Step 6: Init / migrate database ──────────────────────────────────────
Write-Step 6 "Initialising database (tables + sample data)..."

if ($Reset) {
    Write-Warn 'RESET flag set -- all existing data will be wiped.'
}

Push-Location $root
try {
    if ($Reset) {
        & $py 'init_db.py' '--reset'
    } else {
        & $py 'init_db.py'
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host ''
        Write-Err 'Database init failed. Common fixes:'
        Write-Host '    1. Make sure PostgreSQL is running.' -ForegroundColor DarkGray
        Write-Host "    2. Check DATABASE_URL in .env matches your credentials." -ForegroundColor DarkGray
        Write-Host '    3. Create DB manually: psql -U postgres -c "CREATE DATABASE vulndb;"' -ForegroundColor DarkGray
        exit 1
    }
} finally {
    Pop-Location
}
Write-OK 'Database ready.'

# ── Step 7: Port availability ─────────────────────────────────────────────
Write-Step 7 "Checking port $Port..."

$inUse = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($inUse) {
    $procId = $inUse.OwningProcess
    $proc   = Get-Process -Id $procId -ErrorAction SilentlyContinue
    $procName = if ($proc) { $proc.ProcessName } else { "PID $procId" }
    Write-Warn "Port $Port is in use by '$procName'."
    $choice = Read-Host '      Kill it and continue? [y/N]'
    if ($choice -match '^[yY]$') {
        Stop-Process -Id $procId -Force
        Write-OK "Killed $procName."
        Start-Sleep -Milliseconds 800
    } else {
        Write-Host "  Tip: use a different port:  .\start.ps1 -Port 9090" -ForegroundColor DarkGray
        exit 1
    }
}
Write-OK "Port $Port is free."

# ── Step 8: Open browser after server warms up ───────────────────────────
if (-not $NoBrowser) {
    $url = "http://localhost:$Port"
    Start-Job -ScriptBlock {
        param($u)
        Start-Sleep 3
        Start-Process $u
    } -ArgumentList $url | Out-Null
}

# ── Step 9: Start server (foreground -- Ctrl+C to stop) ──────────────────
Write-Host ''
Write-Host '  +--------------------------------------------------+' -ForegroundColor Green
Write-Host "  |  Dashboard  http://localhost:$Port                |" -ForegroundColor Green
Write-Host "  |  API docs   http://localhost:$Port/docs           |" -ForegroundColor Green
Write-Host '  |  Press Ctrl+C to stop.                           |' -ForegroundColor Green
Write-Host '  +--------------------------------------------------+' -ForegroundColor Green
Write-Host ''

Push-Location $root
try {
    & $uvicorn 'app.main:app' --port $Port --reload
} finally {
    Pop-Location
}
