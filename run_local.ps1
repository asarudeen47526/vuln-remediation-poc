#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Local launcher for vuln-remediation-poc on Windows.

.DESCRIPTION
    Creates/activates the Python venv, installs dependencies, loads .env, then
    runs the requested mode.

.PARAMETER Mode
    selftest      - Verify config, LLM key, and safety gate. No target needed. (default)
    analyze       - Analyze sample_report.json locally. No target needed.
    pull          - Pull existing report from target, then analyze.
    pull <path>   - Pull a specific remote path from target, then analyze.
    scan          - SSH to target, run Trivy, pull report, then analyze.

.EXAMPLE
    .\run_local.ps1                        # selftest (safe first run)
    .\run_local.ps1 analyze                # LLM analysis of local sample data
    .\run_local.ps1 pull                   # pull /tmp/analyze.json from target
    .\run_local.ps1 pull ~/incoming/scan.json
    .\run_local.ps1 scan                   # trigger fresh Trivy scan on target
#>
param(
    [string]$Mode = "selftest",
    [string]$RemotePath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --------------------------------------------------------------------------
# 1. Check Python 3.11+
# --------------------------------------------------------------------------
$python = $null
foreach ($candidate in @("python", "python3", "python3.11")) {
    try {
        $ver = & $candidate --version 2>&1
        if ($ver -match "Python 3\.(\d+)" -and [int]$Matches[1] -ge 11) {
            $python = $candidate
            break
        }
    } catch {}
}
if (-not $python) {
    Write-Error "Python 3.11+ is required but was not found in PATH. Install from https://www.python.org/downloads/"
    exit 1
}
Write-Host "[ok] Using: $(& $python --version)" -ForegroundColor Green

# --------------------------------------------------------------------------
# 2. Create venv if it doesn't exist
# --------------------------------------------------------------------------
$venvDir = Join-Path $PSScriptRoot ".venv"
if (-not (Test-Path $venvDir)) {
    Write-Host "[..] Creating virtual environment at .venv ..." -ForegroundColor Cyan
    & $python -m venv $venvDir
    Write-Host "[ok] Virtual environment created." -ForegroundColor Green
} else {
    Write-Host "[ok] Virtual environment already exists." -ForegroundColor Green
}

# --------------------------------------------------------------------------
# 3. Activate venv and install/upgrade dependencies
# --------------------------------------------------------------------------
$pip = Join-Path $venvDir "Scripts\pip.exe"
$pythonVenv = Join-Path $venvDir "Scripts\python.exe"

Write-Host "[..] Installing / verifying dependencies ..." -ForegroundColor Cyan
& $pip install --quiet -r (Join-Path $PSScriptRoot "requirements.txt")
Write-Host "[ok] Dependencies ready." -ForegroundColor Green

# --------------------------------------------------------------------------
# 4. Load .env into the current process environment
# --------------------------------------------------------------------------
$envFile = Join-Path $PSScriptRoot ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        # skip blank lines and comments
        if ($line -eq "" -or $line.StartsWith("#")) { return }
        # split on the FIRST '=' only so API keys with '=' are preserved
        $idx = $line.IndexOf('=')
        if ($idx -lt 1) { return }
        $name  = $line.Substring(0, $idx).Trim()
        $value = $line.Substring($idx + 1).Trim()
        # strip inline comment (e.g. "15   # R-Act poll seconds")
        $commentIdx = $value.IndexOf(' #')
        if ($commentIdx -gt 0) { $value = $value.Substring(0, $commentIdx).Trim() }
        [System.Environment]::SetEnvironmentVariable($name, $value, "Process")
    }
    Write-Host "[ok] .env loaded." -ForegroundColor Green
} else {
    Write-Warning ".env not found - LLM_PROVIDER and API key must already be set in your environment."
}

# --------------------------------------------------------------------------
# 5. Run the requested mode
# --------------------------------------------------------------------------
Write-Host ""
switch ($Mode.ToLower()) {

    "selftest" {
        Write-Host "Mode: selftest (config + LLM + safety gate, no target)" -ForegroundColor Yellow
        & $pythonVenv (Join-Path $PSScriptRoot "selftest.py")
    }

    "analyze" {
        Write-Host "Mode: analyze (local sample_report.json, no target)" -ForegroundColor Yellow
        & $pythonVenv (Join-Path $PSScriptRoot "analyze.py") `
            (Join-Path $PSScriptRoot "sample_report.json")
    }

    "pull" {
        Write-Host "Mode: pull (pull existing report from target, then analyze)" -ForegroundColor Yellow
        if ($RemotePath -ne "") {
            & $pythonVenv (Join-Path $PSScriptRoot "analyze.py") "--pull" $RemotePath
        } else {
            & $pythonVenv (Join-Path $PSScriptRoot "analyze.py") "--pull"
        }
    }

    "scan" {
        Write-Host "Mode: scan (SSH to target, run Trivy, pull report, analyze)" -ForegroundColor Yellow
        Write-Host "      TARGET_HOST = $env:TARGET_HOST  |  SSH_USER = $env:SSH_USER" -ForegroundColor DarkGray
        Write-Host "      SSH_KEY     = $env:SSH_KEY" -ForegroundColor DarkGray
        if ($env:JUMP_HOST) {
            Write-Host "      JUMP_HOST   = $env:JUMP_HOST" -ForegroundColor DarkGray
        }
        Write-Host ""
        & $pythonVenv (Join-Path $PSScriptRoot "analyze.py")
    }

    default {
        Write-Error "Unknown mode: '$Mode'. Valid modes: selftest | analyze | pull | scan"
        exit 1
    }
}
