#Requires -RunAsAdministrator
<#
.SYNOPSIS
    EDR Graph Agent — Windows Installation Script

.DESCRIPTION
    Installs the EDR Graph Agent as a Windows Service:
    1. Verifies Python 3.11+ and Administrator privileges
    2. Copies agent files to C:\Program Files\edr-graph
    3. Creates Python venv and installs dependencies
    4. Writes initial config to C:\ProgramData\edr-graph\config.yaml
    5. Installs and starts the Windows service

.EXAMPLE
    # Run from the project root:
    powershell -ExecutionPolicy Bypass -File deploy\install.ps1
#>

param(
    [string]$InstallDir = "C:\Program Files\edr-graph",
    [string]$DataDir = "C:\ProgramData\edr-graph",
    [string]$ConfigDir = "C:\ProgramData\edr-graph",
    [int]$MetricsPort = 9100
)

$ErrorActionPreference = "Stop"

# --- Helpers ---
function Write-Info  { Write-Host "[INFO]  $args" -ForegroundColor Green }
function Write-Warn  { Write-Host "[WARN]  $args" -ForegroundColor Yellow }
function Write-Err   { Write-Host "[ERROR] $args" -ForegroundColor Red }

# --- Pre-flight checks ---
Write-Info "EDR Graph Agent Installer"
Write-Info "========================="

# Check Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $currentPrincipal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err "This script must be run as Administrator"
    exit 1
}
Write-Info "Running as Administrator"

# Check Python
$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $version = & $cmd --version 2>&1
        if ($version -match "Python (\d+)\.(\d+)") {
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            if ($major -ge 3 -and $minor -ge 11) {
                $pythonCmd = $cmd
                Write-Info "Found $version"
                break
            }
        }
    } catch {}
}
if (-not $pythonCmd) {
    Write-Err "Python 3.11+ is required but not found"
    Write-Err "Download from https://www.python.org/downloads/"
    exit 1
}

# --- Step 1: Create directories ---
Write-Info "Creating directories"
$QuarantineDir = Join-Path $DataDir "quarantine"
foreach ($dir in @($InstallDir, $DataDir, $QuarantineDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# --- Step 2: Copy agent files ---
Write-Info "Copying agent files to $InstallDir"
$ScriptDir = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

Copy-Item -Path (Join-Path $ScriptDir "agent") -Destination $InstallDir -Recurse -Force
Copy-Item -Path (Join-Path $ScriptDir "pyproject.toml") -Destination $InstallDir -Force
$srcConfig = Join-Path $ScriptDir "config.yaml"
if (Test-Path $srcConfig) {
    Copy-Item -Path $srcConfig -Destination $InstallDir -Force
}

# --- Step 3: Create venv and install dependencies ---
Write-Info "Creating Python virtual environment"
$VenvDir = Join-Path $InstallDir ".venv"
& $pythonCmd -m venv $VenvDir

$pipExe = Join-Path $VenvDir "Scripts\pip.exe"
Write-Info "Installing Python dependencies"
& $pipExe install --quiet --upgrade pip
& $pipExe install --quiet -e $InstallDir

# --- Step 4: Write config ---
$ConfigFile = Join-Path $ConfigDir "config.yaml"
if (-not (Test-Path $ConfigFile)) {
    Write-Info "Writing initial config to $ConfigFile"
    @"
# EDR Graph Agent Configuration

agent:
  log_level: "INFO"
  log_format: "json"
  data_dir: "$($DataDir -replace '\\', '\\')"

collector:
  poll_interval: 5.0

response:
  auto_respond: false
  auto_terminate: false
  quarantine_dir: "$($QuarantineDir -replace '\\', '\\')"

persistence:
  watchdog_enabled: true
  heartbeat_interval_seconds: 10
  tamper_check_interval_seconds: 60

metrics:
  enabled: true
  port: $MetricsPort
"@ | Out-File -FilePath $ConfigFile -Encoding UTF8
} else {
    Write-Warn "Config already exists at $ConfigFile — not overwriting"
}

# --- Step 5: Set permissions ---
Write-Info "Setting directory permissions"
$acl = Get-Acl $DataDir
$acl.SetAccessRuleProtection($true, $false)
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit",
    "None", "Allow"
)
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit",
    "None", "Allow"
)
$acl.AddAccessRule($adminRule)
$acl.AddAccessRule($systemRule)
Set-Acl -Path $DataDir -AclObject $acl

# --- Step 6: Install Windows Service ---
Write-Info "Installing Windows service"
$servicePy = Join-Path $InstallDir "agent\platform\windows_service.py"
$pythonExe = Join-Path $VenvDir "Scripts\python.exe"

try {
    & $pythonExe $servicePy install
    Write-Info "Service installed successfully"
} catch {
    Write-Err "Failed to install service: $_"
    Write-Warn "pywin32 may need to be installed: $pipExe install pywin32"
    exit 1
}

# --- Step 7: Start the service ---
Write-Info "Starting EDRGraphAgent service"
try {
    Start-Service -Name "EDRGraphAgent"
    Start-Sleep -Seconds 2

    $svc = Get-Service -Name "EDRGraphAgent"
    if ($svc.Status -eq "Running") {
        Write-Info "EDRGraphAgent is running"
    } else {
        Write-Err "Service is not running (status: $($svc.Status))"
        Get-EventLog -LogName Application -Source "EDRGraphAgent" -Newest 10 |
            Format-Table TimeGenerated, Message -AutoSize
        exit 1
    }
} catch {
    Write-Err "Failed to start service: $_"
    exit 1
}

Write-Info ""
Write-Info "Installation complete!"
Write-Info "  Install:    $InstallDir"
Write-Info "  Config:     $ConfigFile"
Write-Info "  Data:       $DataDir"
Write-Info "  Quarantine: $QuarantineDir"
Write-Info "  Service:    Get-Service EDRGraphAgent"
Write-Info "  Health:     Invoke-RestMethod http://127.0.0.1:${MetricsPort}/health"
Write-Info "  Metrics:    Invoke-RestMethod http://127.0.0.1:${MetricsPort}/metrics"
