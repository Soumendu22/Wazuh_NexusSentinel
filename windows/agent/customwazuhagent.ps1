# Custom Wazuh Agent Setup Script with VirusTotal Integration for Windows
# This script backs up configuration files, runs VirusTotal integration, and restarts services

param(
    [string]$UserName = $env:USERNAME
)

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

# Function to write colored output
function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-ErrorMessage {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Check if Wazuh agent is running
$wazuhService = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if (-not $wazuhService -or $wazuhService.Status -ne "Running") {
    Write-ErrorMessage "Wazuh agent is not running. Please install and start Wazuh agent first."
    exit 1
}

Write-Status "Starting Custom Wazuh Agent Configuration with VirusTotal Integration..."

$WazuhPath = "C:\Program Files (x86)\ossec-agent"

# Create backup directory with timestamp
$BackupDir = "$WazuhPath\backup\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
Write-Status "Creating backup directory: $BackupDir"
New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null

# Step 1: Backup configuration files
Write-Status "Backing up configuration files..."

$OssecConf = "$WazuhPath\ossec.conf"
$ActiveResponsePath = "$WazuhPath\active-response\bin"

# Backup ossec.conf
if (Test-Path $OssecConf) {
    Copy-Item $OssecConf "$BackupDir\ossec.conf.backup"
    Write-Success "Backed up ossec.conf"
} else {
    Write-Warning "ossec.conf not found - this may be a fresh installation"
}

# Backup existing active response scripts if they exist
if (Test-Path $ActiveResponsePath) {
    Copy-Item $ActiveResponsePath "$BackupDir\active-response-bin.backup" -Recurse -ErrorAction SilentlyContinue
    Write-Success "Backed up active response scripts"
}

# Create a restore script
$restoreScript = @"
# Restore script for Wazuh Agent configuration
# Created on: $(Get-Date)

Write-Host "Restoring Wazuh Agent configuration from backup..." -ForegroundColor Green

if (Test-Path "$BackupDir\ossec.conf.backup") {
    Copy-Item "$BackupDir\ossec.conf.backup" "$OssecConf"
    Write-Host "Restored ossec.conf" -ForegroundColor Green
}

if (Test-Path "$BackupDir\active-response-bin.backup") {
    Remove-Item "$ActiveResponsePath" -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item "$BackupDir\active-response-bin.backup" "$ActiveResponsePath" -Recurse
    Write-Host "Restored active response scripts" -ForegroundColor Green
}

Write-Host "Restarting Wazuh agent..." -ForegroundColor Yellow
Restart-Service -Name "WazuhSvc" -Force

Write-Host "Configuration restored successfully!" -ForegroundColor Green
"@

Set-Content -Path "$BackupDir\restore.ps1" -Value $restoreScript
Write-Success "Created restore script at $BackupDir\restore.ps1"

# Step 2: Download and run VirusTotal integration script
Write-Status "Downloading VirusTotal integration script..."

# Create temporary directory for the script
$TempDir = New-TemporaryFile | ForEach-Object { Remove-Item $_; New-Item -ItemType Directory -Path $_ }
Push-Location $TempDir

try {
    # Download the VirusTotal agent script
    $githubUrl = "https://raw.githubusercontent.com/Soumendu22/Wazuh_NexusSentinel/master/windows/agent/virustotalagent.ps1"
    
    try {
        Invoke-WebRequest -Uri $githubUrl -OutFile "virustotalagent.ps1"
        Write-Success "Downloaded VirusTotal agent script"
    } catch {
        Write-ErrorMessage "Failed to download VirusTotal script from GitHub"
        Write-Status "Looking for local copy..."
        
        # Try to find local copy
        $LocalScript = "C:\temp\virustotalagent.ps1"
        if (Test-Path $LocalScript) {
            Copy-Item $LocalScript ".\virustotalagent.ps1"
            Write-Success "Using local VirusTotal script"
        } else {
            Write-ErrorMessage "No local VirusTotal script found. Please ensure the script is available."
            exit 1
        }
    }

    # Step 3: Run VirusTotal integration
    Write-Status "Running VirusTotal integration script..."
    try {
        & ".\virustotalagent.ps1" -UserName $UserName
        Write-Success "VirusTotal integration completed successfully"
    } catch {
        Write-ErrorMessage "VirusTotal integration failed"
        Write-Status "You can restore the original configuration using: $BackupDir\restore.ps1"
        exit 1
    }

} finally {
    Pop-Location
    Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Step 4: Restart Wazuh Agent service
Write-Status "Restarting Wazuh Agent service..."
try {
    Restart-Service -Name "WazuhSvc" -Force
    Write-Success "Wazuh Agent restarted successfully"
} catch {
    Write-ErrorMessage "Failed to restart Wazuh Agent"
    Write-Status "You can restore the original configuration using: $BackupDir\restore.ps1"
    exit 1
}

# Wait for service to be fully ready
Write-Status "Waiting for Wazuh Agent to be fully ready..."
Start-Sleep -Seconds 10

# Verify service status
$service = Get-Service -Name "WazuhSvc"
if ($service.Status -eq "Running") {
    Write-Success "Wazuh Agent is running properly"
} else {
    Write-ErrorMessage "Wazuh Agent failed to start properly after configuration"
    Write-Status "You can restore the original configuration using: $BackupDir\restore.ps1"
    exit 1
}

# Final status report
Write-Success "Custom Wazuh Agent setup completed successfully!"
Write-Host ""
Write-Status "Setup Summary:"
Write-Host "  ✓ Configuration backup created: $BackupDir" -ForegroundColor White
Write-Host "  ✓ VirusTotal integration configured" -ForegroundColor White
Write-Host "  ✓ Active response script installed" -ForegroundColor White
Write-Host "  ✓ Wazuh Agent service restarted" -ForegroundColor White
Write-Host "  ✓ Service status verified" -ForegroundColor White
Write-Host ""
Write-Status "Important Information:"
Write-Host "  - Backup location: $BackupDir" -ForegroundColor White
Write-Host "  - Restore script: $BackupDir\restore.ps1" -ForegroundColor White
Write-Host "  - Service status: $($service.Status)" -ForegroundColor White
Write-Host "  - Agent logs: $WazuhPath\ossec.log" -ForegroundColor White
Write-Host ""
Write-Status "Monitored Directory:"
Write-Host "  - C:\Users\$UserName\Downloads (real-time file integrity monitoring)" -ForegroundColor White
Write-Host ""
Write-Warning "Note: If you encounter issues, use the restore script to revert changes"
Write-Status "Setup completed at $(Get-Date)"