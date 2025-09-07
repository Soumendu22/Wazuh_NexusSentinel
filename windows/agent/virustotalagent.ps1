# Wazuh Agent VirusTotal Integration Script for Windows
# Based on: https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html

param(
    [string]$UserName = $env:USERNAME
)

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

Write-Host "Configuring Wazuh Agent for VirusTotal integration..." -ForegroundColor Green

$WazuhPath = "C:\Program Files (x86)\ossec-agent"
$OssecConf = "$WazuhPath\ossec.conf"
$ActiveResponsePath = "$WazuhPath\active-response\bin"

# Check if Wazuh agent is installed
if (-not (Test-Path $WazuhPath)) {
    Write-Error "Wazuh agent not found at $WazuhPath"
    exit 1
}

# Step 1: Configure syscheck to monitor Downloads directory
Write-Host "Configuring File Integrity Monitoring..." -ForegroundColor Yellow

$ossecContent = Get-Content $OssecConf -Raw

# Enable syscheck if disabled
$ossecContent = $ossecContent -replace '<disabled>yes</disabled>', '<disabled>no</disabled>'

# Add Downloads directory monitoring
$downloadsDir = "C:\Users\$UserName\Downloads"
$directoryConfig = "<directories realtime=`"yes`">$downloadsDir</directories>"

# Insert before closing </syscheck> tag
$ossecContent = $ossecContent -replace '</syscheck>', "  $directoryConfig`n  </syscheck>"

Set-Content -Path $OssecConf -Value $ossecContent

# Step 2: Install Python if not present
Write-Host "Checking Python installation..." -ForegroundColor Yellow

try {
    $pythonVersion = python --version 2>$null
    Write-Host "Python is installed: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "Python not found. Please install Python manually from https://www.python.org/" -ForegroundColor Red
    Write-Host "Make sure to check 'Add Python to PATH' during installation" -ForegroundColor Red
    exit 1
}

# Step 3: Install PyInstaller
Write-Host "Installing PyInstaller..." -ForegroundColor Yellow

try {
    pip install pyinstaller --quiet
    Write-Host "PyInstaller installed successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to install PyInstaller: $_"
    exit 1
}

# Step 4: Create the active response Python script
Write-Host "Creating active response script..." -ForegroundColor Yellow

# Create active-response directory if it doesn't exist
if (-not (Test-Path $ActiveResponsePath)) {
    New-Item -Path $ActiveResponsePath -ItemType Directory -Force
}

$pythonScript = @'
# Copyright (C) 2015-2025, Wazuh Inc.
# All rights reserved.

import os
import sys
import json
import datetime
import stat
import tempfile
import pathlib

if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1

class message:
    def __init__(self):
        self.alert = ""
        self.command = 0

def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        log_file.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name + ": " + msg +"\n")

def setup_and_check_message(argv):
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    msg_obj = message()
    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        msg_obj.command = OS_INVALID
        return msg_obj

    msg_obj.alert = data
    command = data.get("command")

    if command == "add":
        msg_obj.command = ADD_COMMAND
    elif command == "delete":
        msg_obj.command = DELETE_COMMAND
    else:
        msg_obj.command = OS_INVALID
        write_debug_file(argv[0], 'Not valid command: ' + command)

    return msg_obj

def send_keys_and_check_message(argv, keys):
    keys_msg = json.dumps({"version": 1,"origin":{"name": argv[0],"module":"active-response"},"command":"check_keys","parameters":{"keys":keys}})

    write_debug_file(argv[0], keys_msg)
    print(keys_msg)
    sys.stdout.flush()

    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        return message()

    action = data.get("command")

    if "continue" == action:
        ret = message()
        ret.command = CONTINUE_COMMAND
        return ret
    elif "abort" == action:
        ret = message()
        ret.command = ABORT_COMMAND
        return ret
    else:
        ret = message()
        ret.command = OS_INVALID
        write_debug_file(argv[0], "Invalid value of 'command'")
        return ret

def remove_file(argv, filename):
    try:
        if os.path.exists(filename):
            # Check if it's a file and not a directory
            if os.path.isfile(filename):
                os.remove(filename)
                write_debug_file(argv[0], f"Successfully removed threat: {filename}")
                return OS_SUCCESS
            else:
                write_debug_file(argv[0], f"Target is not a file: {filename}")
                return OS_INVALID
        else:
            write_debug_file(argv[0], f"File not found: {filename}")
            return OS_INVALID
    except Exception as e:
        write_debug_file(argv[0], f"Error removing threat {filename}: {str(e)}")
        return OS_INVALID

def main(argv):
    write_debug_file(argv[0], "Started")

    # Check arguments
    if len(argv) != 4:
        write_debug_file(argv[0], "Bad arguments given")
        return OS_INVALID

    # Validate basic fields
    msg = setup_and_check_message(argv)

    if msg.command < 0:
        return OS_INVALID

    if msg.command == ADD_COMMAND:
        # Send keys and check message
        keys = [1]
        ret_msg = send_keys_and_check_message(argv, keys)

        if ret_msg.command == CONTINUE_COMMAND:
            # Get filename from alert data
            try:
                filename = msg.alert['parameters']['alert']['data']['virustotal']['source']['file']
                write_debug_file(argv[0], f"Attempting to remove file: {filename}")
                
                result = remove_file(argv, filename)
                if result == OS_SUCCESS:
                    write_debug_file(argv[0], "Successfully removed threat")
                else:
                    write_debug_file(argv[0], "Error removing threat")
                    
                return result
            except KeyError as e:
                write_debug_file(argv[0], f"Missing required field in alert data: {str(e)}")
                return OS_INVALID
        elif ret_msg.command == ABORT_COMMAND:
            write_debug_file(argv[0], "Aborted")
            return OS_SUCCESS
        else:
            write_debug_file(argv[0], "Invalid continue/abort command")
            return OS_INVALID

    elif msg.command == DELETE_COMMAND:
        write_debug_file(argv[0], "Delete command received - no action needed")
        return OS_SUCCESS
    else:
        write_debug_file(argv[0], f"Invalid command: {msg.command}")

    write_debug_file(argv[0], "Ended")
    return OS_SUCCESS

if __name__ == "__main__":
    sys.exit(main(sys.argv))
'@

Set-Content -Path "$ActiveResponsePath\remove-threat.py" -Value $pythonScript

# Step 5: Convert Python script to executable using PyInstaller
Write-Host "Converting Python script to executable..." -ForegroundColor Yellow

Push-Location $ActiveResponsePath
try {
    pyinstaller --onefile --distpath . remove-threat.py --clean --noconfirm
    
    if (Test-Path "remove-threat.exe") {
        Write-Host "Successfully created remove-threat.exe" -ForegroundColor Green
        
        # Clean up PyInstaller artifacts
        Remove-Item -Path "build" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "remove-threat.spec" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "__pycache__" -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Write-Error "Failed to create remove-threat.exe"
        exit 1
    }
} catch {
    Write-Error "Failed to convert Python script to executable: $_"
    exit 1
} finally {
    Pop-Location
}

# Step 6: Restart Wazuh agent
Write-Host "Restarting Wazuh agent..." -ForegroundColor Yellow

try {
    Restart-Service -Name "WazuhSvc" -Force
    Write-Host "Wazuh Agent VirusTotal integration configured successfully!" -ForegroundColor Green
} catch {
    Write-Error "Failed to restart Wazuh agent service: $_"
    exit 1
}

Write-Host ""
Write-Host "Configuration completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Important Information:" -ForegroundColor Cyan
Write-Host "  - Monitored Directory: C:\Users\$UserName\Downloads" -ForegroundColor White
Write-Host "  - Active Response Script: $ActiveResponsePath\remove-threat.exe" -ForegroundColor White