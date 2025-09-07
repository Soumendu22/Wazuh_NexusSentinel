#!/bin/bash

# Custom Wazuh Agent Setup Script with VirusTotal Integration
# This script backs up configuration files, runs VirusTotal integration, and restarts services

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   exit 1
fi

# Check if Wazuh agent is installed and running
if ! systemctl is-active --quiet wazuh-agent; then
    print_error "Wazuh agent is not running. Please install and start Wazuh agent first."
    exit 1
fi

print_status "Starting Custom Wazuh Agent Configuration with VirusTotal Integration..."

# Create backup directory with timestamp
BACKUP_DIR="/var/ossec/backup/$(date +%Y%m%d_%H%M%S)"
print_status "Creating backup directory: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

# Step 1: Backup configuration files
print_status "Backing up configuration files..."

# Backup ossec.conf
if [ -f "/var/ossec/etc/ossec.conf" ]; then
    cp "/var/ossec/etc/ossec.conf" "$BACKUP_DIR/ossec.conf.backup"
    print_success "Backed up ossec.conf"
else
    print_warning "ossec.conf not found - this may be a fresh installation"
fi

# Backup existing active response scripts if they exist
if [ -d "/var/ossec/active-response/bin" ]; then
    cp -r "/var/ossec/active-response/bin" "$BACKUP_DIR/active-response-bin.backup" 2>/dev/null || true
    print_success "Backed up active response scripts"
fi

# Create a restore script
cat > "$BACKUP_DIR/restore.sh" << EOF
#!/bin/bash
# Restore script for Wazuh Agent configuration
# Created on: $(date)

echo "Restoring Wazuh Agent configuration from backup..."

if [ -f "$BACKUP_DIR/ossec.conf.backup" ]; then
    cp "$BACKUP_DIR/ossec.conf.backup" "/var/ossec/etc/ossec.conf"
    echo "Restored ossec.conf"
fi

if [ -d "$BACKUP_DIR/active-response-bin.backup" ]; then
    rm -rf "/var/ossec/active-response/bin"
    cp -r "$BACKUP_DIR/active-response-bin.backup" "/var/ossec/active-response/bin"
    echo "Restored active response scripts"
fi

echo "Restarting Wazuh agent..."
systemctl restart wazuh-agent

echo "Configuration restored successfully!"
EOF

chmod +x "$BACKUP_DIR/restore.sh"
print_success "Created restore script at $BACKUP_DIR/restore.sh"

# Step 2: Download and run VirusTotal integration script
print_status "Downloading VirusTotal integration script..."

# Create temporary directory for the script
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Download the VirusTotal agent script
if curl -LO "https://raw.githubusercontent.com/Soumendu22/Wazuh_NexusSentinel/master/linux/agent/virustotalagent.sh"; then
    print_success "Downloaded VirusTotal agent script"
else
    print_error "Failed to download VirusTotal script from GitHub"
    print_status "Looking for local copy..."
    
    # Try to find local copy
    LOCAL_SCRIPT="/opt/virustotalagent.sh"
    if [ -f "$LOCAL_SCRIPT" ]; then
        cp "$LOCAL_SCRIPT" "./virustotalagent.sh"
        print_success "Using local VirusTotal script"
    else
        print_error "No local VirusTotal script found. Please ensure the script is available."
        exit 1
    fi
fi

# Make the script executable
chmod +x virustotalagent.sh

# Step 3: Run VirusTotal integration
print_status "Running VirusTotal integration script..."
if ./virustotalagent.sh; then
    print_success "VirusTotal integration completed successfully"
else
    print_error "VirusTotal integration failed"
    print_status "You can restore the original configuration using: $BACKUP_DIR/restore.sh"
    exit 1
fi

# Step 4: Restart Wazuh Agent service
print_status "Restarting Wazuh Agent service..."
if systemctl restart wazuh-agent; then
    print_success "Wazuh Agent restarted successfully"
else
    print_error "Failed to restart Wazuh Agent"
    print_status "You can restore the original configuration using: $BACKUP_DIR/restore.sh"
    exit 1
fi

# Wait for service to be fully ready
print_status "Waiting for Wazuh Agent to be fully ready..."
sleep 10

# Verify service status
if systemctl is-active --quiet wazuh-agent; then
    print_success "Wazuh Agent is running properly"
else
    print_error "Wazuh Agent failed to start properly after configuration"
    print_status "You can restore the original configuration using: $BACKUP_DIR/restore.sh"
    exit 1
fi

# Step 5: Verify agent connection to manager
print_status "Checking agent connection..."
if grep -q "Connected to the server" /var/ossec/logs/ossec.log 2>/dev/null; then
    print_success "Agent is connected to Wazuh Manager"
else
    print_warning "Agent connection status unclear - check /var/ossec/logs/ossec.log"
fi

# Step 6: Create test script for VirusTotal integration
print_status "Creating VirusTotal test script..."
cat > "/root/test_virustotal_integration.sh" << 'EOF'
#!/bin/bash
# Test script for VirusTotal integration

echo "Testing VirusTotal integration..."
echo "Downloading EICAR test file to trigger VirusTotal scan..."
echo "This file should be detected as malicious and automatically removed."
echo

# Download EICAR test file to monitored directory
echo "Downloading to /root directory (monitored by FIM)..."
curl -Lo /root/eicar_test.com https://secure.eicar.org/eicar.com

if [ -f /root/eicar_test.com ]; then
    echo "EICAR test file downloaded successfully"
    echo "File details:"
    ls -lah /root/eicar_test.com
    echo
    echo "Monitor the following for integration verification:"
    echo "  1. Wazuh Dashboard for FIM alerts"
    echo "  2. VirusTotal API calls in manager logs"
    echo "  3. Active response execution"
    echo "  4. Automatic file removal"
    echo
    echo "Logs to monitor:"
    echo "  - Agent FIM: /var/ossec/logs/ossec.log"
    echo "  - Manager VirusTotal: /var/ossec/logs/integrations.log"
    echo "  - Active Response: /var/ossec/logs/active-responses.log"
    echo
    echo "The file should be automatically removed within a few minutes."
else
    echo "Failed to download EICAR test file"
    echo "Please check your internet connection and try again."
fi
EOF

chmod +x "/root/test_virustotal_integration.sh"
print_success "Created test script at /root/test_virustotal_integration.sh"

# Cleanup temporary directory
cd /
rm -rf "$TEMP_DIR"

# Final status report
print_success "Custom Wazuh Agent setup completed successfully!"
echo
print_status "Setup Summary:"
echo "  ✓ Configuration backup created: $BACKUP_DIR"
echo "  ✓ VirusTotal integration configured"
echo "  ✓ Active response script installed"
echo "  ✓ Wazuh Agent service restarted"
echo "  ✓ Service status verified"
echo "  ✓ Test script created"
echo
print_status "Important Information:"
echo "  - Backup location: $BACKUP_DIR"
echo "  - Restore script: $BACKUP_DIR/restore.sh"
echo "  - Service status: $(systemctl is-active wazuh-agent)"
echo "  - Agent logs: /var/ossec/logs/ossec.log"
echo "  - Test script: /root/test_virustotal_integration.sh"
echo
print_status "Testing the Integration:"
echo "  1. Run: /root/test_virustotal_integration.sh"
echo "  2. Monitor Wazuh dashboard for alerts"
echo "  3. Check that the test file gets automatically removed"
echo
print_status "Monitored Directory:"
echo "  - /root (real-time file integrity monitoring)"
echo
print_warning "Note: If you encounter issues, use the restore script to revert changes"
print_status "Setup completed at $(date)"