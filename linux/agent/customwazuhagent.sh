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



# Step 7: Suricata Integration Setup
print_status "Starting Suricata Integration after VirusTotal setup..."
echo
print_status "Suricata requires network interface and IP address configuration"

# Prompt for IP address
read -p "Enter the IP address of this Ubuntu endpoint (e.g., 10.0.2.15): " UBUNTU_IP
while [[ ! $UBUNTU_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; do
    print_error "Invalid IP address format. Please enter a valid IPv4 address."
    read -p "Enter the IP address of this Ubuntu endpoint (e.g., 10.0.2.15): " UBUNTU_IP
done

# Show available network interfaces
print_status "Available network interfaces:"
ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print "  - " $2}' | sed 's/@.*//'
echo

# Prompt for network interface
read -p "Enter the network interface to monitor (e.g., enp0s3, eth0): " INTERFACE
while [[ -z "$INTERFACE" ]]; do
    print_error "Interface cannot be empty. Please enter a valid network interface."
    read -p "Enter the network interface to monitor (e.g., enp0s3, eth0): " INTERFACE
done

# Verify interface exists
if ! ip link show "$INTERFACE" &>/dev/null; then
    print_warning "Interface '$INTERFACE' not found. Available interfaces:"
    ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print "  - " $2}' | sed 's/@.*//'
    read -p "Please enter a valid network interface: " INTERFACE
fi

print_status "Configuration: IP=$UBUNTU_IP, Interface=$INTERFACE"

# Download and run Suricata integration script
print_status "Downloading Suricata integration script..."
if curl -LO "https://raw.githubusercontent.com/Soumendu22/Wazuh_NexusSentinel/master/linux/agent/suricata.sh"; then
    print_success "Downloaded Suricata integration script"
else
    print_error "Failed to download from GitHub, looking for local copy..."
    # Try to find local copy
    if [ -f "/opt/suricata.sh" ]; then
        cp "/opt/suricata.sh" "./suricata.sh"
        print_success "Using local Suricata script"
    elif [ -f "$(dirname "$0")/suricata.sh" ]; then
        cp "$(dirname "$0")/suricata.sh" "./suricata.sh"
        print_success "Using Suricata script from same directory"
    else
        print_error "No Suricata script found. Please ensure the script is available."
        print_warning "Skipping Suricata integration - you can run it manually later"
        print_status "Manual command: sudo ./suricata.sh $UBUNTU_IP $INTERFACE"
        # Continue without Suricata integration
        SURICATA_SKIPPED=true
    fi
fi

if [[ "$SURICATA_SKIPPED" != "true" ]]; then
    # Make the script executable
    chmod +x suricata.sh
    
    # Run Suricata integration
    print_status "Running Suricata integration with IP: $UBUNTU_IP, Interface: $INTERFACE"
    if ./suricata.sh "$UBUNTU_IP" "$INTERFACE"; then
        print_success "Suricata integration completed successfully"
    else
        print_error "Suricata integration failed"
        print_status "You can run it manually later with: sudo ./suricata.sh $UBUNTU_IP $INTERFACE"
    fi
fi

# Step 8: Auditd Integration Setup
print_status "Starting Auditd Integration after Suricata setup..."
echo
print_status "Auditd will monitor command execution for security auditing"

# Prompt for user ID to monitor (default 1000)
read -p "Enter the user ID to monitor for command execution (default: 1000): " AUDIT_USER_ID
AUDIT_USER_ID="${AUDIT_USER_ID:-1000}"

# Validate user ID is numeric
while ! [[ "$AUDIT_USER_ID" =~ ^[0-9]+$ ]]; do
    print_error "Invalid user ID. Please enter a numeric user ID."
    read -p "Enter the user ID to monitor for command execution (default: 1000): " AUDIT_USER_ID
    AUDIT_USER_ID="${AUDIT_USER_ID:-1000}"
done

print_status "Configuration: Monitoring user ID $AUDIT_USER_ID"

# Download and run Auditd integration script
print_status "Downloading Auditd integration script..."
if curl -LO "https://raw.githubusercontent.com/Soumendu22/Wazuh_NexusSentinel/master/linux/agent/auditd.sh"; then
    print_success "Downloaded Auditd integration script"
else
    print_error "Failed to download from GitHub, looking for local copy..."
    # Try to find local copy
    if [ -f "/opt/auditd.sh" ]; then
        cp "/opt/auditd.sh" "./auditd.sh"
        print_success "Using local Auditd script"
    elif [ -f "$(dirname "$0")/auditd.sh" ]; then
        cp "$(dirname "$0")/auditd.sh" "./auditd.sh"
        print_success "Using Auditd script from same directory"
    else
        print_error "No Auditd script found. Please ensure the script is available."
        print_warning "Skipping Auditd integration - you can run it manually later"
        print_status "Manual command: sudo ./auditd.sh $AUDIT_USER_ID"
        # Continue without Auditd integration
        AUDITD_SKIPPED=true
    fi
fi

if [[ "$AUDITD_SKIPPED" != "true" ]]; then
    # Make the script executable
    chmod +x auditd.sh
    
    # Run Auditd integration
    print_status "Running Auditd integration for user ID: $AUDIT_USER_ID"
    if ./auditd.sh "$AUDIT_USER_ID"; then
        print_success "Auditd integration completed successfully"
    else
        print_error "Auditd integration failed"
        print_status "You can run it manually later with: sudo ./auditd.sh $AUDIT_USER_ID"
    fi
fi

# Step 9: YARA Malware Detection Integration Setup
print_status "Starting YARA Malware Detection Integration after Auditd setup..."
echo
print_status "YARA will scan files for malware using threat intelligence rules"

print_status "Using default demo API key for YARA rules download"

# Download and run YARA integration script
print_status "Downloading YARA integration script..."
if curl -LO "https://raw.githubusercontent.com/Soumendu22/Wazuh_NexusSentinel/master/linux/agent/yaramodelagent.sh"; then
    print_success "Downloaded YARA integration script"
else
    print_error "Failed to download from GitHub, looking for local copy..."
    # Try to find local copy
    if [ -f "/opt/yaramodelagent.sh" ]; then
        cp "/opt/yaramodelagent.sh" "./yaramodelagent.sh"
        print_success "Using local YARA script"
    elif [ -f "$(dirname "$0")/yaramodelagent.sh" ]; then
        cp "$(dirname "$0")/yaramodelagent.sh" "./yaramodelagent.sh"
        print_success "Using YARA script from same directory"
    else
        print_error "No YARA script found. Please ensure the script is available."
        print_warning "Skipping YARA integration - you can run it manually later"
        print_status "Manual command: sudo ./yaramodelagent.sh"
        # Continue without YARA integration
        YARA_SKIPPED=true
    fi
fi

if [[ "$YARA_SKIPPED" != "true" ]]; then
    # Make the script executable
    chmod +x yaramodelagent.sh
    
    # Run YARA integration
    print_status "Running YARA malware detection integration..."
    if ./yaramodelagent.sh; then
        print_success "YARA integration completed successfully"
    else
        print_error "YARA integration failed"
        print_status "You can run it manually later with: sudo ./yaramodelagent.sh"
    fi
fi

# Cleanup temporary directory
cd /
rm -rf "$TEMP_DIR"

# Clean up downloaded scripts if they exist in temp location
if [ -f "./suricata.sh" ]; then
    rm -f "./suricata.sh"
fi
if [ -f "./auditd.sh" ]; then
    rm -f "./auditd.sh"
fi
if [ -f "./yaramodelagent.sh" ]; then
    rm -f "./yaramodelagent.sh"
fi

# Final status report
print_success "Custom Wazuh Agent setup completed successfully!"
echo
print_status "Setup Summary:"
echo "  ✓ Configuration backup created: $BACKUP_DIR"
echo "  ✓ VirusTotal integration configured"
echo "  ✓ Active response script installed"
if [[ "$SURICATA_SKIPPED" != "true" ]]; then
    echo "  ✓ Suricata integration configured ($UBUNTU_IP on $INTERFACE)"
else
    echo "  ! Suricata integration skipped (can be run manually)"
fi
if [[ "$AUDITD_SKIPPED" != "true" ]]; then
    echo "  ✓ Auditd integration configured (monitoring user ID: $AUDIT_USER_ID)"
else
    echo "  ! Auditd integration skipped (can be run manually)"
fi
if [[ "$YARA_SKIPPED" != "true" ]]; then
    echo "  ✓ YARA malware detection configured"
else
    echo "  ! YARA integration skipped (can be run manually)"
fi
echo "  ✓ Wazuh Agent service restarted"
echo "  ✓ Service status verified"

echo
print_status "Important Information:"
echo "  - Backup location: $BACKUP_DIR"
echo "  - Restore script: $BACKUP_DIR/restore.sh"
echo "  - Service status: $(systemctl is-active wazuh-agent)"
echo "  - Agent logs: /var/ossec/logs/ossec.log"
if [[ "$SURICATA_SKIPPED" != "true" ]]; then
    echo "  - Suricata status: $(systemctl is-active suricata 2>/dev/null || echo 'not running')"
fi
if [[ "$AUDITD_SKIPPED" != "true" ]]; then
    echo "  - Auditd status: $(systemctl is-active auditd 2>/dev/null || echo 'not running')"
fi
if [[ "$YARA_SKIPPED" != "true" ]]; then
    echo "  - YARA version: $(yara --version 2>/dev/null || echo 'not installed')"
fi


echo
print_status "Testing the Integrations:"
echo "  VirusTotal:"
echo "    1. Monitor Wazuh dashboard for FIM alerts"
echo "    2. Use EICAR test file in monitored directories"
echo "    3. Check automatic malware removal"
if [[ "$SURICATA_SKIPPED" != "true" ]]; then
    echo "  Suricata:"
    echo "    1. Monitor Wazuh dashboard with filter: rule.groups:suricata"
    echo "    2. Generate network traffic to trigger alerts"
    echo "    3. Check Suricata logs: /var/log/suricata/eve.json"
fi
if [[ "$AUDITD_SKIPPED" != "true" ]]; then
    echo "  Auditd:"
    echo "    1. Execute commands as user ID $AUDIT_USER_ID"
    echo "    2. Monitor Wazuh dashboard for audit alerts"
    echo "    3. Check audit logs: /var/log/audit/audit.log"
fi
if [[ "$YARA_SKIPPED" != "true" ]]; then
    echo "  YARA:"
    echo "    1. Add suspicious files to /tmp/yara/malware directory"
    echo "    2. Monitor Wazuh dashboard with filter: rule.groups:yara"
    echo "    3. Check Active Response logs: /var/ossec/logs/active-responses.log"
fi
echo
print_status "Monitored Components:"
echo "  - /root (real-time file integrity monitoring)"
if [[ "$SURICATA_SKIPPED" != "true" ]]; then
    echo "  - Network traffic on $INTERFACE (Suricata IDS)"
    echo "  - Suricata logs: /var/log/suricata/"
fi
if [[ "$AUDITD_SKIPPED" != "true" ]]; then
    echo "  - Command execution by user ID $AUDIT_USER_ID (Auditd)"
    echo "  - Audit logs: /var/log/audit/audit.log"
fi
if [[ "$YARA_SKIPPED" != "true" ]]; then
    echo "  - Files in /tmp/yara/malware (YARA malware detection)"
    echo "  - YARA rules: /tmp/yara/rules/yara_rules.yar"
fi
echo
if [[ "$SURICATA_SKIPPED" == "true" ]]; then
    print_warning "To complete Suricata integration manually:"
    echo "  sudo ./suricata.sh $UBUNTU_IP $INTERFACE"
    echo
fi
if [[ "$AUDITD_SKIPPED" == "true" ]]; then
    print_warning "To complete Auditd integration manually:"
    echo "  sudo ./auditd.sh $AUDIT_USER_ID"
    echo
fi
if [[ "$YARA_SKIPPED" == "true" ]]; then
    print_warning "To complete YARA integration manually:"
    echo "  sudo ./yaramodelagent.sh"
    echo
fi
print_warning "Note: If you encounter issues, use the restore script to revert changes"
print_status "Setup completed at $(date)"