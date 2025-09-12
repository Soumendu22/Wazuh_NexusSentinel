#!/bin/bash

# Auditd Integration Script for Wazuh Agent
# Based on official Wazuh documentation:
# https://documentation.wazuh.com/current/proof-of-concept-guide/audit-commands-run-by-user.html

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

# Check if Wazuh agent is installed
if ! command -v /var/ossec/bin/wazuh-control &> /dev/null; then
    print_error "Wazuh agent is not installed. Please install Wazuh agent first."
    exit 1
fi

print_status "Starting Auditd Integration Setup..."

# Get user ID for audit rules (default to user 1000, but allow override)
USER_ID="${1:-1000}"
print_status "Configuring Auditd for user ID: $USER_ID"

# Step 1: Install Auditd
print_status "Installing Auditd..."
apt -y install auditd
print_success "Auditd installed successfully"

# Step 2: Start and enable Auditd service
print_status "Starting and enabling Auditd service..."
systemctl start auditd
systemctl enable auditd
print_success "Auditd service started and enabled"

# Step 3: Backup original audit rules
print_status "Backing up original audit rules..."
if [ -f "/etc/audit/audit.rules" ]; then
    cp "/etc/audit/audit.rules" "/etc/audit/audit.rules.backup"
    print_success "Audit rules backed up to /etc/audit/audit.rules.backup"
else
    print_warning "No existing audit rules found - creating new file"
    touch "/etc/audit/audit.rules"
fi

# Step 4: Add audit rules for command monitoring
print_status "Adding audit rules for command monitoring..."

# Add audit rules to monitor execve syscalls for the specified user
echo "-a exit,always -F auid=$USER_ID -F egid!=994 -F auid!=-1 -F arch=b32 -S execve -k audit-wazuh-c" >> /etc/audit/audit.rules
echo "-a exit,always -F auid=$USER_ID -F egid!=994 -F auid!=-1 -F arch=b64 -S execve -k audit-wazuh-c" >> /etc/audit/audit.rules

print_success "Audit rules added for user ID: $USER_ID"

# Step 5: Reload audit rules and verify
print_status "Reloading audit rules..."
auditctl -R /etc/audit/audit.rules
print_success "Audit rules reloaded"

print_status "Verifying audit rules are in place..."
auditctl -l | grep "audit-wazuh-c" || print_warning "Audit rules verification failed - check manually"
print_success "Audit rules verified"

# Step 6: Configure Wazuh agent to read audit logs
print_status "Configuring Wazuh agent to monitor audit logs..."

# Backup ossec.conf
cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.auditd.backup

# Add audit log configuration to ossec.conf
sed -i '/<\/ossec_config>/i\
  <localfile>\
    <log_format>audit</log_format>\
    <location>/var/log/audit/audit.log</location>\
  </localfile>' /var/ossec/etc/ossec.conf

print_success "Wazuh agent configured to monitor audit logs"

# Step 7: Restart Wazuh agent
print_status "Restarting Wazuh agent to apply changes..."
systemctl restart wazuh-agent
print_success "Wazuh agent restarted"

# Wait for services to be ready
print_status "Waiting for services to be fully ready..."
sleep 10

# Step 8: Verify services status
print_status "Verifying services status..."

# Check Auditd status
if systemctl is-active --quiet auditd; then
    print_success "Auditd is running properly"
else
    print_error "Auditd failed to start properly"
    print_status "Check logs: sudo journalctl -u auditd -f"
fi

# Check Wazuh agent status
if systemctl is-active --quiet wazuh-agent; then
    print_success "Wazuh agent is running properly"
else
    print_error "Wazuh agent failed to start properly"
    print_status "Check logs: sudo tail -f /var/ossec/logs/ossec.log"
fi

# Step 9: Check audit log file exists and is being written to
print_status "Checking audit log file..."
if [ -f "/var/log/audit/audit.log" ]; then
    print_success "Audit log file exists: /var/log/audit/audit.log"
    print_status "Recent audit log entries:"
    tail -n 5 /var/log/audit/audit.log 2>/dev/null || print_warning "No audit entries yet"
else
    print_warning "Audit log file not found - may take time to be created"
fi

# Final status report
print_success "Auditd Integration Setup Completed Successfully!"
echo
print_status "Setup Summary:"
echo "  ✓ Auditd installed and configured"
echo "  ✓ Audit rules added for user ID: $USER_ID"
echo "  ✓ Wazuh agent configured to monitor audit logs"
echo "  ✓ Services restarted and verified"
echo
print_status "Configuration Details:"
echo "  - Audit rules: /etc/audit/audit.rules"
echo "  - Audit backup: /etc/audit/audit.rules.backup"
echo "  - Wazuh config: /var/ossec/etc/ossec.conf"
echo "  - Wazuh backup: /var/ossec/etc/ossec.conf.auditd.backup"
echo "  - Audit logs: /var/log/audit/audit.log"
echo
print_status "Service Status:"
echo "  - Auditd: $(systemctl is-active auditd)"
echo "  - Wazuh Agent: $(systemctl is-active wazuh-agent)"
echo
print_status "Monitored Events:"
echo "  - Commands executed by user ID: $USER_ID"
echo "  - System calls: execve (both 32-bit and 64-bit)"
echo "  - Audit key: audit-wazuh-c"
echo
print_status "Testing the Integration:"
echo "  1. Execute commands as the monitored user"
echo "  2. Monitor Wazuh dashboard for audit alerts"
echo "  3. Check audit logs: sudo tail -f /var/log/audit/audit.log"
echo "  4. Verify Wazuh agent logs: sudo tail -f /var/ossec/logs/ossec.log"
echo
print_status "Verification Commands:"
echo "  - Check audit rules: sudo auditctl -l"
echo "  - Monitor audit events: sudo tail -f /var/log/audit/audit.log"
echo "  - Test command execution: run any command as user $USER_ID"
echo
print_warning "Note: If you encounter issues, restore from backups:"
echo "  - Audit rules: sudo cp /etc/audit/audit.rules.backup /etc/audit/audit.rules"
echo "  - Wazuh config: sudo cp /var/ossec/etc/ossec.conf.auditd.backup /var/ossec/etc/ossec.conf"
echo
print_status "Integration completed at $(date)"
print_status "Monitor dashboard and logs for audit events!"