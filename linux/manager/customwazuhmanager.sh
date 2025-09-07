#!/bin/bash

# Custom Wazuh Manager Setup Script with VirusTotal Integration
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

# Check if Wazuh manager is installed and running
if ! systemctl is-active --quiet wazuh-manager; then
    print_error "Wazuh manager is not running. Please install and start Wazuh manager first."
    exit 1
fi

print_status "Starting Custom Wazuh Manager Configuration with VirusTotal Integration..."

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

# Backup local_rules.xml
if [ -f "/var/ossec/etc/rules/local_rules.xml" ]; then
    cp "/var/ossec/etc/rules/local_rules.xml" "$BACKUP_DIR/local_rules.xml.backup"
    print_success "Backed up local_rules.xml"
else
    print_warning "local_rules.xml not found - will be created during VirusTotal integration"
fi

# Create a restore script
cat > "$BACKUP_DIR/restore.sh" << EOF
#!/bin/bash
# Restore script for Wazuh Manager configuration
# Created on: $(date)

echo "Restoring Wazuh Manager configuration from backup..."

if [ -f "$BACKUP_DIR/ossec.conf.backup" ]; then
    cp "$BACKUP_DIR/ossec.conf.backup" "/var/ossec/etc/ossec.conf"
    echo "Restored ossec.conf"
fi

if [ -f "$BACKUP_DIR/local_rules.xml.backup" ]; then
    cp "$BACKUP_DIR/local_rules.xml.backup" "/var/ossec/etc/rules/local_rules.xml"
    echo "Restored local_rules.xml"
fi

echo "Restarting Wazuh manager..."
systemctl restart wazuh-manager

echo "Configuration restored successfully!"
EOF

chmod +x "$BACKUP_DIR/restore.sh"
print_success "Created restore script at $BACKUP_DIR/restore.sh"

# Step 2: Download and run VirusTotal integration script
print_status "Downloading VirusTotal integration script..."

# Create temporary directory for the script
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Download the VirusTotal manager script
if curl -LO "https://raw.githubusercontent.com/Soumendu22/Wazuh_NexusSentinel/master/linux/manager/virustotalmanager.sh"; then
    print_success "Downloaded VirusTotal manager script"
else
    print_error "Failed to download VirusTotal script from GitHub"
    print_status "Looking for local copy..."
    
    # Try to find local copy
    LOCAL_SCRIPT="/opt/virustotalmanager.sh"
    if [ -f "$LOCAL_SCRIPT" ]; then
        cp "$LOCAL_SCRIPT" "./virustotalmanager.sh"
        print_success "Using local VirusTotal script"
    else
        print_error "No local VirusTotal script found. Please ensure the script is available."
        exit 1
    fi
fi

# Make the script executable
chmod +x virustotalmanager.sh

# Step 3: Run VirusTotal integration
print_status "Running VirusTotal integration script..."
if ./virustotalmanager.sh; then
    print_success "VirusTotal integration completed successfully"
else
    print_error "VirusTotal integration failed"
    print_status "You can restore the original configuration using: $BACKUP_DIR/restore.sh"
    exit 1
fi

# Step 4: Restart Wazuh Manager service
print_status "Restarting Wazuh Manager service..."
if systemctl restart wazuh-manager; then
    print_success "Wazuh Manager restarted successfully"
else
    print_error "Failed to restart Wazuh Manager"
    print_status "You can restore the original configuration using: $BACKUP_DIR/restore.sh"
    exit 1
fi

# Wait for service to be fully ready
print_status "Waiting for Wazuh Manager to be fully ready..."
sleep 10

# Verify service status
if systemctl is-active --quiet wazuh-manager; then
    print_success "Wazuh Manager is running properly"
else
    print_error "Wazuh Manager failed to start properly after configuration"
    print_status "You can restore the original configuration using: $BACKUP_DIR/restore.sh"
    exit 1
fi

# Step 5: Validate configuration
print_status "Validating Wazuh configuration..."
if /var/ossec/bin/wazuh-logtest -t 2>/dev/null; then
    print_success "Configuration validation passed"
else
    print_warning "Configuration validation failed, but service is running"
fi

# Cleanup temporary directory
cd /
rm -rf "$TEMP_DIR"

# Final status report
print_success "Custom Wazuh Manager setup completed successfully!"
echo
print_status "Setup Summary:"
echo "  ✓ Configuration backup created: $BACKUP_DIR"
echo "  ✓ VirusTotal integration configured"
echo "  ✓ Wazuh Manager service restarted"
echo "  ✓ Service status verified"
echo
print_status "Important Information:"
echo "  - Backup location: $BACKUP_DIR"
echo "  - Restore script: $BACKUP_DIR/restore.sh"
echo "  - Service status: $(systemctl is-active wazuh-manager)"
echo "  - Log file: /var/ossec/logs/ossec.log"
echo
print_status "Next Steps:"
echo "  1. Configure Wazuh agents using the custom agent script"
echo "  2. Test VirusTotal integration with EICAR test file"
echo "  3. Monitor alerts in Wazuh dashboard"
echo
print_warning "Note: If you encounter issues, use the restore script to revert changes"
print_status "Setup completed at $(date)"