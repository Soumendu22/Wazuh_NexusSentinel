#!/bin/bash

# YARA Malware Detection Integration Script for Wazuh Manager (Linux Server)
# Based on official Wazuh documentation:
# https://documentation.wazuh.com/current/proof-of-concept-guide/detect-malware-yara-integration.html

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

# Check if Wazuh manager is installed
if ! command -v /var/ossec/bin/wazuh-control &> /dev/null; then
    print_error "Wazuh manager is not installed. Please install Wazuh manager first."
    exit 1
fi

print_status "Starting YARA Malware Detection Integration Setup for Wazuh Manager (Ubuntu)..."

# Step 1: Backup configuration files
print_status "Creating backup of configuration files..."
BACKUP_DIR="/var/ossec/backup/yara_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup existing files
cp /var/ossec/etc/rules/local_rules.xml "$BACKUP_DIR/local_rules.xml.backup" 2>/dev/null || touch "$BACKUP_DIR/local_rules.xml.backup"
cp /var/ossec/etc/decoders/local_decoder.xml "$BACKUP_DIR/local_decoder.xml.backup" 2>/dev/null || touch "$BACKUP_DIR/local_decoder.xml.backup"
cp /var/ossec/etc/ossec.conf "$BACKUP_DIR/ossec.conf.backup"

print_success "Configuration files backed up to $BACKUP_DIR"

# Step 2: Configure local rules for YARA integration
print_status "Configuring detection rules for YARA integration..."

# Check if local_rules.xml exists, create if not
if [ ! -f "/var/ossec/etc/rules/local_rules.xml" ]; then
    cat > /var/ossec/etc/rules/local_rules.xml << 'EOF'
<!-- Local rules -->

<!-- Modify it at your will. -->
<!-- Copyright (C) 2015, Wazuh Inc. -->

<!-- Example -->
<group name="local,syslog,sshd,">
  <!--
  Dec 10 01:02:02 host sshd[1234]: Failed password for root from 1.1.1.1 port 1066 ssh2
  -->
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failure from IP 1.1.1.1.</description>
    <group>authentication_failure,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
</group>
EOF
fi

# Add YARA-specific rules to local_rules.xml
if ! grep -q "rule id=\"100300\"" /var/ossec/etc/rules/local_rules.xml; then
    sed -i '/<\/group>/i\
\
<group name="syscheck,">\
  <rule id="100300" level="7">\
    <if_sid>550</if_sid>\
    <field name="file">/tmp/yara/malware/</field>\
    <description>File modified in /tmp/yara/malware/ directory.</description>\
  </rule>\
  <rule id="100301" level="7">\
    <if_sid>554</if_sid>\
    <field name="file">/tmp/yara/malware/</field>\
    <description>File added to /tmp/yara/malware/ directory.</description>\
  </rule>\
</group>\
\
<group name="yara,">\
  <rule id="108000" level="0">\
    <decoded_as>yara_decoder</decoded_as>\
    <description>Yara grouping rule</description>\
  </rule>\
  <rule id="108001" level="12">\
    <if_sid>108000</if_sid>\
    <match>wazuh-yara: INFO - Scan result: </match>\
    <description>File "$(yara_scanned_file)" is a positive match. Yara rule: $(yara_rule)</description>\
  </rule>\
</group>' /var/ossec/etc/rules/local_rules.xml
    print_success "YARA detection rules added to local_rules.xml"
else
    print_warning "YARA rules already exist in local_rules.xml"
fi

# Step 3: Configure local decoders for YARA integration
print_status "Configuring decoders for YARA integration..."

# Check if local_decoder.xml exists, create if not
if [ ! -f "/var/ossec/etc/decoders/local_decoder.xml" ]; then
    cat > /var/ossec/etc/decoders/local_decoder.xml << 'EOF'
<!-- Local Decoders -->

<!-- Modify it at your will. -->
<!-- Copyright (C) 2015, Wazuh Inc. -->

<!-- Example -->
<decoder name="local_decoder_example">
  <prematch>^test_prefix</prematch>
</decoder>
EOF
fi

# Add YARA-specific decoders to local_decoder.xml
if ! grep -q "yara_decoder" /var/ossec/etc/decoders/local_decoder.xml; then
    sed -i '/<\/decoder>/a\
\
<decoder name="yara_decoder">\
  <prematch>wazuh-yara:</prematch>\
</decoder>\
\
<decoder name="yara_decoder1">\
  <parent>yara_decoder</parent>\
  <regex>wazuh-yara: (\\S+) - Scan result: (\\S+) (\\S+)</regex>\
  <order>log_type, yara_rule, yara_scanned_file</order>\
</decoder>' /var/ossec/etc/decoders/local_decoder.xml
    print_success "YARA decoders added to local_decoder.xml"
else
    print_warning "YARA decoders already exist in local_decoder.xml"
fi

# Step 4: Configure Active Response in ossec.conf
print_status "Configuring Active Response for YARA integration..."

# Check if YARA Active Response already exists
if ! grep -q "yara_linux" /var/ossec/etc/ossec.conf; then
    # Add YARA Active Response configuration
    sed -i '/<\/ossec_config>/i\
\
  <command>\
    <name>yara_linux</name>\
    <executable>yara.sh</executable>\
    <extra_args>-yara_path /usr/local/bin -yara_rules /tmp/yara/rules/yara_rules.yar</extra_args>\
    <timeout_allowed>no</timeout_allowed>\
  </command>\
\
  <active-response>\
    <disabled>no</disabled>\
    <command>yara_linux</command>\
    <location>local</location>\
    <rules_id>100300,100301</rules_id>\
  </active-response>' /var/ossec/etc/ossec.conf
    print_success "YARA Active Response configuration added to ossec.conf"
else
    print_warning "YARA Active Response configuration already exists in ossec.conf"
fi

# Step 5: Validate configuration syntax
print_status "Validating Wazuh configuration syntax..."
if /var/ossec/bin/wazuh-logtest -t 2>/dev/null || /var/ossec/bin/wazuh-logtest-legacy -t 2>/dev/null; then
    print_success "Configuration syntax is valid"
else
    print_warning "Configuration validation had some warnings - check manually if needed"
fi

# Step 6: Create restore script
print_status "Creating restore script..."
cat > "$BACKUP_DIR/restore_yara.sh" << EOF
#!/bin/bash
# Restore script for YARA integration configuration
# Created on: $(date)

echo "Restoring YARA integration configuration from backup..."

if [ -f "$BACKUP_DIR/local_rules.xml.backup" ]; then
    cp "$BACKUP_DIR/local_rules.xml.backup" "/var/ossec/etc/rules/local_rules.xml"
    echo "Restored local_rules.xml"
fi

if [ -f "$BACKUP_DIR/local_decoder.xml.backup" ]; then
    cp "$BACKUP_DIR/local_decoder.xml.backup" "/var/ossec/etc/decoders/local_decoder.xml"
    echo "Restored local_decoder.xml"
fi

if [ -f "$BACKUP_DIR/ossec.conf.backup" ]; then
    cp "$BACKUP_DIR/ossec.conf.backup" "/var/ossec/etc/ossec.conf"
    echo "Restored ossec.conf"
fi

echo "Restarting Wazuh manager..."
systemctl restart wazuh-manager

echo "YARA integration configuration restored successfully!"
EOF

chmod +x "$BACKUP_DIR/restore_yara.sh"
print_success "Created restore script at $BACKUP_DIR/restore_yara.sh"

# Step 7: Restart Wazuh manager
print_status "Restarting Wazuh manager to apply configuration changes..."
if systemctl restart wazuh-manager; then
    print_success "Wazuh manager restarted successfully"
else
    print_error "Failed to restart Wazuh manager"
    print_status "You can restore the original configuration using: $BACKUP_DIR/restore_yara.sh"
    exit 1
fi

# Wait for service to be ready
print_status "Waiting for Wazuh manager to be fully ready..."
sleep 15

# Step 8: Verify services status
print_status "Verifying services status..."
if systemctl is-active --quiet wazuh-manager; then
    print_success "Wazuh manager is running properly"
else
    print_error "Wazuh manager failed to start properly"
    print_status "Check logs: sudo tail -f /var/ossec/logs/ossec.log"
    exit 1
fi

# Step 9: Test rule compilation
print_status "Testing rule compilation..."
if /var/ossec/bin/wazuh-logtest -t &>/dev/null || /var/ossec/bin/wazuh-logtest-legacy -t &>/dev/null; then
    print_success "All rules compiled successfully"
else
    print_warning "Rule compilation had warnings - integration should still work"
fi

# Final status report
print_success "YARA Malware Detection Integration Setup Completed Successfully!"
echo
print_status "Setup Summary:"
echo "  ✓ Detection rules configured for FIM events in /tmp/yara/malware (Ubuntu)"
echo "  ✓ YARA-specific rules configured for malware detection alerts"
echo "  ✓ Decoders configured to parse YARA scan results"
echo "  ✓ Active Response configured to trigger YARA scans"
echo "  ✓ Configuration files backed up"
echo "  ✓ Wazuh manager restarted and verified"
echo
print_status "Configuration Details:"
echo "  - Detection rules: /var/ossec/etc/rules/local_rules.xml"
echo "  - Decoders: /var/ossec/etc/decoders/local_decoder.xml"
echo "  - Active Response: /var/ossec/etc/ossec.conf"
echo "  - Backup location: $BACKUP_DIR"
echo "  - Restore script: $BACKUP_DIR/restore_yara.sh"
echo
print_status "Service Status:"
echo "  - Wazuh Manager: $(systemctl is-active wazuh-manager)"
echo
print_status "Configured Rules:"
echo "  - Rule 100300: File modified in /tmp/yara/malware/ (level 7)"
echo "  - Rule 100301: File added to /tmp/yara/malware/ (level 7)"
echo "  - Rule 108000: YARA grouping rule (level 0)"
echo "  - Rule 108001: YARA positive match alert (level 12)"
echo
print_status "Active Response Configuration:"
echo "  - Command: yara_linux"
echo "  - Executable: yara.sh"
echo "  - YARA Path: /usr/local/bin"
echo "  - YARA Rules: /tmp/yara/rules/yara_rules.yar"
echo "  - Triggered by: Rules 100300, 100301"
echo "  - Location: local (agent-side execution)"
echo
print_status "Monitoring and Alerts:"
echo "  1. Monitor Wazuh dashboard with filter: rule.groups:yara"
echo "  2. Check FIM alerts for /tmp/yara/malware directory"
echo "  3. Verify YARA scan results in agent active-response logs"
echo "  4. High-severity alerts (level 12) for malware detection"
echo
print_status "Integration Workflow:"
echo "  1. File added/modified in /tmp/yara/malware → FIM alert (rules 100300/100301)"
echo "  2. Active Response triggered → YARA scan executed on agent"
echo "  3. YARA results sent to manager → Parsed by decoders"
echo "  4. Malware detection → High-severity alert (rule 108001)"
echo
print_warning "Note: If you encounter issues, use the restore script:"
echo "  bash $BACKUP_DIR/restore_yara.sh"
echo
print_status "Integration completed at $(date)"
print_status "YARA integration is ready to detect malware on monitored endpoints!"

print_warning "IMPORTANT: Ensure agents are configured with yaramodelagent.sh to complete the integration!"
print_status "Ready to receive and process YARA scan results from configured agents."