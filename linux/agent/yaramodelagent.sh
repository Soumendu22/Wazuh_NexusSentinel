#!/bin/bash

# YARA Malware Detection Integration Script for Wazuh Agent (Linux Endpoint)
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

# Check if Wazuh agent is installed
if ! command -v /var/ossec/bin/wazuh-control &> /dev/null; then
    print_error "Wazuh agent is not installed. Please install Wazuh agent first."
    exit 1
fi

print_status "Starting YARA Malware Detection Integration Setup for Wazuh Agent (Ubuntu)..."

# Step 1: Install dependencies and YARA
print_status "Installing dependencies and YARA for Ubuntu..."
apt update
apt install -y make gcc autoconf libtool libssl-dev pkg-config jq
print_success "Dependencies installed successfully"

# Step 2: Download, compile and install YARA
print_status "Downloading and compiling YARA v4.2.3..."
curl -LO https://github.com/VirusTotal/yara/archive/v4.2.3.tar.gz
tar -xvzf v4.2.3.tar.gz -C /usr/local/bin/ && rm -f v4.2.3.tar.gz

cd /usr/local/bin/yara-4.2.3/
./bootstrap.sh && ./configure && make && make install && make check

print_success "YARA compiled and installed successfully"

# Step 3: Test YARA installation
print_status "Testing YARA installation..."
if command -v yara &> /dev/null; then
    print_success "YARA is properly installed"
else
    print_error "YARA installation failed"
    # Try to fix library path issue
    print_status "Attempting to fix library path..."
    echo "/usr/local/lib" >> /etc/ld.so.conf
    ldconfig
    
    if command -v yara &> /dev/null; then
        print_success "YARA is now working after library path fix"
    else
        print_error "YARA installation still failing"
        exit 1
    fi
fi

# Step 4: Create YARA rules directory and download rules
print_status "Setting up YARA rules..."
mkdir -p /tmp/yara/rules

print_status "Downloading YARA detection rules from Valhalla..."
curl 'https://valhalla.nextron-systems.com/api/v1/get' \
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
    -H 'Accept-Language: en-US,en;q=0.5' \
    --compressed \
    -H 'Referer: https://valhalla.nextron-systems.com/' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' \
    --data 'demo=demo&apikey=1111111111111111111111111111111111111111111111111111111111111111&format=text' \
    -o /tmp/yara/rules/yara_rules.yar

if [ -f "/tmp/yara/rules/yara_rules.yar" ]; then
    print_success "YARA rules downloaded successfully"
else
    print_error "Failed to download YARA rules"
    exit 1
fi

# Step 5: Create YARA Active Response script
print_status "Creating YARA Active Response script..."
cat > /var/ossec/active-response/bin/yara.sh << 'EOF'
#!/bin/bash
# Wazuh - Yara active response
# Copyright (C) 2015-2022, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

#------------------------- Gather parameters -------------------------#

# Extra arguments
read INPUT_JSON
YARA_PATH=$(echo $INPUT_JSON | jq -r .parameters.extra_args[1])
YARA_RULES=$(echo $INPUT_JSON | jq -r .parameters.extra_args[3])
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.syscheck.path)

# Set LOG_FILE path
LOG_FILE="logs/active-responses.log"

size=0
actual_size=$(stat -c %s ${FILENAME})
while [ ${size} -ne ${actual_size} ]; do
    sleep 1
    size=${actual_size}
    actual_size=$(stat -c %s ${FILENAME})
done

#----------------------- Analyze parameters -----------------------#

if [[ ! $YARA_PATH ]] || [[ ! $YARA_RULES ]]
then
    echo "wazuh-yara: ERROR - Yara active response error. Yara path and rules parameters are mandatory." >> ${LOG_FILE}
    exit 1
fi

#------------------------- Main workflow --------------------------#

# Execute Yara scan on the specified filename
yara_output="$("${YARA_PATH}"/yara -w -r "$YARA_RULES" "$FILENAME")"

if [[ $yara_output != "" ]]
then
    # Iterate every detected rule and append it to the LOG_FILE
    while read -r line; do
        echo "wazuh-yara: INFO - Scan result: $line" >> ${LOG_FILE}
    done <<< "$yara_output"
fi

exit 0;
EOF

# Set proper permissions for YARA script
chown root:wazuh /var/ossec/active-response/bin/yara.sh
chmod 750 /var/ossec/active-response/bin/yara.sh
print_success "YARA Active Response script created and configured"

# Step 6: Create malware monitoring directory
print_status "Creating malware monitoring directory..."
mkdir -p /tmp/yara/malware
chmod 755 /tmp/yara/malware
print_success "Malware monitoring directory created"

# Step 7: Backup and configure Wazuh agent
print_status "Configuring Wazuh agent FIM monitoring..."

# Backup ossec.conf
cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.yara.backup

# Add YARA monitoring directory to FIM
if ! grep -q "/tmp/yara/malware" /var/ossec/etc/ossec.conf; then
    sed -i '/<\/syscheck>/i\    <directories realtime="yes">/tmp/yara/malware</directories>' /var/ossec/etc/ossec.conf
    print_success "Added /tmp/yara/malware to FIM monitoring"
else
    print_warning "YARA malware directory already being monitored"
fi

# Step 8: Restart Wazuh agent
print_status "Restarting Wazuh agent to apply configuration changes..."
systemctl restart wazuh-agent
print_success "Wazuh agent restarted"

# Wait for service to be ready
print_status "Waiting for Wazuh agent to be fully ready..."
sleep 10

# Step 9: Verify services status
print_status "Verifying services status..."
if systemctl is-active --quiet wazuh-agent; then
    print_success "Wazuh agent is running properly"
else
    print_error "Wazuh agent failed to start properly"
    print_status "Check logs: sudo tail -f /var/ossec/logs/ossec.log"
fi

# Final status report
print_success "YARA Malware Detection Integration Setup Completed Successfully!"
echo
print_status "Setup Summary:"
echo "  ✓ YARA v4.2.3 installed and configured for Ubuntu"
echo "  ✓ YARA detection rules downloaded from Valhalla"
echo "  ✓ Active Response script created and configured"
echo "  ✓ FIM monitoring configured for /tmp/yara/malware"
echo "  ✓ Wazuh agent restarted and verified"
echo
print_status "Configuration Details:"
echo "  - YARA binary: /usr/local/bin/yara"
echo "  - YARA rules: /tmp/yara/rules/yara_rules.yar"
echo "  - Active Response script: /var/ossec/active-response/bin/yara.sh"
echo "  - Monitored directory: /tmp/yara/malware (realtime FIM)"
echo "  - Wazuh config backup: /var/ossec/etc/ossec.conf.yara.backup"
echo
print_status "Service Status:"
echo "  - Wazuh Agent: $(systemctl is-active wazuh-agent)"
echo "  - YARA Version: $(yara --version 2>/dev/null || echo 'Command failed')"
echo
print_status "Testing the Integration:"
echo "  1. Add suspicious files to /tmp/yara/malware directory"
echo "  2. Monitor Wazuh dashboard with filter: rule.groups:yara"
echo "  3. Check FIM alerts for file additions in /tmp/yara/malware"
echo "  4. Verify Active Response logs: /var/ossec/logs/active-responses.log"
echo
print_status "Manual Testing Commands:"
echo "  - Test YARA scan: yara /tmp/yara/rules/yara_rules.yar <file_path>"
echo "  - Monitor agent logs: sudo tail -f /var/ossec/logs/ossec.log"
echo "  - Check Active Response: sudo tail -f /var/ossec/logs/active-responses.log"
echo
print_warning "Note: If you encounter issues, restore from backup:"
echo "  - Wazuh config: sudo cp /var/ossec/etc/ossec.conf.yara.backup /var/ossec/etc/ossec.conf"
echo
print_status "Integration completed at $(date)"
print_status "YARA is ready to detect malware in monitored directories!"

print_warning "IMPORTANT: Configure the Wazuh Manager with yaramodelmanager.sh to complete the integration!"