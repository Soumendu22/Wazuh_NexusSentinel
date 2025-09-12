#!/bin/bash

# Suricata Integration Script for Wazuh Agent
# Based on official Wazuh documentation:
# https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html

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

print_status "Starting Suricata Integration Setup..."

# Get IP address and interface from parameters (set by customwazuhagent.sh)
UBUNTU_IP="$1"
INTERFACE="$2"

if [ -z "$UBUNTU_IP" ] || [ -z "$INTERFACE" ]; then
    print_error "Usage: $0 <IP_ADDRESS> <INTERFACE>"
    print_error "Example: $0 10.0.2.15 enp0s3"
    exit 1
fi

print_status "Configuring Suricata for IP: $UBUNTU_IP, Interface: $INTERFACE"

# Step 1: Install Suricata
print_status "Installing Suricata (this may take some time)..."
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt-get update
sudo apt-get install suricata -y
print_success "Suricata installed successfully"

# Step 2: Download and extract Emerging Threats ruleset
print_status "Downloading Emerging Threats Suricata ruleset..."
cd /tmp/
curl -LO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz
sudo tar -xvzf emerging.rules.tar.gz
sudo mkdir -p /etc/suricata/rules
sudo mv rules/*.rules /etc/suricata/rules/
sudo chmod 777 /etc/suricata/rules/*.rules
print_success "Emerging Threats ruleset installed"

# Step 3: Backup original Suricata configuration
print_status "Backing up original Suricata configuration..."
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.backup
print_success "Configuration backed up to /etc/suricata/suricata.yaml.backup"

# Step 4: Configure Suricata YAML file
print_status "Configuring Suricata settings..."

# Update HOME_NET in suricata.yaml
sudo sed -i "s/HOME_NET: \".*\"/HOME_NET: \"$UBUNTU_IP\"/g" /etc/suricata/suricata.yaml

# Update EXTERNAL_NET in suricata.yaml
sudo sed -i "s/EXTERNAL_NET: \".*\"/EXTERNAL_NET: \"any\"/g" /etc/suricata/suricata.yaml

# Update default-rule-path
sudo sed -i "s|default-rule-path: .*|default-rule-path: /etc/suricata/rules|g" /etc/suricata/suricata.yaml

# Update rule-files section
sudo sed -i '/rule-files:/,/^[[:space:]]*$/c\
rule-files:\
  - "*.rules"' /etc/suricata/suricata.yaml

# Enable stats
sudo sed -i '/^stats:/,/^[[:space:]]*enabled:/ s/enabled: .*/enabled: yes/' /etc/suricata/suricata.yaml

# Update af-packet interface
sudo sed -i "/af-packet:/,/interface:/ s/interface: .*/interface: $INTERFACE/" /etc/suricata/suricata.yaml

print_success "Suricata configuration updated"

# Step 5: Restart Suricata service
print_status "Restarting Suricata service..."
sudo systemctl restart suricata
sudo systemctl enable suricata
print_success "Suricata service restarted and enabled"

# Step 6: Configure Wazuh agent to read Suricata logs
print_status "Configuring Wazuh agent to monitor Suricata logs..."

# Backup ossec.conf
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.suricata.backup

# Add Suricata log configuration to ossec.conf
sudo sed -i '/<\/ossec_config>/i\
  <localfile>\
    <log_format>json</log_format>\
    <location>/var/log/suricata/eve.json</location>\
  </localfile>' /var/ossec/etc/ossec.conf

print_success "Wazuh agent configured to monitor Suricata logs"

# Step 7: Restart Wazuh agent
print_status "Restarting Wazuh agent to apply changes..."
sudo systemctl restart wazuh-agent
print_success "Wazuh agent restarted"

# Wait for services to be ready
print_status "Waiting for services to be fully ready..."
sleep 15

# Step 8: Verify services status
print_status "Verifying services status..."

# Check Suricata status
if systemctl is-active --quiet suricata; then
    print_success "Suricata is running properly"
else
    print_error "Suricata failed to start properly"
    print_status "Check logs: sudo journalctl -u suricata -f"
fi

# Check Wazuh agent status
if systemctl is-active --quiet wazuh-agent; then
    print_success "Wazuh agent is running properly"
else
    print_error "Wazuh agent failed to start properly"
    print_status "Check logs: sudo tail -f /var/ossec/logs/ossec.log"
fi



# Final status report
print_success "Suricata Integration Setup Completed Successfully!"
echo
print_status "Setup Summary:"
echo "  ✓ Suricata installed and configured"
echo "  ✓ Emerging Threats ruleset installed"
echo "  ✓ Network interface configured: $INTERFACE"
echo "  ✓ Home network configured: $UBUNTU_IP"
echo "  ✓ Wazuh agent configured to monitor Suricata logs"
echo "  ✓ Services restarted and verified"

echo
print_status "Configuration Details:"
echo "  - Suricata config: /etc/suricata/suricata.yaml"
echo "  - Suricata backup: /etc/suricata/suricata.yaml.backup"
echo "  - Wazuh config: /var/ossec/etc/ossec.conf"
echo "  - Wazuh backup: /var/ossec/etc/ossec.conf.suricata.backup"
echo "  - Suricata logs: /var/log/suricata/"

echo
print_status "Service Status:"
echo "  - Suricata: $(systemctl is-active suricata)"
echo "  - Wazuh Agent: $(systemctl is-active wazuh-agent)"
echo
print_status "Testing the Integration:"
echo "  1. Monitor Wazuh dashboard with filter: rule.groups:suricata"
echo "  2. Generate network traffic to trigger alerts"
echo "  3. Check Suricata logs: /var/log/suricata/eve.json"
echo
print_warning "Note: If you encounter issues, restore from backups:"
echo "  - Suricata: sudo cp /etc/suricata/suricata.yaml.backup /etc/suricata/suricata.yaml"
echo "  - Wazuh: sudo cp /var/ossec/etc/ossec.conf.suricata.backup /var/ossec/etc/ossec.conf"
echo
print_status "Integration completed at $(date)"
print_status "Monitor logs and dashboard for Suricata alerts!"