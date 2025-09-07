#!/bin/bash

# Wazuh Manager VirusTotal Integration Script
# Based on: https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html

set -e

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Prompt for VirusTotal API key
read -p "Enter your VirusTotal API key: " VIRUSTOTAL_API_KEY

if [ -z "$VIRUSTOTAL_API_KEY" ]; then
    echo "VirusTotal API key is required"
    exit 1
fi

echo "Configuring Wazuh Manager for VirusTotal integration..."

# Step 1: Add FIM rules to local_rules.xml
cat >> /var/ossec/etc/rules/local_rules.xml << 'EOF'
<group name="syscheck,pci_dss_11.5,nist_800_53_SI.7,">
<!-- Rules for Linux systems -->
<rule id="100200" level="7">
<if_sid>550</if_sid>
<field name="file">/root</field>
<description>File modified in /root directory.</description>
</rule>
<rule id="100201" level="7">
<if_sid>554</if_sid>
<field name="file">/root</field>
<description>File added to /root directory.</description>
</rule>
</group>

<group name="syscheck,pci_dss_11.5,nist_800_53_SI.7,">
<!-- Rules for Windows systems -->
<rule id="100210" level="7">
<if_sid>550</if_sid>
<field name="file">Downloads</field>
<description>File modified in Downloads directory.</description>
</rule>
<rule id="100211" level="7">
<if_sid>554</if_sid>
<field name="file">Downloads</field>
<description>File added to Downloads directory.</description>
</rule>
</group>
EOF

# Step 2: Add VirusTotal integration to ossec.conf
sed -i "$i\<integration>\n<name>virustotal</name>\n<api_key>$VIRUSTOTAL_API_KEY</api_key>\n<rule_id>100200,100201,100210,100211</rule_id>\n<alert_format>json</alert_format>\n</integration>" /var/ossec/etc/ossec.conf

# Step 3: Add Active Response configuration to ossec.conf
cat >> /var/ossec/etc/ossec.conf << 'EOF'
<command>
<name>remove-threat</name>
<executable>remove-threat.sh</executable>
<timeout_allowed>no</timeout_allowed>
</command>

<command>
<name>remove-threat-windows</name>
<executable>remove-threat.exe</executable>
<timeout_allowed>no</timeout_allowed>
</command>

<active-response>
<disabled>no</disabled>
<command>remove-threat</command>
<location>local</location>
<rules_id>87105</rules_id>
</active-response>
</ossec_config>
EOF

# Step 4: Add Active Response result rules to local_rules.xml
cat >> /var/ossec/etc/rules/local_rules.xml << 'EOF'
<group name="virustotal,">
<rule id="100092" level="12">
<if_sid>657</if_sid>
<match>Successfully removed threat</match>
<description>$(parameters.program) removed threat located at $(parameters.alert.data.virustotal.source.file)</description>
</rule>

<rule id="100093" level="12">
<if_sid>657</if_sid>
<match>Error removing threat</match>
<description>Error removing threat located at $(parameters.alert.data.virustotal.source.file)</description>
</rule>
</group>
EOF

# Step 5: Restart Wazuh manager
sudo systemctl restart wazuh-manager

echo "Wazuh Manager VirusTotal integration configured successfully!"