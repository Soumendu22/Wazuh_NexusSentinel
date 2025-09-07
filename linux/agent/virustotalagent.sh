#!/bin/bash

# Wazuh Agent VirusTotal Integration Script
# Based on: https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html

set -e

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

echo "Configuring Wazuh Agent for VirusTotal integration..."

# Step 1: Enable syscheck and add /root directory monitoring
sed -i 's/<disabled>yes<\/disabled>/<disabled>no<\/disabled>/g' /var/ossec/etc/ossec.conf
sed -i '/<\/syscheck>/i\    <directories realtime="yes">/root</directories>' /var/ossec/etc/ossec.conf

# Step 2: Install jq
sudo apt update
sudo apt -y install jq

# Step 3: Create the active response script
cat > /var/ossec/active-response/bin/remove-threat.sh << 'EOF'
#!/bin/bash

LOCAL=`dirname $0`;
cd $LOCAL
cd ../

PWD=`pwd`

read INPUT_JSON
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.data.virustotal.source.file)
COMMAND=$(echo $INPUT_JSON | jq -r .command)
LOG_FILE="${PWD}/../logs/active-responses.log"

#------------------------ Analyze command -------------------------#
if [ ${COMMAND} = "add" ]
then
# Send control message to execd
printf '{"version":1,"origin":{"name":"remove-threat","module":"active-response"},"command":"check_keys", "parameters":{"keys":[]}}'\n

read RESPONSE
COMMAND2=$(echo $RESPONSE | jq -r .command)
if [ ${COMMAND2} != "continue" ]
then
echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Remove threat active response aborted" >> ${LOG_FILE}
exit 0;
fi
fi

# Removing file
rm -f $FILENAME
if [ $? -eq 0 ]; then
echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Successfully removed threat" >> ${LOG_FILE}
else
echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Error removing threat" >> ${LOG_FILE}
fi

exit 0;
EOF

# Step 4: Change file ownership and permissions
sudo chmod 750 /var/ossec/active-response/bin/remove-threat.sh
sudo chown root:wazuh /var/ossec/active-response/bin/remove-threat.sh

# Step 5: Restart the Wazuh agent
sudo systemctl restart wazuh-agent

echo "Wazuh Agent VirusTotal integration configured successfully!"