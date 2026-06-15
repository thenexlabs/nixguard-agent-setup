#!/bin/bash
# Usage: sudo ./agent-automatic-setup.sh <manager_ip> <agent_name> <api_key>

# Check if three arguments are passed
if [ "$#" -ne 3 ]; then
    echo "Error: Invalid number of arguments." >&2
    echo "Usage: sudo $0 <manager_ip> <agent_name> <api_key>" >&2
    exit 1
fi

# Define variables from command-line arguments
MANAGER_IP=$1
AGENT_NAME=$2
API_KEY=$3

# Function to detect the distribution and architecture
detect_distro_arch() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        distro=$ID
    else
        echo "Cannot detect distribution."
        exit 1
    fi

    arch=$(uname -m)
    if [ "$arch" == "x86_64" ]; then
        arch="amd64"
    elif [ "$arch" == "aarch64" ]; then
        arch="aarch64"
    else
        echo "Unsupported architecture: $arch"
        exit 1
    fi
}

# Function to install initial bootstrapping dependencies (curl, jq)
install_bootstrap_dependencies() {
    echo "Installing bootstrapping dependencies (curl, jq)..."
    if [ "$distro" == "debian" ] || [ "$distro" == "ubuntu" ] || [ "$distro" == "kali" ]; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq curl jq wget
    elif [ "$distro" == "centos" ] || [ "$distro" == "rhel" ] || [ "$distro" == "fedora" ]; then
        sudo yum install -y -q curl jq wget
    fi
}

# Function to decode JWT payload in pure bash
decode_jwt_payload() {
    local token="$1"
    local payload
    payload=$(echo "$token" | cut -d'.' -f2)
    
    # Add padding if necessary
    local len=${#payload}
    local pad=$(( (4 - len % 4) % 4 ))
    if [ $pad -eq 1 ]; then payload="${payload}="
    elif [ $pad -eq 2 ]; then payload="${payload}=="
    elif [ $pad -eq 3 ]; then payload="${payload}==="
    fi
    
    # Convert base64url to standard base64 and decode
    echo "$payload" | tr '_-' '/+' | base64 -d 2>/dev/null
}

# Function to fetch compliance standards from NixGuard API
fetch_compliance_standards() {
    local api_key="$1"
    local api_url="https://api.thenex.world/get-user"
    local api_payload
    api_payload=$(printf '{"apiKey":"%s"}' "$api_key")
    
    local response
    response=$(curl -s -X POST -H "Content-Type: application/json" -d "$api_payload" "$api_url")
    
    local token
    token=$(echo "$response" | jq -r '.token' 2>/dev/null)
    
    if [ -n "$token" ] && [ "$token" != "null" ]; then
        local decoded_payload
        decoded_payload=$(decode_jwt_payload "$token")
        echo "$decoded_payload" | jq -r '.cybersecurityPreferences.complianceStandards[]' 2>/dev/null
    fi
}

# Function to uninstall Wazuh agent
uninstall_wazuh_agent() {
    echo "Checking for existing Wazuh Agent installations..."
    if systemctl list-units --full --all | grep -Fq 'wazuh-agent'; then
        echo "Stopping and removing existing wazuh-agent..."
        sudo systemctl stop wazuh-agent
        if [ "$distro" == "debian" ] || [ "$distro" == "ubuntu" ] || [ "$distro" == "kali" ]; then
            sudo dpkg -r wazuh-agent
        elif [ "$distro" == "centos" ] || [ "$distro" == "rhel" ] || [ "$distro" == "fedora" ]; then
            sudo rpm -e wazuh-agent
        fi
    else
        echo "No existing wazuh-agent installation found."
    fi
}

# Function to fix broken dependencies and ensure auditd is installed and running
fix_dependencies() {
    echo "Starting dependency fix process..."

    if [ "$distro" == "debian" ] || [ "$distro" == "ubuntu" ] || [ "$distro" == "kali" ]; then
        sudo DEBIAN_FRONTEND=noninteractive apt-get update
        sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -y
        sudo apt-get install -y auditd audispd-plugins
        if [ $? -ne 0 ]; then
            echo "Failed to install auditd on $distro."
            return 1
        fi
    elif [ "$distro" == "centos" ] || [ "$distro" == "rhel" ] || [ "$distro" == "fedora" ]; then
        sudo yum install -y audit
        if [ $? -ne 0 ]; then
            echo "Failed to install auditd on $distro."
            return 1
        fi
    fi

    sudo systemctl enable auditd
    sudo systemctl start auditd

    if auditctl -l | grep -q '^-a never,task'; then
        sudo sed -i '/^-a never,task/d' /etc/audit/rules.d/audit.rules
        sudo systemctl restart auditd
    fi

    echo "Dependency fix process completed successfully."
    return 0
}

remove_directories_tags() {
    local ossecConfPath=$1
    sudo cp $ossecConfPath ${ossecConfPath}.bak
    sudo sed -i '/<directories>/,/<\/directories>/d' $ossecConfPath
    echo "All <directories> tags have been removed."
}

add_new_directories() {
    local ossecConfPath=$1
    shift
    local directories=("$@")

    if ! sudo grep -q "<syscheck>" $ossecConfPath; then
        sudo sed -i '/<\/ossec_config>/i \ \ <syscheck>\n\ \ </syscheck>' $ossecConfPath
    fi

    local line_number
    line_number=$(sudo grep -n "Directories" $ossecConfPath | cut -d: -f1)

    for (( i=${#directories[@]}-1 ; i>=0 ; i-- )); do
        sudo sed -i "${line_number}a \ \ ${directories[$i]}" $ossecConfPath
    done
    echo "New <directories> tags have been added."
}

add_ignore_directories() {
    local ossecConfPath=$1
    shift
    local ignore_directories=("$@")

    if ! sudo grep -q "<syscheck>" $ossecConfPath; then
        sudo sed -i '/<\/ossec_config>/i \ \ <syscheck>\n\ \ </syscheck>' $ossecConfPath
    fi

    local line_number
    line_number=$(sudo grep -n "<!-- Files/directories to ignore -->" $ossecConfPath | cut -d: -f1)

    for (( i=${#ignore_directories[@]}-1 ; i>=0 ; i-- )); do
        sudo sed -i "${line_number}a \ \ ${ignore_directories[$i]}" $ossecConfPath
    done
    echo "New <ignore> tags have been added."
}

optimize_syscheck_performance() {
    local ossecConfPath=$1
    echo "Optimizing Syscheck (FIM) performance to prevent high CPU/IO usage..."
    
    # Remove any pre-existing performance tags to prevent XML parser errors from duplicates
    sudo sed -i '/<frequency>/d' $ossecConfPath
    sudo sed -i '/<max_eps>/d' $ossecConfPath
    sudo sed -i '/<process_priority>/d' $ossecConfPath
    sudo sed -i '/<sleep>/d' $ossecConfPath
    sudo sed -i '/<nodiff>/d' $ossecConfPath
    
    # Inject clean, optimized parameters right after the <syscheck> tag
    sudo sed -i '/<syscheck>/a \ \ \ \ <max_eps>50</max_eps>\n\ \ \ \ <frequency>43200</frequency>\n\ \ \ \ <process_priority>10</process_priority>\n\ \ \ \ <sleep>20</sleep>' $ossecConfPath
    
    # Add nodiff tags to prevent memory spikes on large binaries
    sudo sed -i '/<\/syscheck>/i \ \ \ \ <nodiff>/bin</nodiff>\n\ \ \ \ <nodiff>/sbin</nodiff>\n\ \ \ \ <nodiff>/usr/bin</nodiff>\n\ \ \ \ <nodiff>/usr/sbin</nodiff>' $ossecConfPath
    
    echo "Syscheck performance optimized."
}

# Function to install and configure Wazuh agent
install_wazuh_agent() {
    local WAZUH_MANAGER="$MANAGER_IP"
    local WAZUH_AGENT_NAME="$AGENT_NAME"
    local WAZUH_AGENT_GROUP="default"

    echo "Private cloud SOC IP: $WAZUH_MANAGER"
    echo "Agent name: $WAZUH_AGENT_NAME"
    echo "Agent group: $WAZUH_AGENT_GROUP"

    # ==========================================
    # STEP 1: DISTRO-SPECIFIC PACKAGE INSTALLATION
    # ==========================================
    if [ "$distro" == "debian" ] || [ "$distro" == "ubuntu" ] || [ "$distro" == "kali" ]; then
        if [ "$arch" == "amd64" ]; then
            sudo wget -O wazuh-agent_nixguard_amd64.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.1-1_amd64.deb
            sudo WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" WAZUH_AGENT_GROUP="$WAZUH_AGENT_GROUP" DEBIAN_FRONTEND=noninteractive dpkg -i ./wazuh-agent_nixguard_amd64.deb
        elif [ "$arch" == "aarch64" ]; then
            sudo wget -O wazuh-agent_nixguard_arm64.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.1-1_arm64.deb
            sudo WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" WAZUH_AGENT_GROUP="$WAZUH_AGENT_GROUP" DEBIAN_FRONTEND=noninteractive dpkg -i ./wazuh-agent_nixguard_arm64.deb
        fi
    elif [ "$distro" == "centos" ] || [ "$distro" == "rhel" ] || [ "$distro" == "fedora" ]; then
        if [ "$arch" == "amd64" ]; then
            sudo wget -O wazuh-agent_nixguard.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.1-1.x86_64.rpm
            sudo WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" WAZUH_AGENT_GROUP="$WAZUH_AGENT_GROUP" rpm -ihv wazuh-agent_nixguard.x86_64.rpm
        elif [ "$arch" == "aarch64" ]; then
            sudo wget -O wazuh-agent_nixguard.aarch64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.1-1.aarch64.rpm
            sudo WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" WAZUH_AGENT_GROUP="$WAZUH_AGENT_GROUP" rpm -ihv wazuh-agent_nixguard.aarch64.rpm
        fi
    else
        echo "Unsupported distribution: $distro"
        exit 1
    fi

    # Fix dependencies immediately after package installation
    fix_dependencies

    # ==========================================
    # STEP 2: GLOBAL AGENT CONFIGURATION
    # ==========================================
    ossecConfPath="/var/ossec/etc/ossec.conf"

    # Set the manager IP in the ossec.conf file
    sudo sed -i "s|<address>MANAGER_IP</address>|<address>${WAZUH_MANAGER}</address>|g" $ossecConfPath

    # Define the enrollment section
    ENROLLMENT_SECTION="<enrollment>\n\t<enabled>yes</enabled>\n\t<manager_address>${WAZUH_MANAGER}</manager_address>\n\t<agent_name>${WAZUH_AGENT_NAME}</agent_name>\n</enrollment>"

    # Add the enrollment section to the ossec.conf file
    sudo awk -v enrollment="$ENROLLMENT_SECTION" '
        /<client>/ { print; print enrollment; next }
        !/<enrollment>/ { print }
    ' "$ossecConfPath" > temp_ossec.conf && sudo mv temp_ossec.conf "$ossecConfPath"

    # Scheduled /home Scanning to Prevent CPU Melt
    directories=(
        "<directories check_all=\"yes\" realtime=\"yes\">/root</directories>"
        "<directories check_all=\"yes\" realtime=\"no\">/home</directories>"
    )

    # Regex-Based Ignores to Cover ALL Users in /home
    ignore_directories=(
        "<ignore type=\"sregex\">^/home/[^/]+/\.cache</ignore>"
        "<ignore type=\"sregex\">^/home/[^/]+/\.mozilla</ignore>"
        "<ignore type=\"sregex\">^/home/[^/]+/\.config</ignore>"
        "<ignore type=\"sregex\">^/home/[^/]+/\.local</ignore>"
        "<ignore type=\"sregex\">^/home/[^/]+/\.xsession-errors</ignore>"
        "<ignore>/root/.wget-hsts</ignore>"
        "<ignore>/root/.rpmdb</ignore>"
    )

    # Apply FIM directory configurations
    remove_directories_tags $ossecConfPath
    add_new_directories $ossecConfPath "${directories[@]}"
    add_ignore_directories $ossecConfPath "${ignore_directories[@]}"

    # Optimize Syscheck CPU/IO Performance
    optimize_syscheck_performance $ossecConfPath

    # ==========================================
    # STEP 3: INTELLIGENT COMPLIANCE DEPLOYMENT (LUKS)
    # ==========================================
    local requires_encryption=false
    local standards
    standards=$(fetch_compliance_standards "$API_KEY")
    
    for std in $standards; do
        if [[ "$std" =~ ^(soc2|nist_sp_800_53|iso27001|gdpr|hipaa|pci_dss|pipeda|cis_controls)$ ]]; then
            requires_encryption=true
            break
        fi
    done

    if [ "$requires_encryption" = true ]; then
        echo "Compliance standards require endpoint encryption. Configuring LUKS monitoring for Wazuh."
        
        # FIXED: Changed to direct raw.githubusercontent.com URL and added /active-response/ subfolder
        local luksScriptUrl="https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/linux/active-response/luks_check.sh"
        local luksScriptPath="/var/ossec/bin/luks_check.sh"
        
        sudo wget -O $luksScriptPath $luksScriptUrl
        sudo chmod 750 $luksScriptPath
        sudo chown root:wazuh $luksScriptPath

        # Schedule cron job to run every 5 minutes
        (sudo crontab -l 2>/dev/null | grep -v "luks_check.sh"; echo "*/5 * * * * $luksScriptPath >/dev/null 2>&1") | sudo crontab -

        # Configure ossec.conf to monitor the log file
        local logFileToMonitor="/var/log/luks_status.log"
        local localfileBlock="<localfile>\n\t<location>${logFileToMonitor}</location>\n\t<log_format>json</log_format>\n</localfile>"
        sudo sed -i "/<\/ossec_config>/i $localfileBlock" $ossecConfPath
    else
        echo "Compliance standards do not require encryption monitoring. Skipping LUKS configuration."
    fi

    # ==========================================
    # STEP 4: ACTIVE RESPONSE REMEDIATION DEPLOYMENT
    # ==========================================
    destDir="/var/ossec/active-response/bin"
    sudo mkdir -p $destDir

    # 1. Download the remove-threat.sh script
    echo "Downloading threat removal active response script..."
    # FIXED: Changed to direct raw.githubusercontent.com URL and added /active-response/ subfolder
    removeThreatUrl="https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/linux/active-response/remove-threat.sh"
    removeThreatPath="$destDir/remove-threat.sh"
    sudo wget -O $removeThreatPath $removeThreatUrl
    sudo chmod 750 $removeThreatPath
    sudo chown root:wazuh $removeThreatPath

    # 2. Download the nixguard-remediate.sh script
    echo "Downloading NixGuard remediation active response script..."
    # FIXED: Changed to direct raw.githubusercontent.com URL and added /active-response/ subfolder
    remediateUrl="https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/linux/active-response/nixguard-remediate.sh"
    remediatePath="$destDir/nixguard-remediate.sh"
    sudo wget -O $remediatePath $remediateUrl
    sudo chmod 750 $remediatePath
    sudo chown root:wazuh $remediatePath

    echo "Active Response remediation configurations added successfully."

    # ==========================================
    # STEP 5: SERVICE STARTUP & VERIFICATION
    # ==========================================
    sudo systemctl daemon-reload
    sudo systemctl enable wazuh-agent
    sudo systemctl restart wazuh-agent

    # Verify if the audit rules for monitoring the selected directories are applied
    auditctl -l | grep wazuh_fim

    echo "NixGuard agent setup and started successfully."
}

# Main script execution
detect_distro_arch
install_bootstrap_dependencies
uninstall_wazuh_agent
install_wazuh_agent