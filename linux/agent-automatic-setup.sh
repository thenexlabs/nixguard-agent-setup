#!/bin/bash
# Usage: sudo ./agent-automatic-setup.sh <manager_ip> <agent_name> <api_key>

set -e

# Check if three arguments are passed
if [ "$#" -ne 3 ]; then
    echo "Error: Invalid number of arguments." >&2
    echo "Usage: sudo $0 <manager_ip> <agent_name> <api_key>" >&2
    exit 1
fi

MANAGER_IP="$1"
AGENT_NAME="$2"
API_KEY="$3"

detect_distro_arch() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        distro=$ID
    else
        echo "Error: Cannot detect OS distribution." >&2
        exit 1
    fi

    local raw_arch
    raw_arch=$(uname -m)
    if [ "$raw_arch" = "x86_64" ]; then
        arch="amd64"
        pkg_arch="x86_64"
    elif [ "$raw_arch" = "aarch64" ] || [ "$raw_arch" = "arm64" ]; then
        arch="arm64"
        pkg_arch="aarch64"
    else
        echo "Error: Unsupported architecture: $raw_arch" >&2
        exit 1
    fi
}

install_bootstrap_dependencies() {
    echo "Installing bootstrapping dependencies (curl, jq, wget)..."
    if [ "$distro" = "debian" ] || [ "$distro" = "ubuntu" ] || [ "$distro" = "kali" ]; then
        sudo apt-get update -qq
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl jq wget auditd audispd-plugins
    elif [ "$distro" = "centos" ] || [ "$distro" = "rhel" ] || [ "$distro" = "fedora" ]; then
        sudo yum install -y -q curl jq wget audit
    fi
}

decode_jwt_payload() {
    local token="$1"
    local payload
    payload=$(echo "$token" | cut -d'.' -f2)
    
    local len=${#payload}
    local pad=$(( (4 - len % 4) % 4 ))
    if [ $pad -eq 1 ]; then payload="${payload}="
    elif [ $pad -eq 2 ]; then payload="${payload}=="
    elif [ $pad -eq 3 ]; then payload="${payload}==="
    fi
    
    echo "$payload" | tr '_-' '/+' | base64 -d 2>/dev/null || true
}

fetch_compliance_standards() {
    local key="$1"
    local api_url="https://api.thenex.world/get-user"
    local api_payload
    api_payload=$(printf '{"apiKey":"%s"}' "$key")
    
    local response
    response=$(curl -s -X POST -H "Content-Type: application/json" -d "$api_payload" "$api_url" || true)
    
    local token
    token=$(echo "$response" | jq -r '.token // empty' 2>/dev/null || true)
    
    if [ -n "$token" ]; then
        local decoded
        decoded=$(decode_jwt_payload "$token")
        echo "$decoded" | jq -r '.cybersecurityPreferences.complianceStandards[]? // empty' 2>/dev/null || true
    fi
}

uninstall_wazuh_agent() {
    echo "Checking for existing Wazuh Agent installations..."
    if systemctl list-units --full --all | grep -Fq 'wazuh-agent'; then
        echo "Stopping and removing existing wazuh-agent..."
        sudo systemctl stop wazuh-agent || true
        if [ "$distro" = "debian" ] || [ "$distro" = "ubuntu" ] || [ "$distro" = "kali" ]; then
            sudo dpkg -r wazuh-agent || true
        elif [ "$distro" = "centos" ] || [ "$distro" = "rhel" ] || [ "$distro" = "fedora" ]; then
            sudo rpm -e wazuh-agent || true
        fi
    fi
}

fix_auditd() {
    echo "Configuring auditd service..."
    sudo systemctl enable auditd || true
    sudo systemctl start auditd || true

    if sudo auditctl -l 2>/dev/null | grep -q '^-a never,task'; then
        sudo sed -i '/^-a never,task/d' /etc/audit/rules.d/audit.rules || true
        sudo systemctl restart auditd || true
    fi
}

configure_syscheck_and_enrollment() {
    local conf="/var/ossec/etc/ossec.conf"
    local backup="${conf}.bak.$(date +%s)"
    sudo cp "$conf" "$backup"
    echo "Created backup of ossec.conf at $backup"

    # 1. Update Manager IP and ensure enrollment block is present
    sudo sed -i "s|<address>MANAGER_IP</address>|<address>${MANAGER_IP}</address>|g" "$conf"

    if ! sudo grep -q "<enrollment>" "$conf"; then
        sudo sed -i "/<client>/a \\\t<enrollment>\\n\\t\\t<enabled>yes</enabled>\\n\\t\\t<manager_address>${MANAGER_IP}</manager_address>\\n\\t\\t<agent_name>${AGENT_NAME}</agent_name>\\n\\t</enrollment>" "$conf"
    fi

    # 2. Extract entire <syscheck> section and replace with an optimized, deterministic configuration
    # Strip existing syscheck block completely to prevent duplicate/conflicting directive loops
    sudo sed -i '/<syscheck>/,/<\/syscheck>/d' "$conf"

    # 3. Append the hardened, throttled <syscheck> block right before </ossec_config>
    cat << 'EOF' | sudo tee /tmp/nixguard_syscheck.xml > /dev/null
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>no</scan_on_start>
    
    <!-- THROTTLE CONFIGURATION TO PREVENT 99% CPU SPIKES -->
    <max_eps>25</max_eps>
    <process_priority>10</process_priority>
    <synchronization>
      <enabled>yes</enabled>
      <interval>10m</interval>
      <max_eps>10</max_eps>
    </synchronization>

    <!-- DIRECTORIES TO MONITOR (Targeted, non-recursive home scans) -->
    <directories check_all="yes" realtime="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes" realtime="yes">/root</directories>
    <directories check_all="yes" realtime="no">/home</directories>

    <!-- CRITICAL SYSTEM VOLATILE DIRECTORIES TO IGNORE -->
    <ignore>/proc</ignore>
    <ignore>/sys</ignore>
    <ignore>/dev</ignore>
    <ignore>/run</ignore>
    <ignore>/var/run</ignore>
    <ignore>/var/log</ignore>
    <ignore>/var/tmp</ignore>
    <ignore>/tmp</ignore>

    <!-- COMMON RECURSION LOOPS & NOISY CONTAINERS -->
    <ignore type="sregex">node_modules</ignore>
    <ignore type="sregex">\.git</ignore>
    <ignore type="sregex">^/var/lib/docker</ignore>
    <ignore type="sregex">^/var/lib/containerd</ignore>
    <ignore type="sregex">/\.cache</ignore>
    <ignore type="sregex">/\.local/share/Trash</ignore>
    <ignore>/root/.wget-hsts</ignore>

    <!-- PREVENT MEMORY CHURNING ON LARGE SYSTEM BINARIES -->
    <nodiff>/bin</nodiff>
    <nodiff>/sbin</nodiff>
    <nodiff>/usr/bin</nodiff>
    <nodiff>/usr/sbin</nodiff>
  </syscheck>
EOF

    # Insert the clean block before </ossec_config>
    sudo sed -i '/<\/ossec_config>/e cat /tmp/nixguard_syscheck.xml' "$conf"
    sudo rm -f /tmp/nixguard_syscheck.xml
    echo "Syscheck configuration completely hardened and rewritten."
}

install_wazuh_agent() {
    echo "Target Private Cloud SOC IP: $MANAGER_IP"
    echo "Agent Name: $AGENT_NAME"

    # STEP 1: DOWNLOAD AND INSTALL AGENT
    if [ "$distro" = "debian" ] || [ "$distro" = "ubuntu" ] || [ "$distro" = "kali" ]; then
        local deb_pkg="wazuh-agent_4.9.1-1_${arch}.deb"
        sudo wget -q -O "$deb_pkg" "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/${deb_pkg}"
        sudo WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" WAZUH_AGENT_GROUP="default" DEBIAN_FRONTEND=noninteractive dpkg -i "$deb_pkg"
        rm -f "$deb_pkg"
    elif [ "$distro" = "centos" ] || [ "$distro" = "rhel" ] || [ "$distro" = "fedora" ]; then
        local rpm_pkg="wazuh-agent-4.9.1-1.${pkg_arch}.rpm"
        sudo wget -q -O "$rpm_pkg" "https://packages.wazuh.com/4.x/yum/${rpm_pkg}"
        sudo WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" WAZUH_AGENT_GROUP="default" rpm -ihv "$rpm_pkg"
        rm -f "$rpm_pkg"
    fi

    fix_auditd
    configure_syscheck_and_enrollment

    # STEP 2: COMPLIANCE ENCRYPTION SCRIPT (LUKS)
    local requires_encryption=false
    local standards
    standards=$(fetch_compliance_standards "$API_KEY")
    
    for std in $standards; do
        if [[ "$std" =~ ^(soc2|nist_sp_800_53|iso27001|gdpr|hipaa|pci_dss|pipeda|cis_controls)$ ]]; then
            requires_encryption=true
            break
        fi
    done

    local conf="/var/ossec/etc/ossec.conf"
    if [ "$requires_encryption" = true ]; then
        echo "Compliance standards require endpoint encryption tracking. Installing LUKS monitor..."
        local luksScriptUrl="https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/linux/active-response/luks_check.sh"
        local luksScriptPath="/var/ossec/bin/luks_check.sh"
        
        sudo wget -q -O "$luksScriptPath" "$luksScriptUrl" || true
        if [ -f "$luksScriptPath" ]; then
            sudo chmod 750 "$luksScriptPath"
            sudo chown root:wazuh "$luksScriptPath"
            (sudo crontab -l 2>/dev/null | grep -v "luks_check.sh" || true; echo "*/10 * * * * $luksScriptPath >/dev/null 2>&1") | sudo crontab -
            
            if ! sudo grep -q "/var/log/luks_status.log" "$conf"; then
                sudo sed -i "/<\/ossec_config>/i \\\t<localfile>\\n\\t\\t<location>/var/log/luks_status.log</location>\\n\\t\\t<log_format>json</log_format>\\n\\t</localfile>" "$conf"
            fi
        fi
    fi

    # STEP 3: ACTIVE RESPONSE SANDBOX SCRIPTS
    local arDir="/var/ossec/active-response/bin"
    sudo mkdir -p "$arDir"

    local rmThreatUrl="https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/linux/active-response/remove-threat.sh"
    sudo wget -q -O "$arDir/remove-threat.sh" "$rmThreatUrl" || true
    if [ -f "$arDir/remove-threat.sh" ]; then
        sudo chmod 750 "$arDir/remove-threat.sh"
        sudo chown root:wazuh "$arDir/remove-threat.sh"
    fi

    local remUrl="https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/linux/active-response/nixguard-remediate.sh"
    sudo wget -q -O "$arDir/nixguard-remediate.sh" "$remUrl" || true
    if [ -f "$arDir/nixguard-remediate.sh" ]; then
        sudo chmod 750 "$arDir/nixguard-remediate.sh"
        sudo chown root:wazuh "$arDir/nixguard-remediate.sh"
    fi

    # STEP 4: SERVICE RESTART & HEALTH CHECK
    sudo systemctl daemon-reload
    sudo systemctl enable wazuh-agent
    sudo systemctl restart wazuh-agent

    echo "Verifying Wazuh Agent daemon status..."
    if systemctl is-active --quiet wazuh-agent; then
        echo "SUCCESS: NixGuard Wazuh Agent is running and connected to $MANAGER_IP."
    else
        echo "WARNING: wazuh-agent installed but not active. Inspect with: journalctl -u wazuh-agent -n 20" >&2
    fi
}

# Main Execution
detect_distro_arch
install_bootstrap_dependencies
uninstall_wazuh_agent
install_wazuh_agent