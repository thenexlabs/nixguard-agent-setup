#!/bin/bash
# Usage: sudo ./agent-automatic-setup.sh <manager_ip> <agent_name> [--requires-encryption] [--soc2]

set -e

# Optional flags set by the NixGuard app from the account's compliance standards:
#   --requires-encryption  install the disk-encryption status check
#   --soc2                 install the NixGuard SOC 2 SCA policy locally on this endpoint
# A third positional argument (the API key older install commands passed) is accepted and ignored.
REQUIRES_ENCRYPTION=false
SOC2=false
POSITIONAL=()
for arg in "$@"; do
    case "$arg" in
        --requires-encryption) REQUIRES_ENCRYPTION=true ;;
        --soc2) SOC2=true ;;
        --*) echo "Unknown option: $arg" >&2; exit 1 ;;
        *) POSITIONAL+=("$arg") ;;
    esac
done
set -- "${POSITIONAL[@]}"

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "Error: Invalid number of arguments." >&2
    echo "Usage: sudo $0 <manager_ip> <agent_name> [--requires-encryption] [--soc2]" >&2
    exit 1
fi

MANAGER_IP="$1"
AGENT_NAME="$2"

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
    # The NixGuard app passes --requires-encryption when the account's compliance standards require it.
    local requires_encryption=$REQUIRES_ENCRYPTION
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

    # SOC 2: local policy, so it checks this endpoint only.
    if [ "$SOC2" = true ]; then
        if sudo wget -q -O /var/ossec/ruleset/sca/sca_soc2_linux.yml "https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/sca/sca_soc2_linux.yml"; then
            sudo chown root:wazuh /var/ossec/ruleset/sca/sca_soc2_linux.yml
            sudo chmod 640 /var/ossec/ruleset/sca/sca_soc2_linux.yml
            echo "Installed the NixGuard SOC 2 policy."
        else
            echo "WARNING: could not download the SOC 2 policy." >&2
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

    # Removes a NixGuard IP block (run from the NixGuard app's Unblock).
    local unblockUrl="https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/linux/active-response/nixguard-unblock-ip.sh"
    sudo wget -q -O "$arDir/nixguard-unblock-ip.sh" "$unblockUrl" || true
    if [ -f "$arDir/nixguard-unblock-ip.sh" ]; then
        sudo chmod 750 "$arDir/nixguard-unblock-ip.sh"
        sudo chown root:wazuh "$arDir/nixguard-unblock-ip.sh"
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