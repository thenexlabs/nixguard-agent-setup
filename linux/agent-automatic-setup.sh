#!/bin/bash
# ./scriptname.sh "your_manager_ip" "your_agent_name"


# Check if two arguments are passed
if [ "$#" -ne 2 ]; then
    echo "Usage: ./scriptname.sh <manager_ip> <agent_name>"
    exit 1
fi

# Define the manager IP agent name, group label from command-line arguments
MANAGER_IP=$1
AGENT_NAME=$2
GROUP_LABEL=$3

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

# Function to uninstall Wazuh agent
uninstall_wazuh_agent() {
    if [ "$distro" == "debian" ] || [ "$distro" == "ubuntu" ] || [ "$distro" == "kali" ]; then
        if systemctl list-units --full --all | grep -Fq 'wazuh-agent'; then
            sudo systemctl stop wazuh-agent
            sudo dpkg -r wazuh-agent
        else
            echo "wazuh-agent is not installed"
        fi
    elif [ "$distro" == "centos" ] || [ "$distro" == "rhel" ] || [ "$distro" == "fedora" ]; then
        if systemctl list-units --full --all | grep -Fq 'wazuh-agent'; then
            sudo systemctl stop wazuh-agent
            sudo rpm -e wazuh-agent
        else
            echo "wazuh-agent is not installed"
        fi
    else
        echo "Unsupported distribution: $distro"
        exit 1
    fi
}

# Function to install Wazuh agent
install_wazuh_agent() {
    local WAZUH_MANAGER="$MANAGER_IP"
    local WAZUH_AGENT_NAME="$AGENT_NAME"
    echo "private cloud soc ip: $WAZUH_MANAGER"
    echo "agent name: $WAZUH_AGENT_NAME"

    if [ "$distro" == "debian" ] || [ "$distro" == "ubuntu" ] || [ "$distro" == "kali" ]; then
        if [ "$arch" == "amd64" ]; then
            wget -O wazuh-agent_nixguard_amd64.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.1-1_amd64.deb
            sudo WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" dpkg -i ./wazuh-agent_nixguard_amd64.deb
        elif [ "$arch" == "aarch64" ]; then
            wget -O wazuh-agent_nixguard_arm64.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.1-1_arm64.deb
            sudo WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" dpkg -i ./wazuh-agent_nixguard_arm64.deb
        fi
            # Define the path to the OSSEC configuration file
            ossecConfPath="/var/ossec/etc/ossec.conf"

            # Set the manager IP in the ossec.conf file
            sudo sed -i "s/<address>.*<\/address>/<address>${WAZUH_MANAGER}<\/address>/g" $ossecConfPath

            # Define the enrollment section
            ENROLLMENT_SECTION="<enrollment>\n\t<enabled>yes</enabled>\n\t<manager_address>${WAZUH_MANAGER}</manager_address>\n\t<agent_name>${WAZUH_AGENT_NAME}</agent_name>\n</enrollment>"

            # Add the enrollment section to the ossec.conf file
            sudo awk -v enrollment="$ENROLLMENT_SECTION" '
                /<client>/ { print; print enrollment; next }
                !/<enrollment>/ { print }
            ' "$ossecConfPath" > temp_ossec.conf && sudo mv temp_ossec.conf "$ossecConfPath"

            # Define the new directories to monitor
            directories=(
                "<directories check_all=\"yes\" realtime=\"yes\">/root</directories>"
                "<directories check_all=\"yes\" realtime=\"yes\">/etc</directories>"
                "<directories check_all=\"yes\" realtime=\"yes\">/var</directories>"
                "<directories check_all=\"yes\" realtime=\"yes\">/usr</directories>"
                "<directories check_all=\"yes\" realtime=\"yes\">/home</directories>"
                "<directories check_all=\"yes\" realtime=\"yes\">/boot</directories>"
                "<directories check_all=\"yes\" realtime=\"yes\">/tmp</directories>"
                "<directories check_all=\"yes\" realtime=\"yes\">/opt</directories>"
                "<directories check_all=\"yes\" realtime=\"yes\">/sbin</directories>"
                "<directories check_all=\"yes\" realtime=\"yes\">/bin</directories>"
                "<directories check_all=\"yes\" realtime=\"yes\">/lib</directories>"
                "<directories check_all=\"yes\" realtime=\"yes\">/lib64</directories>"
            )

            # Check if the syscheck section exists
            if ! sudo grep -q "<syscheck>" $ossecConfPath; then
                # If syscheck section does not exist, create it
                sudo sed -i '/<\/ossec_config>/i \ \ <syscheck>\n\ \ </syscheck>' $ossecConfPath
            fi

            # Add the new directory monitoring configuration
            for directory in "${directories[@]}"; do
                sudo sed -i "/<syscheck>/a \ \ $directory" $ossecConfPath
            done

            echo "Directory monitoring configuration added successfully."

            ###########################################################################################

            # Set the current directory to the user's home directory
            # cd ~

            sudo apt update
            sudo apt -y install jq

            # Define the URL of the remove-threat.sh script
            removeThreatUrl="https://github.com/thenexlabs/nixguard-agent-setup/raw/main/linux/remove-threat.sh"

            # Define the destination directory
            destDir="/var/ossec/active-response/bin"

            # Define the path to save the remove-threat.sh script in the destination directory
            removeThreatPath="$destDir/remove-threat.sh"

            # Download the remove-threat.sh script
            sudo curl -o $removeThreatPath $removeThreatUrl

            sudo chmod 750 /var/ossec/active-response/bin/remove-threat.sh
            sudo chown root:wazuh /var/ossec/active-response/bin/remove-threat.sh

            # Clean up the build artifacts
            # rm -rf /tmp/remove-threat.py /tmp/dist /tmp/build /tmp/remove-threat.spec

            echo "Virus threat response configuration added successfully."

            ###########################################################################################

            echo "NixGuard agent setup successfully."
    elif [ "$distro" == "centos" ] || [ "$distro" == "rhel" ] || [ "$distro" == "fedora" ]; then
        if [ "$arch" == "amd64" ]; then
            curl -O wazuh-agent_nixguard.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.1-1.x86_64.rpm
            sudo WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" rpm -ihv wazuh-agent_nixguard.x86_64.rpm
        elif [ "$arch" == "aarch64" ]; then
            curl -O wazuh-agent_nixguard.aarch64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.1-1.aarch64.rpm
            sudo WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" rpm -ihv wazuh-agent_nixguard.aarch64.rpm
        fi
    else
        echo "Unsupported distribution: $distro"
        exit 1
    fi

    # Start the Wazuh agent
    sudo systemctl daemon-reload
    sudo systemctl enable wazuh-agent
    sudo systemctl start wazuh-agent

    echo "NixGuard agent started successfully."
}

# Main script execution
if [ $# -lt 2 ]; then
    echo "Usage: $0 <WAZUH_MANAGER_IP> <WAZUH_AGENT_NAME>"
    exit 1
fi


# function calls
detect_distro_arch

uninstall_wazuh_agent

install_wazuh_agent
