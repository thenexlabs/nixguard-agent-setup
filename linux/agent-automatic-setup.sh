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

# Function to fix broken dependencies and ensure auditd is installed and running
fix_dependencies() {
    echo "Starting dependency fix process..."

    # Update the package lists
    sudo DEBIAN_FRONTEND=noninteractive apt-get update
    if [ $? -ne 0 ]; then
        echo "Failed to update package lists. Please check your network connection."
        return 1
    fi

    # Attempt to fix broken dependencies
    sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -y
    if [ $? -ne 0 ]; then
        echo "Failed to fix broken dependencies. Please check the logs for more details."
        return 1
    fi

    # Install auditd and ensure it's running based on the distro
    if [ "$distro" == "debian" ] || [ "$distro" == "ubuntu" ] || [ "$distro" == "kali" ]; then
        sudo apt-get install -y auditd audispd-plugins
        if [ $? -ne 0 ]; then
            echo "Failed to install auditd on $distro. Please check the logs for more details."
            return 1
        fi
        sudo systemctl enable auditd
        sudo systemctl start auditd
        if [ $? -ne 0 ]; then
            echo "Failed to start auditd on $distro. Please check the logs for more details."
            return 1
        fi
    elif [ "$distro" == "centos" ] || [ "$distro" == "rhel" ] || [ "$distro" == "fedora" ]; then
        sudo yum install -y audit
        if [ $? -ne 0 ]; then
            echo "Failed to install auditd on $distro. Please check the logs for more details."
            return 1
        fi
        sudo systemctl enable auditd
        sudo systemctl start auditd
        if [ $? -ne 0 ]; then
            echo "Failed to start auditd on $distro. Please check the logs for more details."
            return 1
        fi
    else
        echo "Unsupported distribution: $distro"
        return 1
    fi

    # Ensure auditd is not disabled by default
    if auditctl -l | grep -q '^-a never,task'; then
        sudo sed -i '/^-a never,task/d' /etc/audit/rules.d/audit.rules
        sudo systemctl restart auditd
    fi

    echo "Dependency fix process completed successfully."
    return 0
}

remove_directories_tags() {
    local ossecConfPath=$1

    # Backup the original file
    sudo cp $ossecConfPath ${ossecConfPath}.bak

    # Remove all <directories> tags and their content
    sudo sed -i '/<directories>/,/<\/directories>/d' $ossecConfPath

    echo "All <directories> tags have been removed."
}

add_new_directories() {
    local ossecConfPath=$1
    shift
    local directories=("$@")

    # Check if the syscheck section exists
    if ! sudo grep -q "<syscheck>" $ossecConfPath; then
        # If syscheck section does not exist, create it
        sudo sed -i '/<\/ossec_config>/i \ \ <syscheck>\n\ \ </syscheck>' $ossecConfPath
    fi

    # Find the line number of the comment containing the word "Directories"
    local line_number=$(sudo grep -n "Directories" $ossecConfPath | cut -d: -f1)

    # Insert the new directories after the comment containing the word "Directories"
    for (( i=${#directories[@]}-1 ; i>=0 ; i-- )); do
        sudo sed -i "${line_number}a \ \ ${directories[$i]}" $ossecConfPath
    done

    echo "New <directories> tags have been added after the comment containing the word 'Directories'."
}

# Function to install Wazuh agent
install_wazuh_agent() {
    local WAZUH_MANAGER="$MANAGER_IP"
    local WAZUH_AGENT_NAME="$AGENT_NAME"
    local WAZUH_AGENT_GROUP="default"  # Adding the missing agent group

    echo "Private cloud SOC IP: $WAZUH_MANAGER"
    echo "Agent name: $WAZUH_AGENT_NAME"
    echo "Agent group: $WAZUH_AGENT_GROUP"

    if [ "$distro" == "debian" ] || [ "$distro" == "ubuntu" ] || [ "$distro" == "kali" ]; then
        if [ "$arch" == "amd64" ]; then
            sudo wget -O wazuh-agent_nixguard_amd64.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.1-1_amd64.deb
            sudo DEBIAN_FRONTEND=noninteractive dpkg -i ./wazuh-agent_nixguard_amd64.deb
        elif [ "$arch" == "aarch64" ]; then
            sudo wget -O wazuh-agent_nixguard_arm64.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.1-1_arm64.deb
            sudo DEBIAN_FRONTEND=noninteractive dpkg -i ./wazuh-agent_nixguard_arm64.deb
        fi

        # Fix dependencies
        fix_dependencies

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

        # Update the log_format in the ossec.conf file to json
        # sudo sed -i 's/<log_format>[^<]*<\/log_format>/<log_format>json<\/log_format>/' $ossecConfPath

        # Define the new directories to monitor with whodata enabled
        directories=(
            "<directories check_all=\"yes\" realtime=\"yes\">/root</directories>"  # Root directory
            # "<directories check_all=\"yes\" realtime=\"yes\">/etc</directories>"  # Configuration files
            # "<directories check_all=\"yes\" realtime=\"yes\">/var</directories>"  # Variable files (limited)
            # "<directories check_all=\"yes\" realtime=\"yes\">/usr</directories>"  # User programs
            "<directories check_all=\"yes\" realtime=\"yes\">/home</directories>"  # Home directories
            # "<directories check_all=\"yes\" realtime=\"yes\">/bin</directories>"  # Binaries
            "<directories check_all=\"yes\" realtime=\"yes\">${HOME}/Downloads</directories>"  # User Downloads folder
        )

        # Excluding the /tmp directory as it typically contains many transient files

        # Function to remove old directories tags
        remove_directories_tags $ossecConfPath

        # Function to add new directories tags
        add_new_directories $ossecConfPath "${directories[@]}"

        echo "Directory monitoring configuration added successfully."

        # Restart Wazuh Agent to apply the new configuration
        sudo systemctl restart wazuh-agent

        # Verify if the audit rules for monitoring the selected directories are applied
        auditctl -l | grep wazuh_fim

        echo "Wazuh agent installed and configured successfully."

        ###########################################################################################

        sudo apt update
        sudo apt -y install jq

        # Define the URL of the remove-threat.sh script
        removeThreatUrl="https://github.com/thenexlabs/nixguard-agent-setup/raw/main/linux/remove-threat.sh"

        # Define the destination directory
        destDir="~/var/ossec/active-response/bin"

        # Define the path to save the remove-threat.sh script in the destination directory
        removeThreatPath="$destDir/remove-threat.sh"

        # Download the remove-threat.sh script
        sudo wget -o $removeThreatPath $removeThreatUrl

        sudo chmod 750 ~/var/ossec/active-response/bin/remove-threat.sh
        sudo chown root:wazuh ~/var/ossec/active-response/bin/remove-threat.sh

        echo "Virus threat response configuration added successfully."

        ###########################################################################################

        echo "NixGuard agent setup successfully."
    elif [ "$distro" == "centos" ] || [ "$distro" == "rhel" ] || [ "$distro" == "fedora" ]; then
        if [ "$arch" == "amd64" ]; then
            sudo wget -O wazuh-agent_nixguard.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.1-1.x86_64.rpm
            sudo WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" rpm -ihv wazuh-agent_nixguard.x86_64.rpm
        elif [ "$arch" == "aarch64" ]; then
            sudo wget -O wazuh-agent_nixguard.aarch64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.1-1.aarch64.rpm
            sudo WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" rpm -ihv wazuh-agent_nixguard.aarch64.rpm
        fi
    else
        echo "Unsupported distribution: $distro"
        exit 1
    fi

    # Fix dependencies
    fix_dependencies

    # Start the Wazuh agent
    sudo systemctl daemon-reload
    sudo systemctl enable wazuh-agent
    sudo systemctl start wazuh-agent

    echo "NixGuard agent started successfully."
}

# Main script execution
if [ $# -lt 2 ]; then
    echo "Usage: $0 <WAZUH_MANAGER> <WAZUH_AGENT_NAME>"
    exit 1
fi

# Function calls
detect_distro_arch
uninstall_wazuh_agent
install_wazuh_agent
