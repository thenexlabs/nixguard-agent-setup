#!/bin/bash
# ./mac_setup.sh "your_manager_ip" "your_agent_name"

# Check if two arguments are passed
if [ "$#" -ne 2 ]; then
    echo "Usage: ./mac_setup.sh <manager_ip> <agent_name>"
    exit 1
fi

# Define the manager IP and agent name from command-line arguments
MANAGER_IP=$1
AGENT_NAME=$2
GROUP_LABEL="default"

# Function to uninstall Wazuh agent on macOS
uninstall_wazuh_agent() {
    if [ -d "/Library/Ossec" ]; then
        sudo /Library/Ossec/bin/wazuh-control stop
        sudo rm -rf /Library/Ossec
    else
        echo "wazuh-agent is not installed"
    fi
}

remove_directories_tags() {
    local ossecConfPath=$1

    # Backup the original file
    sudo cp $ossecConfPath ${ossecConfPath}.bak

    # Remove all <directories> tags and their content
    sudo sed -i '' '/<directories>/,/<\/directories>/d' $ossecConfPath

    echo "All <directories> tags have been removed."
}

add_new_directories() {
    local ossecConfPath=$1
    shift
    local directories=("$@")

    # Check if the syscheck section exists
    if ! sudo grep -q "<syscheck>" $ossecConfPath; then
        # If syscheck section does not exist, create it
        sudo sed -i '' '/<\/ossec_config>/i \ \ <syscheck>\n\ \ </syscheck>' $ossecConfPath
    fi

    # Add the new directory monitoring configuration
    for directory in "${directories[@]}"; do
        sudo sed -i '' "/<syscheck>/a \ \ $directory" $ossecConfPath
    done

    echo "New <directories> tags have been added."
}

add_ignore_directories() {
    local ossecConfPath=$1
    shift
    local ignore_directories=("$@")

    # Check if the syscheck section exists
    if ! sudo grep -q "<syscheck>" $ossecConfPath; then
        # If syscheck section does not exist, create it
        sudo sed -i '' '/<\/ossec_config>/i \ \ <syscheck>\n\ \ </syscheck>' $ossecConfPath
    fi

    # Find the line number of the comment containing the words "Files/directories to ignore"
    local line_number=$(sudo grep -n "<!-- Files/directories to ignore -->" $ossecConfPath | cut -d: -f1)

    # Insert the new ignore directories after the comment
    for (( i=${#ignore_directories[@]}-1 ; i>=0 ; i-- )); do
        sudo sed -i '' "${line_number}a \ \ ${ignore_directories[$i]}" $ossecConfPath
    done

    echo "New <ignore> tags have been added after the comment 'Files/directories to ignore'."
}

# Function to configure the ossec.conf file
configure_ossec_conf() {
    local WAZUH_MANAGER="$MANAGER_IP"
    local WAZUH_AGENT_NAME="$AGENT_NAME"

    # Define the path to the OSSEC configuration file
    ossecConfPath="/Library/Ossec/etc/ossec.conf"

    # Set the manager IP in the ossec.conf file
    sudo sed -i '' "s/<address>.*<\/address>/<address>${WAZUH_MANAGER}<\/address>/g" $ossecConfPath

    # Define the enrollment section
    ENROLLMENT_SECTION="<enrollment>\n\t<enabled>yes</enabled>\n\t<manager_address>${WAZUH_MANAGER}</manager_address>\n\t<agent_name>${WAZUH_AGENT_NAME}</agent_name>\n</enrollment>"

    # Add the enrollment section to the ossec.conf file
    sudo awk -v enrollment="$ENROLLMENT_SECTION" '
        /<client>/ { print; print enrollment; next }
        !/<enrollment>/ { print }
    ' "$ossecConfPath" > temp_ossec.conf && sudo mv temp_ossec.conf "$ossecConfPath"

    # Define the new directories to monitor
    directories=(
        "<directories check_all=\"yes\" realtime=\"yes\">/root</directories>"  # Root directory
        # "<directories check_all=\"yes\" realtime=\"yes\">/etc</directories>"  # Configuration files
        # "<directories check_all=\"yes\" realtime=\"yes\">/var</directories>"  # Variable files (limited)
        # "<directories check_all=\"yes\" realtime=\"yes\">/usr</directories>"  # User programs
        "<directories check_all=\"yes\" realtime=\"yes\">/home</directories>"  # Home directories
        # "<directories check_all=\"yes\" realtime=\"yes\">/boot</directories>"  # Boot files
        # "<directories check_all=\"yes\" realtime=\"yes\">/opt</directories>"  # Optional software
        # "<directories check_all=\"yes\" realtime=\"yes\">/sbin</directories>"  # System binaries
        # "<directories check_all=\"yes\" realtime=\"yes\">/bin</directories>"  # Binaries
        # "<directories check_all=\"yes\" realtime=\"yes\">/lib</directories>"  # Libraries
        # "<directories check_all=\"yes\" realtime=\"yes\">/lib64</directories>"  # 64-bit libraries
        "<directories check_all=\"yes\" realtime=\"yes\">${HOME}/Downloads</directories>"  # User Downloads folder
    )

    # Define the new ignore directories
    ignore_directories=(
        "<ignore>${HOME}/.mozilla</ignore>"
        "<ignore>${HOME}/.cache</ignore>"
        "<ignore>${HOME}/.config</ignore>"
        "<ignore>${HOME}/.local</ignore>"
        "<ignore>${HOME}/.xsession-errors</ignore>"
        "<ignore>/root/.wget-hsts</ignore>"
        "<ignore>/root/.rpmdb</ignore>"
    )

    # Excluding the /tmp directory as it typically contains many transient files

    # Function to remove old directories tags
    remove_directories_tags $ossecConfPath

    # Function to add new directories tags
    add_new_directories $ossecConfPath "${directories[@]}"

    # Function to add ignore directories tags
    add_ignore_directories $ossecConfPath "${ignore_directories[@]}"

    echo "Directory monitoring configuration added successfully."
}

# Function to install Wazuh agent on macOS
install_wazuh_agent() {
    local WAZUH_MANAGER="$MANAGER_IP"
    local WAZUH_AGENT_NAME="$AGENT_NAME"

    echo "Private cloud SOC IP: $WAZUH_MANAGER"
    echo "Agent name: $WAZUH_AGENT_NAME"
    echo "Agent group: $GROUP_LABEL"

    arch=$(uname -m)
    if ! command -v wget &> /dev/null; then
        echo "wget could not be found, installing..."
        brew install wget
    fi

    if [ "$arch" == "x86_64" ]; then
        wget -O wazuh-agent_macos.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.9.2-1.intel64.pkg
    elif [ "$arch" == "arm64" ]; then
        wget -O wazuh-agent_macos.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.9.2-1.arm64.pkg
    else
        echo "Unsupported architecture: $arch"
        exit 1
    fi

    if [ ! -f wazuh-agent_macos.pkg ]; then
        echo "Failed to download wazuh-agent_macos.pkg"
        exit 1
    fi

    echo "WAZUH_MANAGER='${WAZUH_MANAGER}'" > /tmp/wazuh_envs
    sudo installer -pkg wazuh-agent_macos.pkg -target /

    echo "NixGuard agent installed successfully."

    # Start the Wazuh agent
    sudo /Library/Ossec/bin/wazuh-control start

    echo "NixGuard agent started successfully."
}

# Function to download and install the remove-threat.sh script
install_remove_threat_script() {
    local removeThreatUrl="https://github.com/thenexlabs/nixguard-agent-setup/raw/main/linux/remove-threat.sh"
    local destDir="/Library/Ossec/active-response/bin"
    local removeThreatPath="$destDir/remove-threat.sh"

    # Download the remove-threat.sh script
    sudo curl -O $removeThreatPath $removeThreatUrl

    sudo chmod 750 $removeThreatPath
    sudo chown root:wazuh $removeThreatPath

    echo "Virus threat response configuration added successfully."
}

# Main script execution
if [ $# -lt 2 ]; then
    echo "Usage: $0 <WAZUH_MANAGER_IP> <WAZUH_AGENT_NAME>"
    exit 1
fi

# Update Homebrew and reinstall pkg-config if needed
brew update
brew install pkg-config

# Uninstall any existing Wazuh agent
uninstall_wazuh_agent

# Install and configure the Wazuh agent
install_wazuh_agent

# Configure the ossec.conf file
configure_ossec_conf

# Download and install the remove-threat.sh script
install_remove_threat_script
