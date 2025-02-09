#!/bin/bash

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

detect_distro_arch
uninstall_wazuh_agent

