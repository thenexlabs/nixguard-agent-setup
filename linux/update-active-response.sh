#!/bin/bash
# Updates only NixGuard's active-response scripts on an endpoint that already runs the NixGuard Wazuh agent.
# The setup script downloads these scripts once, at install, and re-running it reinstalls (and re-enrolls) the agent;
# this replaces just the scripts, so the agent keeps its ID and history. No agent restart is needed: Wazuh starts the
# script fresh for every active response.
# Run: curl -fsSLO https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/linux/update-active-response.sh
#      sudo bash update-active-response.sh
set -eu

AR_DIR="/var/ossec/active-response/bin"
BASE_URL="https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/linux/active-response"

if [ "$(id -u)" != "0" ]; then echo "Run as root (sudo)." >&2; exit 1; fi
if [ ! -d "$AR_DIR" ]; then echo "$AR_DIR not found: install the NixGuard agent first (agent-automatic-setup.sh)." >&2; exit 1; fi
command -v jq >/dev/null 2>&1 || echo "WARNING: jq is missing; the scripts need it (apt-get install jq / yum install jq)." >&2

for script in nixguard-remediate.sh nixguard-unblock-ip.sh; do
    tmp=$(mktemp)
    # Download to a temp file first, so a failed download never leaves a half-written script in place.
    if curl -fsSL -o "$tmp" "$BASE_URL/$script" && bash -n "$tmp"; then
        install -m 750 -o root -g wazuh "$tmp" "$AR_DIR/$script"
        echo "Updated $AR_DIR/$script"
    else
        echo "ERROR: could not download $script; the installed copy (if any) is unchanged." >&2
        rm -f "$tmp"; exit 1
    fi
    rm -f "$tmp"
done
echo "NixGuard active-response scripts are up to date."
