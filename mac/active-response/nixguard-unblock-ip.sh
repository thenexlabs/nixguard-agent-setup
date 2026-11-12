#!/bin/bash
# Wazuh Active Response script: removes the IP block that nixguard-remediate.sh added in macOS Packet Filter (pf).
# NixGuard runs it as "!nixguard-unblock-ip.sh" with extra_args [<IPv4 address>, <run id>]. It is a script of its own,
# so an endpoint that does not have it yet does nothing (the old remediate script would have blocked the address).
# Only the exact rule nixguard-remediate.sh adds ("block drop quick from <ip> to any") is removed.

LOG_FILE="${NIXGUARD_AR_LOG:-/Library/Ossec/logs/active-responses.log}"

log_msg() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') nixguard-unblock-ip: $1" >> "$LOG_FILE"
}

# Same line shape as nixguard-remediate.sh (Wazuh's ar_log_json decoder; stock rule 657 matches "delete").
emit_result() { # <success|failure> <reason>
    echo "$(date '+%Y/%m/%d %H:%M:%S') active-response/bin/nixguard-unblock-ip: {\"version\":1,\"command\":\"delete\",\"parameters\":{\"program\":\"nixguard-unblock-ip\"},\"nixguard\":{\"action\":\"unblock-ip\",\"target\":\"$TARGET\",\"run\":\"$RUN_ID\",\"result\":\"$1\",\"reason\":\"$2\"}}" >> "$LOG_FILE"
}

TARGET=""
RUN_ID=""

read -r INPUT_JSON
if [ -z "$INPUT_JSON" ]; then
    log_msg "Error: No input received from stdin."
    exit 1
fi
log_msg "Raw input received: $INPUT_JSON"

RAW_TARGET=$(echo "$INPUT_JSON" | jq -r '.parameters.extra_args[0] // empty')
RAW_RUN=$(echo "$INPUT_JSON" | jq -r '.parameters.extra_args[1] // empty')
if [[ "$RAW_RUN" =~ ^ngr-[a-f0-9]{16,32}$ ]]; then
    RUN_ID="$RAW_RUN"
fi

# IPv4 only: the address goes into a grep pattern and pf rule text, so nothing else may reach it.
IPV4_RE='^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$'
if ! [[ "$RAW_TARGET" =~ $IPV4_RE ]]; then
    log_msg "Error: Refused target (not an IPv4 address). Exiting."
    emit_result failure invalid-target
    exit 1
fi
TARGET="$RAW_TARGET"
log_msg "Action: Removing the NixGuard block on IP $TARGET in pf."

if ! command -v pfctl >/dev/null 2>&1; then
    log_msg "Error: pfctl not found. Cannot unblock IP."
    emit_result failure no-firewall
    exit 1
fi

# pfctl -sr prints the rule back as "block drop quick inet from <ip> to any". The dots are escaped for grep.
RULE_RE="^block drop quick (inet )?from ${TARGET//./\\.} to any\$"
if ! pfctl -sr 2>/dev/null | grep -Eq "$RULE_RE"; then
    log_msg "Notice: IP $TARGET had no NixGuard block in pf."
    emit_result success not-blocked
    exit 0
fi

# Reload the main ruleset without the block rule (the same way the block was added: pf.conf is not touched).
pfctl -sr 2>/dev/null | grep -Ev "$RULE_RE" | pfctl -f - >/dev/null 2>&1

if pfctl -sr 2>/dev/null | grep -Eq "$RULE_RE"; then
    log_msg "Error: the pf rule for $TARGET is still loaded after removing it."
    emit_result failure rule-still-present
    exit 1
fi
log_msg "Successfully unblocked IP $TARGET via pfctl."
emit_result success unblocked
exit 0
