#!/bin/bash
# Wazuh Active Response script: removes the IP block that nixguard-remediate.sh added on Linux.
# NixGuard runs it as "!nixguard-unblock-ip.sh" with extra_args [<IPv4 address>, <run id>]. It is a script of its own,
# not an action of nixguard-remediate.sh, so an endpoint that does not have it yet does nothing (the old script would
# have blocked the address instead). Only rules NixGuard tagged are removed: iptables rules with the comment
# "nixguard-block" (iptables-nft included, which is how nft-based systems run them) and the exact firewalld rich rule
# nixguard-remediate.sh adds. Plain "-s IP -j DROP" rules are left alone: Wazuh's own firewall-drop adds those.

LOG_FILE="${NIXGUARD_AR_LOG:-/var/ossec/logs/active-responses.log}"
MARK="nixguard-block"
# Enough for any number of duplicate rules a repeated block could have left, and a bound if -D ever fails silently.
MAX_RULES=50

log_msg() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') nixguard-unblock-ip: $1" >> "$LOG_FILE"
}

# Same line shape as nixguard-remediate.sh (Wazuh's ar_log_json decoder; stock rule 657 matches "delete"). TARGET is
# a validated IPv4 address or empty, RUN_ID matches ^ngr-[a-f0-9]+$ or is empty, the reason is a fixed word.
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

# IPv4 only: the address goes into iptables and firewall-cmd arguments, never through a shell.
IPV4_RE='^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$'
if ! [[ "$RAW_TARGET" =~ $IPV4_RE ]]; then
    log_msg "Error: Refused target (not an IPv4 address). Exiting."
    emit_result failure invalid-target
    exit 1
fi
TARGET="$RAW_TARGET"
log_msg "Action: Removing the NixGuard block on IP $TARGET."

# Deletes every copy of the tagged rule in one chain. Prints how many it removed.
remove_tagged() { # <chain>
    local removed=0
    while [ "$removed" -lt "$MAX_RULES" ] && iptables -C "$1" -s "$TARGET" -m comment --comment "$MARK" -j DROP >/dev/null 2>&1; do
        iptables -D "$1" -s "$TARGET" -m comment --comment "$MARK" -j DROP >/dev/null 2>&1 || break
        removed=$((removed + 1))
    done
    echo "$removed"
}

if command -v iptables >/dev/null 2>&1; then
    REMOVED_INPUT=$(remove_tagged INPUT)
    REMOVED_FORWARD=$(remove_tagged FORWARD)
    # Read back: no tagged rule may be left in either chain.
    if iptables -C INPUT -s "$TARGET" -m comment --comment "$MARK" -j DROP >/dev/null 2>&1 \
        || iptables -C FORWARD -s "$TARGET" -m comment --comment "$MARK" -j DROP >/dev/null 2>&1; then
        log_msg "Error: a NixGuard rule for $TARGET is still in iptables after removing it."
        emit_result failure rule-still-present
        exit 1
    fi
    if iptables -C INPUT -s "$TARGET" -j DROP >/dev/null 2>&1; then
        # An untagged rule: NixGuard's fallback when the comment module is missing, or Wazuh's timed firewall-drop.
        # It is not ours to remove, but the address is still blocked, so this is not reported as done.
        log_msg "Notice: an untagged DROP rule for $TARGET remains in iptables; it was not added by NixGuard's tagged block."
        emit_result failure untagged-rule-remains
        exit 1
    fi
    if [ "$REMOVED_INPUT" = "0" ] && [ "$REMOVED_FORWARD" = "0" ]; then
        log_msg "Notice: IP $TARGET had no NixGuard block in iptables."
        emit_result success not-blocked
    else
        log_msg "Successfully unblocked IP $TARGET via iptables (removed rules tagged $MARK)."
        emit_result success unblocked
    fi
elif command -v firewall-cmd >/dev/null 2>&1; then
    RICH_RULE="rule family='ipv4' source address='$TARGET' reject"
    if ! firewall-cmd --permanent --query-rich-rule="$RICH_RULE" >/dev/null 2>&1; then
        log_msg "Notice: IP $TARGET had no NixGuard block in firewalld."
        emit_result success not-blocked
    elif firewall-cmd --permanent --remove-rich-rule="$RICH_RULE" >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1 \
        && ! firewall-cmd --query-rich-rule="$RICH_RULE" >/dev/null 2>&1; then
        log_msg "Successfully unblocked IP $TARGET via firewalld."
        emit_result success unblocked
    else
        log_msg "Error: firewalld could not remove the rule for $TARGET."
        emit_result failure firewalld-failed
        exit 1
    fi
else
    log_msg "Error: Neither iptables nor firewalld found. Cannot unblock IP."
    emit_result failure no-firewall
    exit 1
fi

exit 0
