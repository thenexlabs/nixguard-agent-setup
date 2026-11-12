#!/bin/bash
# Unit-style checks for linux/active-response/nixguard-remediate.sh (IP block) and nixguard-unblock-ip.sh.
# Nothing touches the real firewall: the scripts run with a PATH that holds only fake iptables / firewall-cmd (which
# keep their rules in a temp file), jq and date, and log to a temp file through NIXGUARD_AR_LOG.
# Run: bash tests/linux-active-response.test.sh   (needs bash and jq)
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BLOCK="$ROOT/linux/active-response/nixguard-remediate.sh"
UNBLOCK="$ROOT/linux/active-response/nixguard-unblock-ip.sh"
FAILS=0
PASSES=0

for tool in jq date; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing $tool"; exit 2; }
done

bash -n "$BLOCK" && bash -n "$UNBLOCK" || { echo "FAIL: syntax"; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# A fake iptables: -C (exit 0 when the exact rule is stored), -I (store), -D (remove one copy). Every call is logged.
# NO_COMMENT=1 makes rules with "-m comment" fail, as on a kernel without the comment module.
write_fake_iptables() {
    cat > "$1/iptables" <<'EOF'
#!/bin/bash
echo "iptables $*" >> "$FAKE_STATE/calls"
op="$1"; shift
rule="$*"
touch "$FAKE_STATE/rules"
if [ "${NO_COMMENT:-0}" = "1" ] && [[ "$rule" == *"-m comment"* ]]; then exit 2; fi
case "$op" in
  -C) grep -Fxq -- "$rule" "$FAKE_STATE/rules" ;;
  -I) echo "$rule" >> "$FAKE_STATE/rules" ;;
  -D) n=$(grep -Fxn -- "$rule" "$FAKE_STATE/rules" | head -1 | cut -d: -f1)
      [ -n "$n" ] || exit 1
      sed -i "${n}d" "$FAKE_STATE/rules" ;;
  *) exit 1 ;;
esac
EOF
    chmod +x "$1/iptables"
}

# A fake firewall-cmd with permanent rich rules only (enough for the scripts' query/add/remove/reload).
write_fake_firewalld() {
    cat > "$1/firewall-cmd" <<'EOF'
#!/bin/bash
echo "firewall-cmd $*" >> "$FAKE_STATE/calls"
touch "$FAKE_STATE/rich"
for arg in "$@"; do
  case "$arg" in
    --reload) exit 0 ;;
    --query-rich-rule=*) grep -Fxq -- "${arg#--query-rich-rule=}" "$FAKE_STATE/rich"; exit $? ;;
    --add-rich-rule=*) echo "${arg#--add-rich-rule=}" >> "$FAKE_STATE/rich"; exit 0 ;;
    --remove-rich-rule=*) grep -Fxv -- "${arg#--remove-rich-rule=}" "$FAKE_STATE/rich" > "$FAKE_STATE/rich.new"; mv "$FAKE_STATE/rich.new" "$FAKE_STATE/rich"; exit 0 ;;
  esac
done
exit 0
EOF
    chmod +x "$1/firewall-cmd"
}

# A fresh sandbox: $BIN holds the fakes plus jq and date; $FAKE_STATE their rules and the call log.
new_sandbox() { # <iptables|firewalld|none>
    BIN="$WORK/bin.$RANDOM$RANDOM"; FAKE_STATE="$WORK/state.$RANDOM$RANDOM"
    mkdir -p "$BIN" "$FAKE_STATE"
    ln -s "$(command -v jq)" "$BIN/jq"; ln -s "$(command -v date)" "$BIN/date"
    # Helpers the fakes use (not the scripts under test).
    for t in grep sed head cut mv touch cat; do ln -s "$(command -v $t)" "$BIN/$t"; done
    case "$1" in
      iptables) write_fake_iptables "$BIN" ;;
      firewalld) write_fake_firewalld "$BIN" ;;
    esac
    LOG="$FAKE_STATE/active-responses.log"
    export FAKE_STATE
}

run() { # <script> <json>  -> sets STATUS
    echo "$2" | env -i PATH="$BIN" FAKE_STATE="$FAKE_STATE" NIXGUARD_AR_LOG="$LOG" NO_COMMENT="${NO_COMMENT:-0}" /bin/bash "$1"
    STATUS=$?
}

payload() { # <target> [run id]
    jq -cn --arg t "$1" --arg r "${2:-}" '{version:1,command:"add",parameters:{program:"active-response/bin/x",extra_args:(if $r == "" then [$t] else [$t,$r] end)}}'
}

# The last result line, as the Wazuh ar_log_json decoder would read it: prefix checked, then the JSON parsed.
result() { # <field>
    local line
    line=$(grep -E '^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} active-response/bin/nixguard-(remediate|unblock-ip): \{' "$LOG" | tail -1)
    [ -n "$line" ] || { echo "(none)"; return; }
    echo "${line#*: }" | jq -r ".$1"
}

check() { # <description> <expected> <actual>
    if [ "$2" = "$3" ]; then PASSES=$((PASSES + 1)); else FAILS=$((FAILS + 1)); echo "FAIL: $1: expected [$2], got [$3]"; fi
}

RUN="ngr-0123456789abcdef0123"

# --- Block ---
new_sandbox iptables
run "$BLOCK" "$(payload 203.0.113.7 $RUN)"
check "block exits 0" 0 "$STATUS"
check "block result" success "$(result nixguard.result)"
check "block reason" blocked "$(result nixguard.reason)"
check "block action" block-ip "$(result nixguard.action)"
check "block target" 203.0.113.7 "$(result nixguard.target)"
check "block echoes the run id" "$RUN" "$(result nixguard.run)"
check "block command (rule 657)" add "$(result command)"
check "tagged INPUT rule" 1 "$(grep -Fxc -- 'INPUT -s 203.0.113.7 -m comment --comment nixguard-block -j DROP' "$FAKE_STATE/rules")"
check "lab log line kept" 1 "$(grep -c 'Successfully blocked IP 203.0.113.7 via iptables (rule tagged nixguard-block).' "$LOG")"

run "$BLOCK" "$(payload 203.0.113.7 $RUN)"
check "second block is already-blocked" already-blocked "$(result nixguard.reason)"

# --- Unblock the same address ---
run "$UNBLOCK" "$(payload 203.0.113.7 $RUN)"
check "unblock exits 0" 0 "$STATUS"
check "unblock result" success "$(result nixguard.result)"
check "unblock reason" unblocked "$(result nixguard.reason)"
check "unblock action" unblock-ip "$(result nixguard.action)"
check "unblock command (rule 657)" delete "$(result command)"
check "no rule left" 0 "$(grep -c . "$FAKE_STATE/rules")"

run "$UNBLOCK" "$(payload 203.0.113.7 $RUN)"
check "unblock of an unblocked address" not-blocked "$(result nixguard.reason)"

# Duplicates (a block added twice by older scripts) are all removed; another address's rule and an untagged rule for
# another address stay.
new_sandbox iptables
printf '%s\n' 'INPUT -s 198.51.100.9 -m comment --comment nixguard-block -j DROP' 'INPUT -s 198.51.100.9 -m comment --comment nixguard-block -j DROP' \
  'FORWARD -s 198.51.100.9 -m comment --comment nixguard-block -j DROP' \
  'INPUT -s 198.51.100.10 -m comment --comment nixguard-block -j DROP' 'INPUT -s 198.51.100.11 -j DROP' > "$FAKE_STATE/rules"
run "$UNBLOCK" "$(payload 198.51.100.9 $RUN)"
check "duplicates removed" success "$(result nixguard.result)"
check "other rules kept" 2 "$(grep -c . "$FAKE_STATE/rules")"

# An untagged DROP for the address (firewall-drop, or the no-comment fallback) is not removed, and not reported done.
new_sandbox iptables
printf '%s\n' 'INPUT -s 198.51.100.12 -j DROP' > "$FAKE_STATE/rules"
run "$UNBLOCK" "$(payload 198.51.100.12)"
check "untagged rule: failure" failure "$(result nixguard.result)"
check "untagged rule: reason" untagged-rule-remains "$(result nixguard.reason)"
check "untagged rule kept" 1 "$(grep -c . "$FAKE_STATE/rules")"
check "no run id: empty run" "" "$(result nixguard.run)"

# No comment module: the block falls back to an untagged rule and says so.
new_sandbox iptables
NO_COMMENT=1 run "$BLOCK" "$(payload 203.0.113.8 $RUN)"
check "fallback block result" success "$(result nixguard.result)"
check "fallback block reason" blocked-untagged "$(result nixguard.reason)"

# firewalld only.
new_sandbox firewalld
run "$BLOCK" "$(payload 203.0.113.20 $RUN)"
check "firewalld block" blocked "$(result nixguard.reason)"
run "$UNBLOCK" "$(payload 203.0.113.20 $RUN)"
check "firewalld unblock" unblocked "$(result nixguard.reason)"
check "firewalld rule removed" 0 "$(grep -c . "$FAKE_STATE/rich")"

# No firewall at all: failure, reported.
new_sandbox none
run "$BLOCK" "$(payload 203.0.113.21 $RUN)"
check "no firewall: block exits 1" 1 "$STATUS"
check "no firewall: block failure" no-firewall "$(result nixguard.reason)"
run "$UNBLOCK" "$(payload 203.0.113.21 $RUN)"
check "no firewall: unblock failure" no-firewall "$(result nixguard.reason)"

# --- Input validation: nothing reaches the firewall, and nothing unvalidated reaches the result line ---
new_sandbox iptables
for bad in '203.0.113.7; touch /tmp/nixguard-pwned' '$(id)' '`id`' '203.0.113.256' '203.0.113' '::1' '2001:db8::1' '-F' '' '203.0.113.7 ' ' 203.0.113.7' $'203.0.113.7\nid'; do
    : > "$LOG"
    run "$UNBLOCK" "$(payload "$bad" $RUN)"
    check "unblock refuses [$bad]" 1 "$STATUS"
    check "unblock refusal reason [$bad]" invalid-target "$(result nixguard.reason)"
    check "unblock refusal leaves target empty [$bad]" "" "$(result nixguard.target)"
done
check "refused input never ran iptables" 0 "$( [ -f "$FAKE_STATE/calls" ] && grep -c . "$FAKE_STATE/calls" || echo 0)"
[ ! -e /tmp/nixguard-pwned ] && PASSES=$((PASSES + 1)) || { FAILS=$((FAILS + 1)); echo "FAIL: injection ran"; }

# A run id that is not exactly ngr-<hex> is dropped, never echoed.
for badrun in 'ngr-xyz' 'ngr-0123456789abcdef"}' '$(id)' 'ngr-0123456789ABCDEF0123'; do
    new_sandbox iptables
    run "$BLOCK" "$(payload 203.0.113.30 "$badrun")"
    check "bad run id dropped [$badrun]" "" "$(result nixguard.run)"
    check "bad run id still blocks [$badrun]" success "$(result nixguard.result)"
done

# The block script still refuses a non-IPv4 target when asked to block (the routing above it is unchanged).
new_sandbox iptables
run "$BLOCK" "$(payload '1.2.3.4;id' $RUN)"
check "block refuses injection" 1 "$STATUS"
check "block refusal: no result line" "(none)" "$(result nixguard.result)"

echo "linux active response: $PASSES passed, $FAILS failed"
[ "$FAILS" = "0" ]
