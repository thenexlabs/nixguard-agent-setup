#!/bin/bash
# Unit-style checks for mac/active-response/nixguard-remediate.sh (IP block) and nixguard-unblock-ip.sh, run on any
# machine with bash and jq. A fake pfctl keeps the loaded ruleset in a temp file and prints it back the way pf does
# ("block drop quick inet from <ip> to any"). Nothing touches a real firewall.
# Run: bash tests/mac-active-response.test.sh
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BLOCK="$ROOT/mac/active-response/nixguard-remediate.sh"
UNBLOCK="$ROOT/mac/active-response/nixguard-unblock-ip.sh"
FAILS=0
PASSES=0
bash -n "$BLOCK" && bash -n "$UNBLOCK" || { echo "FAIL: syntax"; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/bin"; FAKE_STATE="$WORK/state"; LOG="$FAKE_STATE/active-responses.log"
mkdir -p "$BIN" "$FAKE_STATE"
for t in jq date grep sed cat; do ln -s "$(command -v $t)" "$BIN/$t"; done
cat > "$BIN/pfctl" <<'EOF'
#!/bin/bash
touch "$FAKE_STATE/rules"
case "$1" in
  -e) exit 0 ;;
  -sr) cat "$FAKE_STATE/rules" ;;
  -f) sed -E 's/^block drop quick from /block drop quick inet from /' > "$FAKE_STATE/rules.new"; mv "$FAKE_STATE/rules.new" "$FAKE_STATE/rules" ;;
esac
EOF
chmod +x "$BIN/pfctl"; ln -s "$(command -v mv)" "$BIN/mv"; ln -s "$(command -v touch)" "$BIN/touch"

run() { echo "$2" | env -i PATH="$BIN" FAKE_STATE="$FAKE_STATE" NIXGUARD_AR_LOG="$LOG" /bin/bash "$1"; STATUS=$?; }
payload() { jq -cn --arg t "$1" --arg r "${2:-}" '{version:1,command:"add",parameters:{program:"x",extra_args:(if $r == "" then [$t] else [$t,$r] end)}}'; }
result() {
    local line
    line=$(grep -E '^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} active-response/bin/nixguard-(remediate|unblock-ip): \{' "$LOG" | tail -1)
    [ -n "$line" ] || { echo "(none)"; return; }
    echo "${line#*: }" | jq -r ".$1"
}
check() { if [ "$2" = "$3" ]; then PASSES=$((PASSES + 1)); else FAILS=$((FAILS + 1)); echo "FAIL: $1: expected [$2], got [$3]"; fi; }
RUN="ngr-0123456789abcdef0123"

printf '%s\n' 'pass in all' 'block drop quick inet from 203.0.113.70 to any' > "$FAKE_STATE/rules"
run "$BLOCK" "$(payload 203.0.113.7 $RUN)"
check "block" blocked "$(result nixguard.reason)"
check "block run id" "$RUN" "$(result nixguard.run)"
check "rule loaded" 1 "$(grep -cx 'block drop quick inet from 203.0.113.7 to any' "$FAKE_STATE/rules")"
run "$BLOCK" "$(payload 203.0.113.7 $RUN)"
check "already blocked, not added twice" already-blocked "$(result nixguard.reason)"
check "one copy" 1 "$(grep -cx 'block drop quick inet from 203.0.113.7 to any' "$FAKE_STATE/rules")"

run "$UNBLOCK" "$(payload 203.0.113.7 $RUN)"
check "unblock" unblocked "$(result nixguard.reason)"
check "unblock command" delete "$(result command)"
check "rule gone" 0 "$(grep -cx 'block drop quick inet from 203.0.113.7 to any' "$FAKE_STATE/rules")"
# 203.0.113.70 starts with the same digits: the anchored, escaped pattern leaves it alone.
check "similar address kept" 1 "$(grep -cx 'block drop quick inet from 203.0.113.70 to any' "$FAKE_STATE/rules")"
check "other rules kept" 1 "$(grep -cx 'pass in all' "$FAKE_STATE/rules")"
run "$UNBLOCK" "$(payload 203.0.113.7 $RUN)"
check "unblock again: not-blocked" not-blocked "$(result nixguard.reason)"

# 203x0x113x70 would match an unescaped dot; it must be refused before any pattern is built.
for bad in '203x0x113x70' '203.0.113.7; pfctl -d' '$(id)' '203.0.113.256' '' '2001:db8::1'; do
    run "$UNBLOCK" "$(payload "$bad" $RUN)"
    check "refused [$bad]" invalid-target "$(result nixguard.reason)"
done
check "refusals changed nothing" 1 "$(grep -cx 'block drop quick inet from 203.0.113.70 to any' "$FAKE_STATE/rules")"

echo "mac active response: $PASSES passed, $FAILS failed"
[ "$FAILS" = "0" ]
