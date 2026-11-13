#!/bin/bash
# Checks for linux/active-response/nixguard-harden.sh. Every fix runs against a fake root (NIXGUARD_HARDEN_ROOT) with
# fake sysctl, sshd, systemctl, visudo, auditctl, augenrules and lsmod, and logs to a temp file; nothing on this machine
# changes. Runs in a user namespace (unshare -r) so the script's chown to root works on the fake files.
# The main check: apply every fix, then undo every fix, and the fake root is byte for byte (and mode for mode) what it
# was before. Run: bash tests/linux-harden.test.sh   (needs bash, jq, unshare)
set -u
if [ "${NIXGUARD_TEST_IN_NS:-}" != "1" ]; then
    command -v unshare >/dev/null 2>&1 || { echo "missing unshare"; exit 2; }
    NIXGUARD_TEST_IN_NS=1 exec unshare -r bash "$0" "$@"
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT="$ROOT/linux/active-response/nixguard-harden.sh"
FAILS=0; PASSES=0
command -v jq >/dev/null 2>&1 || { echo "missing jq"; exit 2; }
bash -n "$SCRIPT" || { echo "FAIL: syntax"; exit 1; }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
FAKE_BIN="$WORK/bin"; mkdir -p "$FAKE_BIN"
export FAKE_STATE="$WORK/state"; mkdir -p "$FAKE_STATE"

# --- Fake commands -------------------------------------------------------------------------------------------------
cat > "$FAKE_BIN/sysctl" <<'EOF'
#!/bin/bash
# Runtime values in $FAKE_STATE/sysctl/<key>; defaults are the "insecure" ones a fresh host has.
d="$FAKE_STATE/sysctl"; mkdir -p "$d"
get() { [ -e "$d/$1" ] && cat "$d/$1" && return; case "$1" in *rp_filter) echo 2 ;; *log_martians|*suid_dumpable) echo 0 ;; *redirects|*accept_source_route|*accept_ra) echo 1 ;; *) echo 1 ;; esac; }
args=(); for a in "$@"; do case "$a" in -q) ;; *) args+=("$a") ;; esac; done
case "${args[0]}" in
  -n) get "${args[1]}" ;;
  -w) kv="${args[1]}"; echo "${kv#*=}" > "$d/${kv%%=*}" ;;
  *) echo "${args[0]} = $(get "${args[0]}")" ;;
esac
EOF
cat > "$FAKE_BIN/sshd" <<'EOF'
#!/bin/bash
# -t fails when SSHD_INVALID=1. -T prints what the drop-in sets (lowercase), else stock values.
case "$1" in
  -t) [ "${SSHD_INVALID:-0}" = "1" ] && exit 255; exit 0 ;;
  -T) f="$NIXGUARD_HARDEN_ROOT/etc/ssh/sshd_config.d/00-nixguard-hardening.conf"
      if [ -e "$f" ]; then grep -v '^#' "$f" | awk 'NF{print tolower($1), $2}'
      else printf 'maxauthtries 6\nlogingracetime 120\nmaxstartups 10:30:100\nclientaliveinterval 0\nclientalivecountmax 3\n'; fi ;;
esac
EOF
cat > "$FAKE_BIN/systemctl" <<'EOF'
#!/bin/bash
echo "systemctl $*" >> "$FAKE_STATE/calls"
s="$FAKE_STATE/apport"; [ -e "$s" ] || echo enabled > "$s"
case "$1 $2" in
  "is-enabled apport.service") cat "$s" ;;
  "disable apport.service") echo disabled > "$s" ;;
  "enable apport.service") echo enabled > "$s" ;;
  "is-active rsyslog") exit 0 ;;
esac
exit 0
EOF
cat > "$FAKE_BIN/visudo" <<'EOF'
#!/bin/bash
[ "${VISUDO_INVALID:-0}" = "1" ] && exit 1; exit 0
EOF
cat > "$FAKE_BIN/augenrules" <<'EOF'
#!/bin/bash
# Loads every rules.d file into the "kernel" list.
cat "$NIXGUARD_HARDEN_ROOT"/etc/audit/rules.d/*.rules 2>/dev/null | grep -v '^#' > "$FAKE_STATE/audit.loaded"; exit 0
EOF
cat > "$FAKE_BIN/auditctl" <<'EOF'
#!/bin/bash
case "$1" in
  -s) echo "enabled ${AUDIT_ENABLED:-1}" ;;
  -l) cat "$FAKE_STATE/audit.loaded" 2>/dev/null ;;
esac
EOF
cat > "$FAKE_BIN/lsmod" <<'EOF'
#!/bin/bash
echo "Module Size Used"; [ -n "${LOADED_MODULE:-}" ] && echo "$LOADED_MODULE 16384 0"; exit 0
EOF
chmod +x "$FAKE_BIN"/*
for tool in bash jq date stat sed grep awk cp rm mkdir chmod chown cat tr basename dirname printf sort diff find xargs wc tail head ls mv touch id env; do
    ln -sf "$(command -v "$tool")" "$FAKE_BIN/$tool" 2>/dev/null
done

# --- A fake Ubuntu root ----------------------------------------------------------------------------------------------
make_root() { # <dir>
    local r="$1"
    mkdir -p "$r"/etc/{sysctl.d,security/limits.d,modprobe.d,ssh/sshd_config.d,default,rsyslog.d,sudoers.d,audit/rules.d,cron.hourly,cron.daily,cron.weekly,cron.monthly,cron.d,pam.d,apparmor,apparmor.d,netplan,network}
    mkdir -p "$r"/var/log "$r"/var/run "$r"/usr/bin "$r"/usr/sbin "$r"/var/ossec/logs
    printf 'ID=ubuntu\nID_LIKE=debian\n' > "$r/etc/os-release"
    printf 'SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n' > "$r/etc/crontab"; chmod 644 "$r/etc/crontab"
    chmod 755 "$r"/etc/cron.{hourly,daily,weekly,monthly,d}
    printf 'Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n' > "$r/etc/ssh/sshd_config"; chmod 644 "$r/etc/ssh/sshd_config"
    printf 'Ubuntu 24.04.4 LTS \\n \\l\n' > "$r/etc/issue"; printf 'Ubuntu 24.04.4 LTS\n' > "$r/etc/issue.net"
    printf '# set this to 0 to disable apport\nenabled=1\n' > "$r/etc/default/apport"
    printf 'UID_MIN\t\t\t 1000\n' > "$r/etc/login.defs"
    printf 'root ALL=(ALL:ALL) ALL\n' > "$r/etc/sudoers"; chmod 440 "$r/etc/sudoers"
    printf -- '-w /etc/existing -p wa -k existing\n' > "$r/etc/audit/rules.d/audit.rules"
    for f in etc/group etc/passwd etc/gshadow etc/shadow etc/nsswitch.conf etc/hosts etc/networks etc/localtime var/log/wtmp var/log/btmp var/run/utmp var/log/lastlog usr/bin/chcon usr/bin/setfacl usr/bin/chacl usr/sbin/usermod usr/bin/kmod; do
        : > "$r/$f"
    done
}
FIXES="net-redirects net-rp-filter core-dumps kernel-modules cron-permissions sshd-config-permissions sshd-limits login-banners apport-off rsyslog-file-mode sudo-logfile audit-rules"

FAKE_ROOT="$WORK/root"
reset_root() { rm -rf "$FAKE_ROOT" "$FAKE_STATE"; mkdir -p "$FAKE_STATE"; make_root "$FAKE_ROOT"; augenrules_init; }
augenrules_init() { NIXGUARD_HARDEN_ROOT="$FAKE_ROOT" PATH="$FAKE_BIN" "$FAKE_BIN/augenrules"; }
LOG="$WORK/ar.log"
run() { # <op> <fix> [run id]  -> the reason word of the result line
    : > "$LOG"
    printf '{"version":1,"command":"add","parameters":{"extra_args":["%s","%s","%s"],"program":"nixguard-harden"}}\n' "$1" "$2" "${3:-ngr-0123456789abcdef}" \
        | env -i PATH="$FAKE_BIN" HOME="$WORK" FAKE_STATE="$FAKE_STATE" NIXGUARD_HARDEN_ROOT="$FAKE_ROOT" NIXGUARD_AR_LOG="$LOG" \
              SSHD_INVALID="${SSHD_INVALID:-0}" VISUDO_INVALID="${VISUDO_INVALID:-0}" AUDIT_ENABLED="${AUDIT_ENABLED:-1}" LOADED_MODULE="${LOADED_MODULE:-}" \
              bash "$SCRIPT" >/dev/null 2>&1
    result_line | jq -r '.nixguard.result + " " + .nixguard.reason'
}
result_line() { grep 'active-response/bin/nixguard-harden: ' "$LOG" | tail -1 | sed 's/^.*nixguard-harden: //'; }
expect() { # <name> <expected> <actual>
    if [ "$2" = "$3" ]; then PASSES=$((PASSES + 1)); else FAILS=$((FAILS + 1)); echo "FAIL: $1: expected [$2], got [$3]"; fi
}
tree_of() { (cd "$1" && find . -path ./var/ossec -prune -o -print0 | sort -z | xargs -0 stat -c '%n %a %s' && find . -path ./var/ossec -prune -o -type f -print0 | sort -z | xargs -0 cat); }

# 1. Every fix applies, reads back, and its result line names the fix, the run and the action.
reset_root
for fix in $FIXES; do expect "apply $fix" "success applied" "$(run apply "$fix")"; done
expect "result line shape" "harden net-redirects ngr-0123456789abcdef add nixguard-harden" \
    "$(run apply net-redirects | true; result_line | jq -r '[.nixguard.action, .nixguard.target, .nixguard.run, .command, .parameters.program] | join(" ")')"
expect "sysctl applied" "0" "$(cat "$FAKE_STATE/sysctl/net.ipv4.conf.all.accept_redirects")"
expect "crontab mode" "600" "$(stat -c %a "$FAKE_ROOT/etc/crontab")"
expect "cron.d mode" "700" "$(stat -c %a "$FAKE_ROOT/etc/cron.d")"
expect "sshd_config mode" "600" "$(stat -c %a "$FAKE_ROOT/etc/ssh/sshd_config")"
expect "sshd_config untouched" "PermitRootLogin yes" "$(tail -1 "$FAKE_ROOT/etc/ssh/sshd_config")"
expect "banner" "Authorized users only. All activity may be monitored and reported." "$(cat "$FAKE_ROOT/etc/issue")"
expect "apport file" "enabled=0" "$(grep '^enabled' "$FAKE_ROOT/etc/default/apport")"
expect "apport service" "disabled" "$(cat "$FAKE_STATE/apport")"
expect "sudoers mode kept" "440" "$(stat -c %a "$FAKE_ROOT/etc/sudoers")"
expect "sudo log line in /etc/sudoers" "1" "$(grep -cx "Defaults logfile=/var/log/sudo.log" "$FAKE_ROOT/etc/sudoers")"
expect "faillock watched even before it exists" "1" "$(grep -c -- "-w /var/run/faillock -p wa -k logins" "$FAKE_ROOT/etc/audit/rules.d/60-nixguard.rules")"
expect "audit keys loaded" "12" "$(grep -oE -- '-k [A-Za-z_-]+' "$FAKE_STATE/audit.loaded" | sort -u | grep -vc existing)"
expect "audit never immutable" "0" "$(grep -c -- '^-e' "$FAKE_STATE/audit.loaded")"
expect "existing audit rules kept" "1" "$(grep -c -- '-k existing' "$FAKE_STATE/audit.loaded")"
expect "uid_min from login.defs" "1" "$(grep -c -- '-F auid>=1000' "$FAKE_ROOT/etc/audit/rules.d/60-nixguard.rules" | awk '{print ($1>0)}')"

# 2. Applying twice keeps the original saved, so undo still restores the state before the first apply.
expect "re-apply" "success applied" "$(run apply login-banners)"

# 3. Undo every fix: the fake root is back to exactly what it was.
reset_root
before=$(tree_of "$FAKE_ROOT"); sysctl_before=$(ls "$FAKE_STATE/sysctl" 2>/dev/null | wc -l)
for fix in $FIXES; do run apply "$fix" >/dev/null; done
run apply login-banners >/dev/null
for fix in $FIXES; do expect "undo $fix" "success restored" "$(run undo "$fix")"; done
expect "tree restored" "same" "$([ "$(tree_of "$FAKE_ROOT")" = "$before" ] && echo same || echo different)"
expect "sysctl restored" "1" "$(cat "$FAKE_STATE/sysctl/net.ipv4.conf.all.accept_redirects")"
expect "rp_filter restored" "2" "$(cat "$FAKE_STATE/sysctl/net.ipv4.conf.all.rp_filter")"
expect "apport service restored" "enabled" "$(cat "$FAKE_STATE/apport")"
expect "audit rules unloaded" "0" "$(grep -vc -- '-k existing' "$FAKE_STATE/audit.loaded")"
expect "undo result line" "unharden delete" "$(result_line | jq -r '.nixguard.action + " " + .command')"
expect "state forgotten" "0" "$(ls "$FAKE_ROOT/var/ossec/nixguard-harden" 2>/dev/null | wc -l)"
expect "undo when nothing applied" "success not-applied" "$(run undo core-dumps)"

# 4. Refusals: nothing is changed.
reset_root; before=$(tree_of "$FAKE_ROOT")
expect "unknown fix" "failure unknown-fix" "$(run apply 'rm -rf /')"
expect "unknown op" "failure invalid-operation" "$(run delete core-dumps)"
expect "bad run id dropped" "" "$(run apply 'x;id' 'ngr-zz' >/dev/null; result_line | jq -r .nixguard.run)"
printf 'ID=fedora\nID_LIKE="rhel centos"\n' > "$FAKE_ROOT/etc/os-release"
expect "not Debian or Ubuntu" "failure unsupported-os" "$(run apply core-dumps)"
printf 'ID=debian\n' > "$FAKE_ROOT/etc/os-release"
LOADED_MODULE=sctp; expect "module in use" "failure module-in-use" "$(run apply kernel-modules)"; LOADED_MODULE=""
SSHD_INVALID=1; expect "sshd -t fails" "failure did-not-validate" "$(run apply sshd-limits)"; SSHD_INVALID=0
expect "sshd drop-in removed" "absent" "$([ -e "$FAKE_ROOT/etc/ssh/sshd_config.d/00-nixguard-hardening.conf" ] && echo present || echo absent)"
VISUDO_INVALID=1; expect "visudo fails" "failure did-not-validate" "$(run apply sudo-logfile)"; VISUDO_INVALID=0
expect "sudoers unchanged after visudo fails" "root ALL=(ALL:ALL) ALL" "$(cat "$FAKE_ROOT/etc/sudoers")"
AUDIT_ENABLED=2; expect "audit immutable" "failure audit-immutable" "$(run apply audit-rules)"; AUDIT_ENABLED=1
printf 'ID=ubuntu\nID_LIKE=debian\n' > "$FAKE_ROOT/etc/os-release"
expect "refusals changed nothing" "same" "$([ "$(tree_of "$FAKE_ROOT")" = "$before" ] && echo same || echo different)"

echo "linux-harden: $PASSES passed, $FAILS failed"
[ "$FAILS" = "0" ]
