#!/bin/bash
# Wazuh Active Response script: applies or undoes one NixGuard endpoint hardening fix on Linux (Debian and Ubuntu).
# NixGuard runs it as "!nixguard-harden.sh" with extra_args [apply|undo, <fix id>, <run id>].
#
# It runs only the fixes named in this file, each a fixed change for CIS benchmark checks that Wazuh's Security
# Configuration Assessment (SCA) reports as failed. Nothing from the request reaches a shell: the fix id selects a
# function here, and anything else is refused. Every fix:
#   - saves what it changes, the first time it is applied, under $STATE_DIR/<fix id>/ (file copies, modes, owners,
#     runtime values), so "undo" puts back exactly what was there before NixGuard changed it;
#   - prefers files of its own (60-nixguard-*.conf) over editing system files, and validates before it reloads anything
#     (sshd -t, visudo -c), removing its own file again if validation fails;
#   - reads the change back, so "success" means the setting is in place, not only that a command returned;
#   - writes one result line to active-responses.log (same shape as nixguard-remediate), which the NixGuard manager rules
#     (nixguard_ar_rules.xml, 100914-100917) store and the NixGuard app reads back.
# The SCA score itself changes at the agent's next SCA scan; NixGuard can restart the agent to scan right away.
#
# Tests: tests/linux-harden.test.sh runs every fix against a fake root (NIXGUARD_HARDEN_ROOT) and fake commands.

LOG_FILE="${NIXGUARD_AR_LOG:-/var/ossec/logs/active-responses.log}"
R="${NIXGUARD_HARDEN_ROOT:-}"
STATE_DIR="$R/var/ossec/nixguard-harden"
PREFIX="60-nixguard"

OP=""; FIX=""; RUN_ID=""

log_msg() { echo "$(date '+%Y/%m/%d %H:%M:%S') nixguard-harden: $1" >> "$LOG_FILE"; }

# OP, FIX and RUN_ID are validated (or empty) before this is called; the reason is a fixed word from this file.
emit_result() { # <success|failure> <reason>
    local action="harden" command="add"
    [ "$OP" = "undo" ] && { action="unharden"; command="delete"; }
    echo "$(date '+%Y/%m/%d %H:%M:%S') active-response/bin/nixguard-harden: {\"version\":1,\"command\":\"$command\",\"parameters\":{\"program\":\"nixguard-harden\"},\"nixguard\":{\"action\":\"$action\",\"target\":\"$FIX\",\"run\":\"$RUN_ID\",\"result\":\"$1\",\"reason\":\"$2\"}}" >> "$LOG_FILE"
}
finish() { # <success|failure> <reason>
    emit_result "$1" "$2"
    [ "$1" = "success" ] && exit 0 || exit 1
}

# --- Saving and restoring what a fix changes ---------------------------------------------------------------------
# A file: its bytes, mode and owner, or a note that it did not exist. Saved once; a second apply keeps the original.
save_file() { # <fix> <path>
    local dir="$STATE_DIR/$1/files" key; key=$(echo "$2" | sed 's|/|%|g')
    mkdir -p "$dir"
    [ -e "$dir/$key.saved" ] && return 0
    if [ -e "$R$2" ]; then
        cp -a "$R$2" "$dir/$key.orig"
        stat -c '%a %u %g' "$R$2" > "$dir/$key.meta"
    else
        : > "$dir/$key.absent"
    fi
    : > "$dir/$key.saved"
}
restore_files() { # <fix>
    local dir="$STATE_DIR/$1/files" saved key path
    [ -d "$dir" ] || return 0
    for saved in "$dir"/*.saved; do
        [ -e "$saved" ] || continue
        key=$(basename "$saved" .saved); path="$R$(echo "$key" | sed 's|%|/|g')"
        if [ -e "$dir/$key.absent" ]; then
            rm -rf "$path"
        elif [ -e "$dir/$key.orig" ]; then
            rm -rf "$path"; cp -a "$dir/$key.orig" "$path"
            read -r mode uid gid < "$dir/$key.meta"; chmod "$mode" "$path"; chown "$uid:$gid" "$path" 2>/dev/null
        fi
    done
}
# A runtime value (sysctl): saved once, put back on undo.
save_sysctl() { # <fix> <key>
    local dir="$STATE_DIR/$1/sysctl"; mkdir -p "$dir"
    [ -e "$dir/$2" ] || sysctl -n "$2" > "$dir/$2" 2>/dev/null || true
}
restore_sysctl() { # <fix>
    local dir="$STATE_DIR/$1/sysctl" f
    [ -d "$dir" ] || return 0
    for f in "$dir"/*; do [ -e "$f" ] && [ -s "$f" ] && sysctl -q -w "$(basename "$f")=$(cat "$f")" >/dev/null 2>&1; done
    return 0
}
forget() { rm -rf "${STATE_DIR:?}/$1"; }
applied() { [ -e "$STATE_DIR/$1/applied" ]; }
mark_applied() { mkdir -p "$STATE_DIR/$1"; : > "$STATE_DIR/$1/applied"; }

# Writes a file NixGuard owns (saved first, so undo removes it or puts back what was there).
own_file() { # <fix> <path> <mode> <content>
    save_file "$1" "$2"
    mkdir -p "$(dirname "$R$2")"
    printf '%s\n' "$4" > "$R$2"
    chmod "$3" "$R$2"; chown 0:0 "$R$2" 2>/dev/null
}
sysctl_is() { [ "$(sysctl -n "$1" 2>/dev/null)" = "$2" ]; }
service_cmd() { command -v systemctl >/dev/null 2>&1 && systemctl "$@" >/dev/null 2>&1; }

# --- Fixes -------------------------------------------------------------------------------------------------------
# Each fix_<id> takes apply|undo|check and returns 0 when done (check: when the setting is in place).

# CIS: packet redirects, ICMP redirects, source routing, martian logging (5 checks). For a host that is not a router.
NET_KEYS="net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0 net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0 net.ipv6.conf.all.accept_redirects=0 net.ipv6.conf.default.accept_redirects=0 net.ipv4.conf.all.secure_redirects=0 net.ipv4.conf.default.secure_redirects=0 net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.default.accept_source_route=0 net.ipv6.conf.all.accept_source_route=0 net.ipv6.conf.default.accept_source_route=0 net.ipv4.conf.all.log_martians=1 net.ipv4.conf.default.log_martians=1"
RP_KEYS="net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1"
sysctl_fix() { # <fix> <file> <keys> <op>
    local kv
    case "$4" in
        apply)
            for kv in $3; do save_sysctl "$1" "${kv%%=*}"; done
            own_file "$1" "$2" 644 "# NixGuard endpoint hardening ($1). Undo it from the NixGuard app.
$(for kv in $3; do echo "${kv%%=*} = ${kv#*=}"; done)"
            for kv in $3; do sysctl -q -w "$kv" >/dev/null 2>&1; done ;;
        undo) restore_files "$1"; restore_sysctl "$1" ;;
        check) for kv in $3; do sysctl_is "${kv%%=*}" "${kv#*=}" || return 1; done ;;
    esac
}
fix_net_redirects() { sysctl_fix net-redirects "/etc/sysctl.d/$PREFIX-network.conf" "$NET_KEYS" "$1"; }
fix_net_rp_filter() { sysctl_fix net-rp-filter "/etc/sysctl.d/$PREFIX-rp-filter.conf" "$RP_KEYS" "$1"; }

# CIS: core dumps restricted (sysctl and limits).
fix_core_dumps() {
    case "$1" in
        apply)
            save_sysctl core-dumps fs.suid_dumpable
            own_file core-dumps "/etc/sysctl.d/$PREFIX-coredump.conf" 644 "# NixGuard endpoint hardening (core-dumps).
fs.suid_dumpable = 0"
            own_file core-dumps "/etc/security/limits.d/$PREFIX-coredump.conf" 644 "# NixGuard endpoint hardening (core-dumps).
* hard core 0"
            sysctl -q -w fs.suid_dumpable=0 >/dev/null 2>&1 ;;
        undo) restore_files core-dumps; restore_sysctl core-dumps ;;
        check) sysctl_is fs.suid_dumpable 0 && grep -qE '^\*\s+hard\s+core\s+0' "$R/etc/security/limits.d/$PREFIX-coredump.conf" 2>/dev/null ;;
    esac
}

# CIS: dccp, tipc, rds and sctp kernel modules not available. Refused while one is loaded: something uses it.
NET_MODULES="dccp tipc rds sctp"
fix_kernel_modules() {
    local m content=""
    case "$1" in
        apply)
            for m in $NET_MODULES; do
                if command -v lsmod >/dev/null 2>&1 && lsmod | grep -qE "^$m\s"; then MODULE_IN_USE="$m"; return 2; fi
            done
            for m in $NET_MODULES; do content="$content
install $m /bin/false
blacklist $m"; done
            own_file kernel-modules "/etc/modprobe.d/$PREFIX-net-modules.conf" 644 "# NixGuard endpoint hardening (kernel-modules).$content" ;;
        undo) restore_files kernel-modules ;;
        check) for m in $NET_MODULES; do grep -qE "^install $m /bin/false" "$R/etc/modprobe.d/$PREFIX-net-modules.conf" 2>/dev/null || return 1; done ;;
    esac
}

# CIS: /etc/crontab 600 and the cron directories 700, owned by root.
CRON_PATHS="/etc/crontab:600 /etc/cron.hourly:700 /etc/cron.daily:700 /etc/cron.weekly:700 /etc/cron.monthly:700 /etc/cron.d:700"
fix_cron_permissions() {
    local entry path mode
    for entry in $CRON_PATHS; do
        path="${entry%%:*}"; mode="${entry#*:}"
        [ -e "$R$path" ] || continue
        case "$1" in
            apply) save_meta cron-permissions "$path"; chown 0:0 "$R$path" 2>/dev/null; chmod "$mode" "$R$path" ;;
            check) [ "$(stat -c '%a %u %g' "$R$path")" = "$mode 0 0" ] || return 1 ;;
        esac
    done
    [ "$1" = "undo" ] && restore_meta cron-permissions
    return 0
}

# CIS: /etc/ssh/sshd_config 600, owned by root.
fix_sshd_config_permissions() {
    local path=/etc/ssh/sshd_config
    [ -e "$R$path" ] || return 3
    case "$1" in
        apply) save_meta sshd-config-permissions "$path"; chown 0:0 "$R$path" 2>/dev/null; chmod 600 "$R$path" ;;
        undo) restore_meta sshd-config-permissions ;;
        check) [ "$(stat -c '%a %u %g' "$R$path")" = "600 0 0" ] ;;
    esac
}
# Modes and owners only (no file copy): for permission fixes on files other programs keep editing.
save_meta() { # <fix> <path>
    local dir="$STATE_DIR/$1/meta" key; key=$(echo "$2" | sed 's|/|%|g'); mkdir -p "$dir"
    [ -e "$dir/$key" ] || stat -c '%a %u %g' "$R$2" > "$dir/$key"
}
restore_meta() { # <fix>
    local dir="$STATE_DIR/$1/meta" f path mode uid gid
    [ -d "$dir" ] || return 0
    for f in "$dir"/*; do
        [ -e "$f" ] || continue
        path="$R$(basename "$f" | sed 's|%|/|g')"; [ -e "$path" ] || continue
        read -r mode uid gid < "$f"; chmod "$mode" "$path"; chown "$uid:$gid" "$path" 2>/dev/null
    done
}

# CIS: sshd MaxAuthTries, LoginGraceTime, MaxStartups, ClientAlive*. In a drop-in read before the others, validated with
# sshd -t before reload; it never changes who may log in or how.
SSHD_DROPIN="/etc/ssh/sshd_config.d/00-nixguard-hardening.conf"
fix_sshd_limits() {
    command -v sshd >/dev/null 2>&1 || return 3
    case "$1" in
        apply)
            own_file sshd-limits "$SSHD_DROPIN" 600 "# NixGuard endpoint hardening (sshd-limits). Read before the other drop-ins, so these values win.
MaxAuthTries 4
LoginGraceTime 60
MaxStartups 10:30:60
ClientAliveInterval 15
ClientAliveCountMax 3"
            if ! sshd -t >/dev/null 2>&1; then restore_files sshd-limits; return 4; fi
            service_cmd reload ssh || service_cmd reload sshd ;;
        undo) restore_files sshd-limits; sshd -t >/dev/null 2>&1 && { service_cmd reload ssh || service_cmd reload sshd; } ;;
        check)
            local t; t=$(sshd -T 2>/dev/null) || return 1
            echo "$t" | grep -qx 'maxauthtries 4' && echo "$t" | grep -qx 'logingracetime 60' && echo "$t" | grep -qx 'maxstartups 10:30:60' \
                && echo "$t" | grep -qx 'clientaliveinterval 15' && echo "$t" | grep -qx 'clientalivecountmax 3' ;;
    esac
}

# CIS: local and remote login banners without OS details.
BANNER="Authorized users only. All activity may be monitored and reported."
fix_login_banners() {
    case "$1" in
        apply) own_file login-banners /etc/issue 644 "$BANNER"; own_file login-banners /etc/issue.net 644 "$BANNER" ;;
        undo) restore_files login-banners ;;
        check) ! grep -qE '\\[vrms]|Debian|Ubuntu' "$R/etc/issue" "$R/etc/issue.net" 2>/dev/null && [ -s "$R/etc/issue" ] && [ -s "$R/etc/issue.net" ] ;;
    esac
}

# CIS: automatic error reporting (apport) off.
fix_apport_off() {
    local dir="$STATE_DIR/apport-off"
    case "$1" in
        apply)
            mkdir -p "$dir"
            [ -e "$dir/service" ] || { systemctl is-enabled apport.service 2>/dev/null || true; } > "$dir/service"
            if [ -e "$R/etc/default/apport" ]; then
                save_file apport-off /etc/default/apport
                sed -i 's/^enabled=1/enabled=0/' "$R/etc/default/apport"
            fi
            service_cmd stop apport.service; service_cmd disable apport.service; true ;;
        undo)
            restore_files apport-off
            if grep -qx enabled "$dir/service" 2>/dev/null; then service_cmd enable apport.service; service_cmd start apport.service; fi; true ;;
        check)
            ! grep -qE '^enabled=[1-9]' "$R/etc/default/apport" 2>/dev/null \
                && ! { systemctl is-enabled apport.service 2>/dev/null | grep -qx enabled; } ;;
    esac
}

# CIS: rsyslog creates log files 0640.
fix_rsyslog_file_mode() {
    case "$1" in
        apply) own_file rsyslog-file-mode "/etc/rsyslog.d/$PREFIX.conf" 644 "# NixGuard endpoint hardening (rsyslog-file-mode).
\$FileCreateMode 0640"
            service_cmd is-active rsyslog && service_cmd restart rsyslog; true ;;
        undo) restore_files rsyslog-file-mode; service_cmd is-active rsyslog && service_cmd restart rsyslog; true ;;
        check) grep -qE '^\$FileCreateMode 0640' "$R/etc/rsyslog.d/$PREFIX.conf" 2>/dev/null ;;
    esac
}

# CIS: sudo keeps its own log file. The line goes in /etc/sudoers itself: the CIS policy's rule for /etc/sudoers.d gives
# the file name as "\.*" without "r:", so SCA looks for a file literally named that and only /etc/sudoers can pass
# (lab, 2026-11-13). /etc/sudoers is saved first; if the result does not pass visudo -c it is put back unchanged.
SUDO_LINE='Defaults logfile=/var/log/sudo.log'
fix_sudo_logfile() {
    command -v visudo >/dev/null 2>&1 || return 3
    [ -e "$R/etc/sudoers" ] || return 3
    case "$1" in
        apply)
            grep -qx "$SUDO_LINE" "$R/etc/sudoers" && return 0
            save_file sudo-logfile /etc/sudoers
            printf '\n# NixGuard endpoint hardening (sudo-logfile). Undo it from the NixGuard app.\n%s\n' "$SUDO_LINE" >> "$R/etc/sudoers"
            if ! visudo -c -q >/dev/null 2>&1; then restore_files sudo-logfile; forget sudo-logfile; return 4; fi ;;
        undo) restore_files sudo-logfile ;;
        check) grep -qx "$SUDO_LINE" "$R/etc/sudoers" ;;
    esac
}

# CIS: audit rules for administration scope, sudo log, time, network environment, identity, mounts, sessions, logins,
# AppArmor policy, permission and user commands, kernel modules (14 checks). Not the noisy ones (every failed file
# access, every deletion) and never "-e 2", which would make the rules impossible to undo without a reboot.
audit_rules() {
    local uid_min; uid_min=$(awk '/^UID_MIN/ {print $2}' "$R/etc/login.defs" 2>/dev/null); [[ "$uid_min" =~ ^[0-9]+$ ]] || uid_min=1000
    local w p
    echo "# NixGuard endpoint hardening (audit-rules). Undo it from the NixGuard app."
    for p in /etc/sudoers /etc/sudoers.d; do [ -e "$R$p" ] && echo "-w $p -p wa -k scope"; done
    echo "-w /var/log/sudo.log -p wa -k sudo_log_file"
    echo "-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change"
    echo "-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change"
    echo "-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change"
    echo "-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change"
    echo "-w /etc/localtime -p wa -k time-change"
    echo "-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale"
    echo "-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale"
    for p in /etc/issue /etc/issue.net /etc/hosts /etc/networks /etc/network /etc/netplan; do [ -e "$R$p" ] && echo "-w $p -p wa -k system-locale"; done
    for p in /etc/group /etc/passwd /etc/gshadow /etc/shadow /etc/security/opasswd /etc/nsswitch.conf /etc/pam.conf /etc/pam.d; do [ -e "$R$p" ] && echo "-w $p -p wa -k identity"; done
    echo "-a always,exit -F arch=b64 -S mount -F auid>=$uid_min -F auid!=unset -k mounts"
    echo "-a always,exit -F arch=b32 -S mount -F auid>=$uid_min -F auid!=unset -k mounts"
    for p in /var/run/utmp /var/log/wtmp /var/log/btmp; do [ -e "$R$p" ] && echo "-w $p -p wa -k session"; done
    [ -e "$R/var/log/lastlog" ] && echo "-w /var/log/lastlog -p wa -k logins"
    # pam_faillock creates /var/run/faillock on the first failed login; audit can watch a path that does not exist yet.
    [ -d "$R/var/run" ] && echo "-w /var/run/faillock -p wa -k logins"
    for p in /etc/apparmor /etc/apparmor.d; do [ -e "$R$p" ] && echo "-w $p -p wa -k MAC-policy"; done
    for w in /usr/bin/chcon /usr/bin/setfacl /usr/bin/chacl; do [ -e "$R$w" ] && echo "-a always,exit -F path=$w -F perm=x -F auid>=$uid_min -F auid!=unset -k perm_chng"; done
    [ -e "$R/usr/sbin/usermod" ] && echo "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=$uid_min -F auid!=unset -k usermod"
    [ -e "$R/usr/bin/kmod" ] && echo "-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=$uid_min -F auid!=unset -k kernel_modules"
    echo "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=$uid_min -F auid!=unset -k kernel_modules"
}
fix_audit_rules() {
    local path="/etc/audit/rules.d/$PREFIX.rules"
    command -v auditctl >/dev/null 2>&1 && command -v augenrules >/dev/null 2>&1 || return 3
    case "$1" in
        apply)
            # Immutable audit rules ("-e 2") cannot be changed until a reboot.
            auditctl -s 2>/dev/null | grep -qE '^enabled 2' && return 5
            own_file audit-rules "$path" 640 "$(audit_rules)"
            augenrules --load >/dev/null 2>&1 || { restore_files audit-rules; augenrules --load >/dev/null 2>&1; return 4; } ;;
        undo) restore_files audit-rules; augenrules --load >/dev/null 2>&1; true ;;
        check) local l; l=$(auditctl -l 2>/dev/null)
            for k in scope sudo_log_file time-change system-locale identity mounts session MAC-policy perm_chng usermod kernel_modules; do
                echo "$l" | grep -q -- "-k $k\|key=$k" || return 1
            done ;;
    esac
}

# --- Main ----------------------------------------------------------------------------------------------------------
read -r INPUT_JSON
[ -n "$INPUT_JSON" ] || { log_msg "Error: No input received from stdin."; exit 1; }
log_msg "Raw input received: $INPUT_JSON"
RAW_OP=$(echo "$INPUT_JSON" | jq -r '.parameters.extra_args[0] // empty')
RAW_FIX=$(echo "$INPUT_JSON" | jq -r '.parameters.extra_args[1] // empty')
RAW_RUN=$(echo "$INPUT_JSON" | jq -r '.parameters.extra_args[2] // empty')
[[ "$RAW_RUN" =~ ^ngr-[a-f0-9]{16,32}$ ]] && RUN_ID="$RAW_RUN"
case "$RAW_OP" in apply|undo) OP="$RAW_OP" ;; *) log_msg "Error: refused operation."; finish failure invalid-operation ;; esac

FIXES="net-redirects net-rp-filter core-dumps kernel-modules cron-permissions sshd-config-permissions sshd-limits login-banners apport-off rsyslog-file-mode sudo-logfile audit-rules"
case " $FIXES " in *" $RAW_FIX "*) FIX="$RAW_FIX" ;; *) log_msg "Error: refused fix (not one NixGuard knows)."; finish failure unknown-fix ;; esac

# Debian and Ubuntu only: the fixes use their file layout and service names.
OS_IDS=$(. "$R/etc/os-release" 2>/dev/null; echo " ${ID:-} ${ID_LIKE:-} ")
case "$OS_IDS" in *" debian "*|*" ubuntu "*) ;; *) log_msg "Error: $FIX is only for Debian and Ubuntu."; finish failure unsupported-os ;; esac

FN="fix_$(echo "$FIX" | tr '-' '_')"
MODULE_IN_USE=""
if [ "$OP" = "apply" ]; then
    log_msg "Applying $FIX."
    "$FN" apply; rc=$?
    case "$rc" in
        2) log_msg "Not applied: kernel module $MODULE_IN_USE is loaded, so something uses it."; finish failure module-in-use ;;
        3) log_msg "Not applied: the program this fix configures is not installed."; finish failure not-installed ;;
        4) log_msg "Not applied: the change did not validate and was taken back."; finish failure did-not-validate ;;
        5) log_msg "Not applied: audit rules are immutable until the next reboot."; finish failure audit-immutable ;;
    esac
    mark_applied "$FIX"
    if "$FN" check; then log_msg "Applied $FIX and read it back."; finish success applied; fi
    log_msg "Applied $FIX, but the setting did not read back as expected."; finish failure not-in-effect
else
    if ! applied "$FIX" && [ ! -d "$STATE_DIR/$FIX" ]; then log_msg "Nothing to undo for $FIX."; finish success not-applied; fi
    log_msg "Undoing $FIX."
    "$FN" undo
    forget "$FIX"
    log_msg "Undid $FIX: what NixGuard changed is back as it was."; finish success restored
fi
