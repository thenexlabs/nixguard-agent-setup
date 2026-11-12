#!/usr/bin/env python3
# Wazuh Active Response script: removes the Windows Firewall rule that nixguard-remediate added for an IP block.
# NixGuard runs it as "!nixguard-unblock-ip.exe" with extra_args [<IPv4 address>, <run id>]. It is a program of its own,
# so an endpoint that does not have it yet does nothing (the old remediate program would have blocked the address).
# Only the rule named "NixGuard Block <ip>" is removed.
import sys
import json
import re
import subprocess
import time

# Wazuh Active Response log file for Windows
LOG_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

IPV4_RE = re.compile(r"((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])")
RUN_ID_RE = re.compile(r"ngr-[a-f0-9]{16,32}")

def log_msg(msg):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"nixguard-unblock-ip: {msg}\n")
    except:
        pass

def emit_result(target, run_id, result, reason):
    """Same line shape as nixguard-remediate (Wazuh's ar_log_json decoder; stock rule 657 matches "delete")."""
    line = json.dumps({"version": 1, "command": "delete", "parameters": {"program": "nixguard-unblock-ip"},
                       "nixguard": {"action": "unblock-ip", "target": target, "run": run_id, "result": result, "reason": reason}},
                      separators=(",", ":"))
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{time.strftime('%Y/%m/%d %H:%M:%S')} active-response/bin/nixguard-unblock-ip: {line}\n")
    except:
        pass

def firewall_rule_exists(name):
    """netsh exits 0 when a rule with this exact name exists."""
    return subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"], capture_output=True).returncode == 0

def main():
    target, run_id = "", ""
    try:
        input_data = sys.stdin.readline()
        if not input_data:
            log_msg("Error: No input received from stdin.")
            return
        log_msg(f"Raw input received: {input_data}")
        extra_args = json.loads(input_data).get("parameters", {}).get("extra_args", []) or []
        raw_run = extra_args[1] if len(extra_args) > 1 else ""
        run_id = raw_run if isinstance(raw_run, str) and RUN_ID_RE.fullmatch(raw_run) else ""
        raw_target = extra_args[0] if extra_args else ""
        # IPv4 only: the address goes into a netsh argument, so nothing else may reach it.
        if not (isinstance(raw_target, str) and IPV4_RE.fullmatch(raw_target)):
            log_msg("Error: Refused target (not an IPv4 address). Exiting.")
            emit_result("", run_id, "failure", "invalid-target")
            return
        target = raw_target
        rule_name = f"NixGuard Block {target}"
        log_msg(f"Action: Removing the NixGuard block on IP {target} (rule '{rule_name}').")

        if not firewall_rule_exists(rule_name):
            log_msg(f"Notice: IP {target} had no NixGuard block in Windows Firewall.")
            emit_result(target, run_id, "success", "not-blocked")
            return
        # "delete rule name=" removes every rule with that name, so duplicates from older scripts go too.
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"], capture_output=True)
        if firewall_rule_exists(rule_name):
            log_msg(f"Error: the Windows Firewall rule for {target} is still there after removing it.")
            emit_result(target, run_id, "failure", "rule-still-present")
            return
        log_msg(f"Successfully unblocked IP {target} via Windows Firewall.")
        emit_result(target, run_id, "success", "unblocked")
    except Exception as e:
        log_msg(f"Fatal error during execution: {str(e)}")
        emit_result(target, run_id, "failure", "error")

if __name__ == "__main__":
    main()
