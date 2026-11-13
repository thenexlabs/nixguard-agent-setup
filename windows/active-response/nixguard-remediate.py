#!/usr/bin/env python3
import sys
import json
import os
import subprocess
import re
import time

# Wazuh Active Response log file for Windows
LOG_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

IPV4_RE = re.compile(r"((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])")
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@+-]{0,63}")
# NixGuard's id for a run (extra_args[1]), echoed in the result so the app matches the result to the run.
RUN_ID_RE = re.compile(r"ngr-[a-f0-9]{16,32}")

def log_msg(msg):
    """Write logs to the standard Wazuh active response log file."""
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"nixguard-remediate: {msg}\n")
    except:
        pass

def emit_result(target, run_id, result, reason):
    """The block result NixGuard reads back. The line has the shape Wazuh's built-in ar_log_json decoder reads
    ("<date> active-response/bin/<name>: <json>") and "command" lets the stock rule 657 raise an alert, so it reaches
    the alerts index with no change on the manager. The target is a validated IPv4 address, the run id matches
    RUN_ID_RE or is empty, and json.dumps writes the rest."""
    line = json.dumps({"version": 1, "command": "add", "parameters": {"program": "nixguard-remediate"},
                       "nixguard": {"action": "block-ip", "target": target, "run": run_id, "result": result, "reason": reason}},
                      separators=(",", ":"))
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{time.strftime('%Y/%m/%d %H:%M:%S')} active-response/bin/nixguard-remediate: {line}\n")
    except:
        pass

def firewall_rule_exists(name):
    """netsh exits 0 when a rule with this exact name exists."""
    return subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"], capture_output=True).returncode == 0

def main():
    log_msg("Started NixGuard Remediation execution.")
    try:
        # 1. Wazuh passes the Active Response payload via stdin as a JSON string
        input_data = sys.stdin.readline()
        if not input_data:
            log_msg("Error: No input received from stdin.")
            return

        log_msg(f"Raw input received: {input_data}")
        data = json.loads(input_data)
        
        # 2. Extract the target argument sent by your Node.js backend
        # The backend sends: arguments: params.target !== "" ? [params.target] : []
        # Wazuh wraps this in the 'parameters' -> 'extra_args' array
        params = data.get("parameters", {})
        extra_args = params.get("extra_args", [])
        
        if not extra_args:
            log_msg("No target arguments provided in extra_args. Exiting.")
            return

        target = extra_args[0]
        log_msg(f"Target extracted: {target}")
        run_id = extra_args[1] if len(extra_args) > 1 and isinstance(extra_args[1], str) and RUN_ID_RE.fullmatch(extra_args[1]) else ""

        # Only two kinds of target are ever acted on: an IPv4 address (blocked), or a plain package or service name.
        # A name never contains quotes, spaces or shell characters and never starts with "-".
        is_ip = isinstance(target, str) and IPV4_RE.fullmatch(target) is not None
        if not is_ip and not (isinstance(target, str) and NAME_RE.fullmatch(target)):
            log_msg("Error: Refused target (not an IPv4 address or a plain package/service name). Exiting.")
            return

        # 3. Execute remediation based on the target format

        # Check if target is an IP address (Maps to 'nixguard-block-ip')
        if is_ip:
            log_msg(f"Action: Blocking IP {target} in Windows Firewall.")
            # nixguard-unblock-ip.exe deletes the rule by this name.
            rule_name = f"NixGuard Block {target}"
            if firewall_rule_exists(rule_name):
                log_msg(f"Notice: IP {target} is already blocked by NixGuard in Windows Firewall.")
                emit_result(target, run_id, "success", "already-blocked")
                return
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in", "action=block", f"remoteip={target}"],
                capture_output=True
            )
            # Read the rule back, so "success" means the rule exists, not only that netsh returned.
            if firewall_rule_exists(rule_name):
                log_msg(f"Successfully blocked IP {target} via Windows Firewall (rule '{rule_name}').")
                emit_result(target, run_id, "success", "blocked")
            else:
                log_msg(f"Error: the Windows Firewall rule for {target} is not in place after adding it.")
                emit_result(target, run_id, "failure", "netsh-failed")
            return
        else:
            # Attempt to restart service (Maps to 'nixguard-service-toggle')
            log_msg(f"Action: Attempting to restart service '{target}'.")
            # The name reaches PowerShell through an environment variable, never inside the command text.
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Restart-Service -Name $env:NIXGUARD_TARGET -Force -ErrorAction Stop"],
                capture_output=True,
                env={**os.environ, "NIXGUARD_TARGET": target}
            )
            
            if res.returncode == 0:
                log_msg(f"Successfully restarted service: {target}")
            else:
                # If not a service, attempt to patch/upgrade package (Maps to 'nixguard-patch')
                log_msg(f"Service restart failed or not a service. Action: Attempting winget upgrade for '{target}'.")
                subprocess.run(
                    ["winget", "upgrade", target, "--silent", "--accept-package-agreements", "--accept-source-agreements"],
                    capture_output=True
                )

        log_msg("Remediation execution completed successfully.")

    except Exception as e:
        log_msg(f"Fatal error during execution: {str(e)}")

if __name__ == "__main__":
    main()