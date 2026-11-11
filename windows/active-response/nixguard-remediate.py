#!/usr/bin/env python3
import sys
import json
import os
import subprocess
import re

# Wazuh Active Response log file for Windows
LOG_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

IPV4_RE = re.compile(r"((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])")
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@+-]{0,63}")

def log_msg(msg):
    """Write logs to the standard Wazuh active response log file."""
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"nixguard-remediate: {msg}\n")
    except:
        pass

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
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule", f"name=NixGuard Block {target}", "dir=in", "action=block", f"remoteip={target}"],
                capture_output=True
            )
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