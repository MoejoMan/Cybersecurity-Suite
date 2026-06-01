"""
Deployment integrations: fail2ban config, systemd service, helper script gen.

These functions write to system paths (/etc/fail2ban, /etc/systemd/system)
or generate executable scripts. They typically require root.
"""
import os
import shlex
import subprocess
import sys


def setup_fail2ban_integration(blocklist_path):
    """Auto-create fail2ban jail and filter configs for SSHvigil."""
    blocklist_path = blocklist_path or "/var/lib/sshvigil/blocklist.txt"

    jail_config = f"""[sshvigil]
enabled = true
backend = polling
logpath = {blocklist_path}
maxretry = 1
findtime = 86400
bantime = 604800
filter = sshvigil
action = iptables-multiport[name=sshvigil, port="ssh", protocol=tcp]
"""

    filter_config = """[Definition]
failregex = ^<HOST>$
ignoreregex =
"""

    try:
        with open('/etc/fail2ban/jail.d/sshvigil.conf', 'w') as f:
            f.write(jail_config)
        print("[OK] Created /etc/fail2ban/jail.d/sshvigil.conf")

        with open('/etc/fail2ban/filter.d/sshvigil.conf', 'w') as f:
            f.write(filter_config)
        print("[OK] Created /etc/fail2ban/filter.d/sshvigil.conf")

        result = subprocess.run(['systemctl', 'restart', 'fail2ban'], capture_output=True)
        if result.returncode == 0:
            print("[OK] Restarted fail2ban service")
            print("\nTo check status: sudo fail2ban-client status sshvigil")
        else:
            print(f"[WARNING] Failed to restart fail2ban: {result.stderr.decode()}")
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo to setup fail2ban integration.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to setup fail2ban: {e}")
        sys.exit(1)


def install_systemd_service(log_path, blocklist_path, threshold, whitelist_path=None):
    """Install SSHvigil as a systemd service for live monitoring."""
    app_dir = os.path.dirname(os.path.abspath(__file__))
    python_bin = sys.executable or "/usr/bin/env python3"
    blocklist_path = blocklist_path or "/var/lib/sshvigil/blocklist.txt"
    threshold = threshold or "HIGH"
    whitelist_arg = f"--whitelist {whitelist_path}" if whitelist_path else ""

    service_content = f"""[Unit]
Description=SSHvigil Live Threat Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={app_dir}
ExecStart={python_bin} {app_dir}/main.py --log-file {log_path} --live --refresh 5 --blocklist-threshold {threshold} --export-blocklist {blocklist_path} {whitelist_arg} --non-interactive
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""

    try:
        with open('/etc/systemd/system/sshvigil.service', 'w') as f:
            f.write(service_content)
        print("[OK] Created /etc/systemd/system/sshvigil.service")

        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'enable', 'sshvigil'], check=True)
        subprocess.run(['systemctl', 'start', 'sshvigil'], check=True)

        print("[OK] SSHvigil service installed and started")
        print("\nUseful commands:")
        print("  sudo systemctl status sshvigil")
        print("  sudo systemctl stop sshvigil")
        print("  sudo journalctl -u sshvigil -f")
    except PermissionError:
        print("[ERROR] Permission denied. Run with sudo to install service.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to install service: {e}")
        sys.exit(1)


def generate_fail2ban_script(script_path, log_path, blocklist_path, threshold, whitelist_path=None):
    """Generate a ready-to-run fail2ban updater script and make it executable."""
    blocklist_path = blocklist_path or "/var/lib/sshvigil/blocklist.txt"
    app_dir = os.path.dirname(os.path.abspath(__file__))
    python_bin = sys.executable or "/usr/bin/env python3"
    threshold = threshold or "HIGH"
    whitelist_path = whitelist_path or ""

    # Restrict threshold to known-safe values; never interpolate raw user
    # text into the script body unquoted.
    if threshold not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        threshold = "HIGH"

    script_dir = os.path.dirname(os.path.abspath(script_path))
    if script_dir:
        os.makedirs(script_dir, exist_ok=True)

    # Shell-quote every interpolated path so paths with spaces / quotes / $()
    # can't break out of the string or execute commands.
    q_log = shlex.quote(log_path) if log_path else "''"
    q_blocklist = shlex.quote(blocklist_path)
    q_python = shlex.quote(python_bin)
    q_whitelist = shlex.quote(whitelist_path)
    main_py = shlex.quote(os.path.join(app_dir, "main.py"))

    script_content = f"""#!/bin/bash
set -euo pipefail

LOG_FILE={q_log}
BLOCKLIST={q_blocklist}
PYTHON_BIN={q_python}
MAIN_PY={main_py}
TOP_N=5
WHITELIST={q_whitelist}

mkdir -p "$(dirname "$BLOCKLIST")"

if [ -n "$WHITELIST" ]; then
    WHITELIST_ARG=(--whitelist "$WHITELIST")
else
    WHITELIST_ARG=()
fi

"$PYTHON_BIN" "$MAIN_PY" \\
    --log-file "$LOG_FILE" \\
    --non-interactive \\
    --export-blocklist "$BLOCKLIST" \\
    --blocklist-threshold {threshold} \\
    "${{WHITELIST_ARG[@]}}"

head -n "$TOP_N" "$BLOCKLIST" | while read -r ip; do
    [ -z "$ip" ] && continue
    sudo fail2ban-client set sshd banip "$ip"
    echo "[$(date)] Banned $ip"
done
"""

    with open(script_path, 'w', newline='\n') as f:
        f.write(script_content)
    try:
        os.chmod(script_path, 0o755)
    except Exception:
        pass
    print(f"[OK] Generated fail2ban helper script: {script_path}")
    print(f"Run: sudo bash {script_path}  (or add to cron)")
