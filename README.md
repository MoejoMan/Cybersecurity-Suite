<!-- SSHVIGIL ASCII Banner -->
<pre>
.oPYo. .oPYo.  o    o o     o  o         o 8 
8      8       8    8 8     8              8 
`Yooo. `Yooo. o8oooo8 8     8 o8 .oPYo. o8 8 
    `8     `8  8    8 `b   d'  8 8    8  8 8 
     8      8  8    8  `b d'   8 8    8  8 8 
`YooP' `YooP'  8    8   `8'    8 `YooP8  8 8 
:.....::.....::..:::..:::..::::..:....8 :....
:::::::::::::::::::::::::::::::::::ooP'.:::::
:::::::::::::::::::::::::::::::::::...:::::::
</pre>

---

# SSHVigil SSH Brute-Force Analyzer

**Purpose:** SSHVigil is a lightweight, focused SSH brute-force detection and analysis tool. It is designed for users who want a simple, production-ready solution for SSH security monitoring—without the complexity or overhead of full-stack monitoring systems like Kibana or Grafana.

**How it fits:** SSHVigil is not a replacement for established tools like fail2ban or enterprise monitoring stacks. Instead, it enhances your existing setup by providing:
- Out-of-the-box SSH brute-force detection and clear, actionable summaries
- Easy integration with fail2ban (to improve its blocklists and detection, not to replace it)
- A portable, dependency-free Python solution for environments where heavier tools are impractical

**Upcoming:** Integration with other popular monitoring and alerting systems is planned for future releases.

> **Version:** `1.1` &nbsp;|&nbsp; **Release Date:** February 10, 2026

---

## Overview
SSHVigil is a robust SSH brute-force detection and analysis tool designed for reliability, security, and production use. It parses SSH logs, detects brute-force attempts, and exports blocklists for fail2ban/systemd integration. The fail2ban integration is meant to enhance fail2ban's detection/blocking by providing better blocklists and analytics, not to replace fail2ban itself. Future versions will add integration with other popular monitoring and alerting tools.

---

## Features
- Focused SSH brute-force detection (all common log patterns)
- Defensive input validation & error handling
- CSV blocklist export (with formula injection protection)
- Configurable detection thresholds
- Dataclasses & enums for core models
- Version constant & `--version` CLI flag
- Production-ready deployment (fail2ban/systemd integration)

---

## Changelog
### **v1.1 (February 10, 2026)**
- Expanded SSH detection rules (covers all common patterns)
- Defensive input validation and CSV sanitization
- Robust error handling and syslog timestamp parsing
- Dataclasses and enums for core models
- Version constant and --version CLI flag
- Updated README and documentation
- All tests passing (84 passed, 2 skipped)

### **v1.0**
- Initial release

---

## Roadmap
- **v2.0:** Advanced threat intelligence, real-time monitoring, and machine learning integration

---

## Requirements
- Python 3.8+ (built-in libraries only)
- Access to SSH auth logs (e.g., `/var/log/auth.log`, `/var/log/secure`)

---

## Installation
1. Clone this repository
2. Optional: create a virtual environment
3. No external dependencies required

---

## Configuration
Edit `config.json` to tune behavior:
- `max_attempts`: Threshold for short-window detection
- `time_window_minutes`: Rolling window size for short-burst detection
- `block_threshold`: Total failed attempts to recommend blocking
- `monitor_threshold`: Total failed attempts to recommend monitoring
- `summary_limit`: Max rows to show in terminal summary
- `verbose_limit`: Max IPs shown in detailed breakdown
- `color_enabled`: Enable ANSI colors (override with `NO_COLOR` env)

On first run, a default `config.json` is created if missing.

---

## Security Posture: SSH-Key vs Password Authentication
**Default thresholds** assume mixed environments where legitimate users might occasionally mistype passwords:
- `max_attempts: 5` — Flags IPs with 5+ failed attempts in a short window
- `monitor_threshold: 20` — Recommends monitoring at 20+ total attempts
- `block_threshold: 50` — Recommends blocking at 50+ total attempts

**SSH-key-only servers** (password auth disabled) should use stricter rules, since *any* password attempt is suspicious:

**Option 1:** Use `--strict` preset (recommended)
```bash
python3 main.py --log-file "/var/log/auth.log" --live --strict
```
This sets `max_attempts=1`, `monitor_threshold=1`, `block_threshold=5` to flag every password attempt.

**Option 2:** Edit `config.json` manually
```json
{
  "max_attempts": 1,
  "time_window_minutes": 10,
  "block_threshold": 5,
  "monitor_threshold": 1,
  "summary_limit": 20,
  "verbose_limit": 10,
  "color_enabled": true
}
```

**Verify your SSH config** (`/etc/ssh/sshd_config`):
- `PasswordAuthentication no` → Use `--strict`
- `PasswordAuthentication yes` → Use defaults

---

## Usage
Interactive run (opens a file picker if no path provided):
```bash
python3 main.py
```

Non-interactive (pass a log file and optional summary size):
```bash
python3 main.py --log-file "/var/log/auth.log" --summary-limit 50
```

Live monitoring (tail the log, refresh every 5s by default):
```bash
python3 main.py --log-file "/var/log/auth.log" --live --refresh 5
```

Start from top of file instead of tail:
```bash
python3 main.py --log-file "/var/log/auth.log" --live --follow-start
```

Reduce noise and condense output:
```bash
# Show only HIGH+ threats and skip event summaries
python3 main.py --log-file "/var/log/auth.log" --live --filter-severity HIGH --compact
```

Quick presets and shortcuts:
```bash
# Strict mode for SSH-key-only servers (flags any password attempt)
python3 main.py --log-file "/var/log/auth.log" --live --strict

# Quiet SOC-style view: HIGH+ only, compact, 5s refresh
python3 main.py --log-file "/var/log/auth.log" --live --mode soc

# Verbose view: no filters, full summaries
python3 main.py --log-file "/var/log/auth.log" --live --mode verbose

# Short flag for filter
python3 main.py --log-file "/var/log/auth.log" --live -f HIGH --compact --refresh 10

# Presets without modes
python3 main.py --log-file "/var/log/auth.log" --live --quiet   # same as HIGH+ compact
python3 main.py --log-file "/var/log/auth.log" --live --noisy   # show everything
```

---

## v1.0 Features
### Non-Interactive Mode
Run without prompts for automation (cron jobs, systemd timers):
```bash
python3 main.py --log-file /var/log/auth.log --non-interactive --export-csv results.csv
```

### IP Whitelist
Prevent false positives by whitelisting trusted IPs. Create a whitelist file (one IP per line, `#` for comments):
**whitelist.txt:**
```
# Trusted infrastructure
192.168.1.1
10.0.0.100
203.0.113.5
```
**Usage:**
```bash
python3 main.py --log-file /var/log/auth.log --whitelist whitelist.txt --export-blocklist blocklist.txt
```

### CSV Export in Live Mode
Export live threat data continuously during real-time monitoring:
```bash
python3 main.py --log-file /var/log/auth.log --live --export-csv threats.csv --refresh 5
```

### IP Validation
All IPs are automatically validated before processing. Invalid IPs (malformed strings, injection attempts) are silently skipped to protect blocklist integrity.

### Automation Example (Cron Job)
```bash
# /etc/cron.hourly/sshvigil-analysis
#!/bin/bash
python3 /opt/sshvigil/main.py \
  --log-file /var/log/auth.log \
  --non-interactive \
  --export-csv /var/log/sshvigil_$(date +\%Y\%m\%d_\%H).csv \
  --export-blocklist /var/lib/sshvigil/blocklist.txt \
  --whitelist /etc/sshvigil/whitelist.txt \
  --blocklist-threshold HIGH
```

Disable color output (useful for CI or plain terminals):
```bash
NO_COLOR=1 python main.py --log-file "/var/log/auth.log"
```

On Windows PowerShell:
```powershell
$env:NO_COLOR = 1
python .\main.py --log-file "C:\\path\\to\\auth.log"
```

---

## Output

![SSHVigil threat analysis output showing real-time SSH brute-force detection: 12 IPs analyzed with 104 total attempts over 19 minutes. Two HIGH-severity IPs (146.190.237.126 and 36.88.28.122) marked as BLOCKED with 12 and 10 attempts respectively, while MEDIUM-severity threats are monitored and LOW-severity IPs allowed. Blocklist summary shows 2 IPs blocked at HIGH+ severity threshold.](<assets/Image of output.png>)

- **Log Coverage**: Time window and total parsed attempts
- **Event Summaries**: Top invalid user and accepted login counts by IP
- **Threat Analysis Summary**: Severity, IP, attempts, rate, and recommended action
- **Detailed Breakdown** (optional): Per-IP statistics including window and targeted users

To export all results to CSV, answer `y` when prompted or set `export_csv` in code; the file is saved next to your log as `brute_force_analysis.csv`.

---

## Fail2ban Integration
SSHVigil is designed to work alongside fail2ban, not to replace it. The integration helps improve fail2ban’s blocklists and analytics. Export a blocklist of malicious IPs for use with fail2ban or manual iptables blocking:
```bash
# Export HIGH+ severity IPs to blocklist (default threshold)
python3 main.py --log-file "/var/log/auth.log" --export-blocklist blocked-ips.txt

# Export only CRITICAL IPs
python3 main.py --log-file "/var/log/auth.log" --export-blocklist blocked-ips.txt --blocklist-threshold CRITICAL

# Live mode with continuous blocklist updates
python3 main.py --log-file "/var/log/auth.log" --live --export-blocklist /var/log/ssh-blocklist.txt --blocklist-threshold HIGH
```

### Manual iptables blocking
```bash
# Block all IPs from the generated file
while read ip; do
  sudo iptables -A INPUT -s $ip -j DROP
done < blocked-ips.txt

# View current blocks
sudo iptables -L INPUT -v -n

# Remove all blocks
sudo iptables -F INPUT
```

### Automated fail2ban setup
One-command fail2ban integration with automatic jail and filter config creation. This setup is optional and intended to enhance fail2ban’s SSH protection:
```bash
# Setup fail2ban jail and filter (creates configs, restarts fail2ban)
sudo python3 main.py --setup-fail2ban

# Then run in live mode to generate and update blocklist
python3 main.py --log-file "/var/log/auth.log" --live --export-blocklist /var/lib/sshvigil/blocklist.txt --strict
```

The `--setup-fail2ban` flag automatically:
- Creates `/etc/fail2ban/jail.d/sshvigil.conf` (jail configuration)
- Creates `/etc/fail2ban/filter.d/sshvigil.conf` (filter configuration)
- Restarts fail2ban to load the new configs
- Sets up blocklist directory at `/var/lib/sshvigil/`

### Systemd service installation (production)
One-command production deployment with auto-start and auto-restart:
```bash
# Install and start systemd service (auto-restarts on crash, runs on boot)
sudo python3 main.py --install-service
```

The `--install-service` flag automatically:
- Creates systemd unit at `/etc/systemd/system/sshvigil.service`
- Enables auto-start on system boot
- Starts the service immediately
- Configures auto-restart on failure
- Uses `--non-interactive` mode to prevent prompts during background operation

After installation, manage the service with standard systemd commands:
```bash
# Check status
sudo systemctl status sshvigil

# View live logs
sudo journalctl -u sshvigil -f

# Restart service
sudo systemctl restart sshvigil

# Stop service
sudo systemctl stop sshvigil
```

### Complete production setup (one-shot)
For a complete production deployment on a fresh system:
```bash
# 1. Setup fail2ban integration
sudo python3 main.py --setup-fail2ban

# 2. Install and start systemd service
sudo python3 main.py --install-service

# 3. Verify fail2ban jail is active
sudo fail2ban-client status sshvigil

# 4. Monitor logs in real-time
sudo journalctl -u sshvigil -f
```

The service will now:
- Start automatically on system boot
- Monitor SSH logs in real-time
- Continuously update `/var/lib/sshvigil/blocklist.txt`
- fail2ban will automatically ban IPs from the blocklist
- Auto-restart if the process crashes

### Manual setup (for reference)
If you prefer manual configuration or need advanced customization:
1. Copy filter config:
```bash
sudo cp examples/fail2ban-ssh-analyzer.conf /etc/fail2ban/filter.d/
```
2. Add jail to `/etc/fail2ban/jail.local`:
```ini
[ssh-analyzer]
enabled  = true
filter   = ssh-analyzer
logpath  = /var/log/ssh-blocklist.txt
backend  = polling
maxretry = 1
findtime = 86400
bantime  = 604800
action   = iptables-multiport[name=SSH, port="ssh", protocol=tcp]
```
3. Run analyzer in live mode writing to blocklist:
```bash
python3 main.py --log-file "/var/log/auth.log" --live --export-blocklist /var/log/ssh-blocklist.txt --strict
```
4. Restart fail2ban:
```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status ssh-analyzer
```

---

## Notes
- Supported formats are auto-detected; if detection fails, available formats are listed.
- The parser tracks basic stats: lines read, format matches, extract matches, and timestamp coverage.

---

## Roadmap (v2.0+)
- Additional event types and heuristics
- Enrichment (GeoIP, ASN) via optional modules
- Batch processing and scheduling
- Database backend for long-term analysis

---

## License
MIT License — See [LICENSE](LICENSE) file for details.

Free to use, modify, and distribute with attribution.
