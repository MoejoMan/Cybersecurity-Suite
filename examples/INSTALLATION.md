# Installation and Usage Guide for SSHVigil

## Systemd Service (Continuous Monitoring)

**Install:**
```bash
# Copy SSHVigil to /opt
sudo cp -r . /opt/sshvigil

# Create data directories
sudo mkdir -p /var/lib/sshvigil
sudo mkdir -p /etc/sshvigil

# Create whitelist
sudo bash -c 'cat > /etc/sshvigil/whitelist.txt << EOF
# Add your trusted IPs here (one per line)
127.0.0.1
EOF'

# Install service
sudo cp examples/sshvigil.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sshvigil
sudo systemctl start sshvigil
```

**Check status:**
```bash
sudo systemctl status sshvigil
sudo journalctl -u sshvigil -f
```

**View live CSV output:**
```bash
tail -f /var/log/sshvigil_live.csv
```

---

## Cron Job (Hourly Analysis)

**Install:**
```bash
# Make script executable
chmod +x examples/sshvigil-cron.sh

# Copy to cron.hourly
sudo cp examples/sshvigil-cron.sh /etc/cron.hourly/sshvigil-analysis

# Or add to crontab for custom schedule
sudo crontab -e
# Add: 0 * * * * /opt/sshvigil/examples/sshvigil-cron.sh
```

**Check results:**
```bash
# View latest CSV
ls -lt /var/log/sshvigil/*.csv | head -1 | awk '{print $NF}' | xargs cat

# View cron logs
sudo tail -f /var/log/sshvigil/sshvigil.log
```

---

## Fail2ban Integration

**Setup:**
```bash
# Install fail2ban
sudo apt install fail2ban  # Debian/Ubuntu
sudo yum install fail2ban  # CentOS/RHEL

# Copy jail config
sudo cp examples/fail2ban-sshvigil.conf /etc/fail2ban/jail.d/

# Start SSHVigil with blocklist export (via systemd or manually)
sudo systemctl start sshvigil
# OR run manually:
python3 main.py --log-file /var/log/auth.log --live \
  --export-blocklist /var/lib/sshvigil/blocklist.txt --quiet

# Restart fail2ban
sudo systemctl restart fail2ban
```

**Verify:**
```bash
# Check jail status
sudo fail2ban-client status sshvigil-blocklist

# View banned IPs
sudo fail2ban-client get sshvigil-blocklist banned

# View fail2ban logs
sudo tail -f /var/log/fail2ban.log
```

**Unban an IP:**
```bash
sudo fail2ban-client set sshvigil-blocklist unbanip 192.0.2.10
```

---

## Combined Setup (Recommended)

Run SSHVigil as a systemd service + fail2ban for enforcement:

```bash
# 1. Install SSHVigil service (continuous monitoring)
sudo systemctl enable --now sshvigil

# 2. Install fail2ban integration (automatic banning)
sudo cp examples/fail2ban-sshvigil.conf /etc/fail2ban/jail.d/
sudo systemctl restart fail2ban

# 3. Check everything is working
sudo systemctl status sshvigil
sudo fail2ban-client status sshvigil-blocklist
```

This setup provides:
- Real-time SSH threat monitoring (SSHVigil systemd service)
- Automated IP blocking via iptables (fail2ban)
- Continuous CSV logging for forensics
- Whitelist protection for trusted IPs

---

## Troubleshooting

**SSHVigil service won't start:**
```bash
# Check logs
sudo journalctl -u sshvigil -n 50

# Verify Python path
which python3

# Test manually
cd /opt/sshvigil
python3 main.py --log-file /var/log/auth.log --live --quiet
```

**Fail2ban not banning IPs:**
```bash
# Check if blocklist file exists
ls -l /var/lib/sshvigil/blocklist.txt

# Verify fail2ban is reading the file
sudo fail2ban-client get sshvigil-blocklist logpath

# Check fail2ban logs
sudo tail -f /var/log/fail2ban.log
```

**Whitelist not working:**
```bash
# Verify whitelist file syntax (one IP per line)
cat /etc/sshvigil/whitelist.txt

# Test manually
python3 main.py --log-file /var/log/auth.log \
  --whitelist /etc/sshvigil/whitelist.txt \
  --export-blocklist /tmp/test-blocklist.txt \
  --non-interactive

# Check if whitelisted IP is excluded
cat /tmp/test-blocklist.txt
```
