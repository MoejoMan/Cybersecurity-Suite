"""
SSHVigil - Lightweight Security Threat Detection

SSH Brute Force Analysis Module

Parses SSH authentication logs, aggregates login attempts by IP,
classifies threat levels, and prints a concise summary and optional detailed
breakdown. Supports fail2ban integration and live monitoring.

Usage:
- Non-interactive: provide a path with --log-file
- Interactive: if no path is provided, a file picker will open
- Live mode: --live flag enables real-time monitoring
"""
import sys
import os
import csv
import shutil
import argparse
import hashlib
import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta
from parser import SSHLogParser
from config import Config
from models import __version__
from utils import follow_file, is_valid_ip

# Localhost whitelist - these IPs are ALWAYS excluded from blocklists for safety
# to prevent accidental self-lockout via fail2ban integration
LOCALHOST_WHITELIST = {
    '127.0.0.1',      # IPv4 localhost
    '::1',            # IPv6 localhost
}

# Private network ranges that should typically be whitelisted
PRIVATE_NETWORK_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),    # IPv4 loopback
    ipaddress.ip_network('::1/128'),        # IPv6 loopback
    ipaddress.ip_network('10.0.0.0/8'),     # Private network (common VPS internal)
    ipaddress.ip_network('172.16.0.0/12'),  # Private network
    ipaddress.ip_network('192.168.0.0/16'), # Private network
]

class BruteForceDetector:
    """
        Detects and summarizes brute-force behaviour in SSH authentication logs.

        Parameters:
        - max_attempts: Number of failed attempts within `time_window_minutes` to flag an IP.
        - time_window_minutes: Size of rolling window used for short-burst detection.
        - block_threshold: Total failed attempts to recommend blocking (persistent attacks).
        - monitor_threshold: Total failed attempts to recommend monitoring.
        - summary_limit: Maximum rows printed in the summary table.
        - verbose_limit: Maximum IPs included in the verbose breakdown.

        Attributes:
        - attempts_by_ip: Mapping of IP to list of parsed attempts with `username`,
            `timestamp`, `success`, and optional `event` label.
        - use_color: Whether to use ANSI colors in terminal output.
    """

    def __init__(self, max_attempts=5, time_window_minutes=10, block_threshold=50, monitor_threshold=20, summary_limit=20, verbose_limit=10):
        # Validate and clamp parameters to sane values
        self.max_attempts = max(0, int(max_attempts)) if max_attempts is not None else 5
        time_window_minutes = max(0, float(time_window_minutes)) if time_window_minutes is not None else 10
        self.time_window = timedelta(minutes=time_window_minutes)
        self.block_threshold = max(0, int(block_threshold)) if block_threshold is not None else 50
        self.monitor_threshold = max(0, int(monitor_threshold)) if monitor_threshold is not None else 20
        self.summary_limit = max(1, int(summary_limit)) if summary_limit is not None else 20
        self.verbose_limit = max(1, int(verbose_limit)) if verbose_limit is not None else 10
        self.use_color = not os.environ.get('NO_COLOR')
        self.attempts_by_ip = defaultdict(list)
        self.written_ips = set()  # Track IPs already written to blocklist

    def _color(self, text, fg=None, bold=False):
        """
        Return `text` decorated with ANSI color codes when enabled.

        Args:
        - text: String to colorize.
        - fg: Optional foreground color name (red, yellow, green, cyan, blue, magenta).
        - bold: Whether to apply bold styling.

        Returns:
        - The possibly colorized text, or the original text when color is disabled.
        """
        if not self.use_color:
            return text
        codes = []
        if bold:
            codes.append('1')
        fg_map = {
            'red': '31', 'yellow': '33', 'green': '32', 'cyan': '36', 'blue': '34', 'magenta': '35'
        }
        if fg and fg in fg_map:
            codes.append(fg_map[fg])
        if not codes:
            return text
        return f"\033[{';'.join(codes)}m{text}\033[0m"

    @staticmethod
    def _sanitize_csv_value(value):
        """
        Sanitize a value for CSV export to prevent formula injection.
        
        Prefixes values starting with =, +, -, @, \t, \r with a single quote
        to neutralize spreadsheet formula execution.
        """
        if isinstance(value, str) and value and value[0] in ('=', '+', '-', '@', '\t', '\r'):
            return "'" + value
        return value

    def add_attempt(self, ip_address, username, timestamp, success, event=None):
        """
        Record a single SSH auth attempt parsed from the logs.

        Args:
        - ip_address: Source IP address.
        - username: Target account name.
        - timestamp: Attempt time as `datetime`.
        - success: True if authentication succeeded; False otherwise.
        - event: Optional label describing the event type (e.g., 'invalid_user').
        """
        # Validate IP before adding
        if not ip_address or not is_valid_ip(str(ip_address)):
            return  # Skip invalid IPs silently
        
        # Validate timestamp
        if not isinstance(timestamp, datetime):
            return  # Skip entries without a valid timestamp
        
        # Coerce username to string and strip control characters for safety
        username = str(username) if username is not None else "<unknown>"
        
        self.attempts_by_ip[ip_address].append({
            "username": username,
            "timestamp": timestamp,
            "success": bool(success),
            "event": event
        })

    def classify_threat(self, total_attempts, attack_rate, duration):
        """
        Classify threat severity from aggregate metrics.

        Logic:
        - Short-burst attacks: high volume within `time_window` → CRITICAL/HIGH.
        - Persistent attacks: very high total volume regardless of rate → HIGH/MEDIUM.
        - Elevated rate with moderate volume → MEDIUM.
        - Otherwise → LOW.

        Args:
        - total_attempts: Total failed attempts for an IP.
        - attack_rate: Failed attempts per minute over the observed window.
        - duration: `timedelta` covering first to last attempt.

        Returns:
        - One of {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}.
        """
        # Rapid attacks - high rate in short window
        if total_attempts >= self.max_attempts and duration <= self.time_window and attack_rate >= 2.0:
            return "CRITICAL"
        elif total_attempts >= self.max_attempts and duration <= self.time_window:
            return "HIGH"
        
        # Persistent attacks - high volume even if slow
        elif total_attempts >= self.block_threshold:
            return "HIGH"
        elif total_attempts >= self.monitor_threshold:
            return "MEDIUM"
        
        # High-rate attacks even if lower volume
        elif attack_rate > 1.0:
            return "MEDIUM"
        
        elif total_attempts >= self.max_attempts:
            return "LOW"
        return "LOW"

    def format_duration(self, delta):
        """
        Format a `timedelta` as a compact human-readable string.

        Example: "2h 3m 15s" or "7m 04s".
        """
        total_seconds = int(abs(delta.total_seconds()))  # abs() to handle negative deltas gracefully
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours:
            return f"{hours}h {minutes}m {seconds}s"
        return f"{minutes}m {seconds}s"

    def analyze(self, verbose=False, export_csv=None, filter_severity=None, compact=False, live_mode=False, export_blocklist=None, blocklist_threshold='HIGH', whitelist=None):
        """
        Aggregate attempts, compute severity, and render summaries.

        Args:
        - verbose: If True, include a per-IP detailed breakdown.
        - export_csv: Optional path to export the full results table.
        - filter_severity: Only show threats at or above this level (CRITICAL/HIGH/MEDIUM/LOW).
        - compact: Skip event summaries, show only threat table.
        - live_mode: Suppress pagination messages for continuous monitoring.
        - export_blocklist: Optional path to export IPs to blocklist file.
        - blocklist_threshold: Minimum severity for blocklist inclusion (default: HIGH).
        - whitelist: Set of whitelisted IPs to exclude from blocklist.

        Returns:
        - List of dict rows with keys: IP, Attempts, Attack_Rate, Severity,
          Action, Duration, Window_Start, Window_End.
        """
        summary = defaultdict(lambda: defaultdict(int))
        whitelist = whitelist or set()  # Default to empty set if None
        
        # Validate severity parameters
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        if blocklist_threshold not in valid_severities:
            print(f"[WARNING] Invalid blocklist_threshold '{blocklist_threshold}', defaulting to HIGH")
            blocklist_threshold = "HIGH"
        if filter_severity is not None and filter_severity not in valid_severities:
            print(f"[WARNING] Invalid filter_severity '{filter_severity}', ignoring filter")
            filter_severity = None

        for ip, attempts in self.attempts_by_ip.items():
            for attempt in attempts:
                # Count only failed attempts towards brute-force summary
                if not attempt.get('success', False):
                    username = attempt['username']
                    summary[ip][username] += 1

        sorted_ips = sorted(summary.items(), key=lambda x: sum(x[1].values()), reverse=True)
        
        # Pre-compute threat levels and scores for sorting (severity, then attempts desc)
        threat_scores = {}
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        
        for ip, usernames in summary.items():
            total_attempts = sum(usernames.values())
            attempts = self.attempts_by_ip[ip]
            
            if attempts:
                timestamps = [att['timestamp'] for att in attempts if isinstance(att.get('timestamp'), datetime)]
                if timestamps:
                    duration = max(timestamps) - min(timestamps)
                    # Add 1 minute floor to prevent inflated rates from tiny time windows
                    total_minutes = max(duration.total_seconds() / 60, 1.0)
                    attack_rate = total_attempts / total_minutes
                else:
                    attack_rate = 0
                    duration = timedelta(0)
            else:
                attack_rate = 0
                duration = timedelta(0)
            
            threat_level = self.classify_threat(total_attempts, attack_rate, duration)
            threat_scores[ip] = (severity_order[threat_level], -total_attempts)
        
        # Sort by: severity first, then by attempt count (desc)
        sorted_ips = sorted(sorted_ips, key=lambda x: threat_scores[x[0]])
        
        # Collect results for export
        results = []
        
        # Determine which IPs will be blocked (for display feedback)
        blocked_ips_display = set()
        if export_blocklist:
            severity_threshold = severity_order[blocklist_threshold]
            for (ip, usernames) in sorted_ips:
                total_attempts = sum(usernames.values())
                attempts = self.attempts_by_ip[ip]
                if not attempts:
                    continue
                timestamps = [att['timestamp'] for att in attempts if isinstance(att.get('timestamp'), datetime)]
                if not timestamps:
                    continue
                duration = max(timestamps) - min(timestamps)
                total_minutes = max(duration.total_seconds() / 60, 1.0)
                attack_rate = total_attempts / total_minutes
                threat_level = self.classify_threat(total_attempts, attack_rate, duration)
                
                # Check if this IP meets blocklist criteria
                # SAFETY: Always exclude localhost and private networks from blocklists
                if (severity_order[threat_level] <= severity_threshold 
                    and ip not in whitelist 
                    and not is_localhost_or_private(ip)):
                    blocked_ips_display.add(ip)
        
        # Compute results for all IPs (for full CSV export)
        all_results = []
        for (ip, usernames) in sorted_ips:
            total_attempts = sum(usernames.values())
            attempts = self.attempts_by_ip[ip]
            if not attempts:
                continue
            timestamps = [att['timestamp'] for att in attempts if isinstance(att.get('timestamp'), datetime)]
            if not timestamps:
                continue
            first = min(timestamps)
            last = max(timestamps)
            duration = last - first
            total_minutes = max(duration.total_seconds() / 60, 1.0)
            attack_rate = total_attempts / total_minutes
            threat_level = self.classify_threat(total_attempts, attack_rate, duration)
            
            # Determine action display
            if ip in blocked_ips_display:
                action = "BLOCKED"
            elif threat_level in ["CRITICAL", "HIGH"]:
                action = "BLOCK"
            elif threat_level == "MEDIUM":
                action = "MONITOR"
            else:
                action = "ALLOW"
                
            all_results.append({
                'IP': ip,
                'Attempts': total_attempts,
                'Attack_Rate': f"{attack_rate:.2f}",
                'Severity': threat_level,
                'Action': action,
                'Duration': self.format_duration(duration),
                'Window_Start': first.isoformat(),
                'Window_End': last.isoformat()
            })

        # Compute overall coverage stats
        all_timestamps = []
        total_parsed_attempts = 0
        for attempts in self.attempts_by_ip.values():
            total_parsed_attempts += len(attempts)
            all_timestamps.extend(att['timestamp'] for att in attempts if isinstance(att.get('timestamp'), datetime))
        ip_count = len(self.attempts_by_ip)

        # Get terminal width for better formatting
        term_width = shutil.get_terminal_size((80, 20)).columns

        # Coverage summary header
        line_width = min(term_width, 100)
        print("\n" + "=" * line_width)
        print(self._color("LOG COVERAGE", bold=True))
        print("=" * line_width)
        # Prefer coverage from parser stats; fall back to attempts
        coverage_start = getattr(self, 'coverage_start', None)
        coverage_end = getattr(self, 'coverage_end', None)
        if not coverage_start or not coverage_end:
            if all_timestamps:
                coverage_start = min(all_timestamps)
                coverage_end = max(all_timestamps)

        if coverage_start and coverage_end:
            coverage_duration = coverage_end - coverage_start
            coverage_str = self.format_duration(coverage_duration)
            print(f"Window: {coverage_start.strftime('%Y-%m-%d %H:%M:%S')} to {coverage_end.strftime('%Y-%m-%d %H:%M:%S')} ({coverage_str})")
            print(f"Parsed IPs: {ip_count:,} | Attempts: {total_parsed_attempts:,}")
        else:
            print("No parsed attempts found.")

        # Compact event summaries to keep output concise
        if not compact:
            print("\n" + "=" * line_width)
            print(self._color("EVENT SUMMARIES", bold=True))
            print("=" * line_width)
            
            # Invalid user summary (top N by count)
            invalid_counts = defaultdict(int)
            for ip, attempts in self.attempts_by_ip.items():
                for att in attempts:
                    if att.get('event') == 'invalid_user':
                        invalid_counts[ip] += 1
            if invalid_counts:
                top_invalid = sorted(invalid_counts.items(), key=lambda x: x[1], reverse=True)[:max(1, self.summary_limit//2)]
                print(self._color(f"Invalid user attempts (top {len(top_invalid)}):", fg='cyan', bold=True))
                for ip, cnt in top_invalid:
                    print(f"  {ip:<18} {cnt:>7,} events")
            else:
                print("No invalid user events detected.")

            # Accepted password summary (top N by count)
            accepted_counts = defaultdict(int)
            for ip, attempts in self.attempts_by_ip.items():
                for att in attempts:
                    if att.get('success') is True:
                        accepted_counts[ip] += 1
            if accepted_counts:
                top_accepted = sorted(accepted_counts.items(), key=lambda x: x[1], reverse=True)[:max(1, self.summary_limit//2)]
                print(self._color(f"Accepted password events (top {len(top_accepted)}):", fg='green', bold=True))
                for ip, cnt in top_accepted:
                    print(f"  {ip:<18} {cnt:>7,} events")
            else:
                print("No accepted password events detected.")

        # Threat summary header
        print("\n" + "=" * line_width)
        print(self._color("THREAT ANALYSIS SUMMARY", bold=True))
        print("=" * line_width)
        
        # Filter results by severity if specified
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        display_results = all_results
        if filter_severity:
            threshold = severity_order[filter_severity]
            display_results = [r for r in all_results if severity_order[r['Severity']] <= threshold]
            display_results = sorted(display_results, key=lambda x: (severity_order[x['Severity']], -int(x['Attempts'])))
        hidden_count = len(all_results) - len(display_results)
        
        # Summary table header
        print(f"{'SEVERITY':<12} {'IP ADDRESS':<18} {'ATTEMPTS':<12} {'RATE':<12} {'ACTION':<12}")
        print("-" * line_width)

        for i, r in enumerate(display_results):
            sev = r['Severity']
            sev_col = {
                'CRITICAL': ('red', True),
                'HIGH': ('yellow', True),
                'MEDIUM': ('cyan', False),
                'LOW': (None, False)
            }
            fg, bold = sev_col.get(sev, (None, False))
            sev_text = self._color(sev, fg=fg, bold=bold)
            rate_val = float(r['Attack_Rate'])
            action = r['Action']
            action_col = {
                'BLOCKED': 'red',
                'BLOCK': 'red',
                'MONITOR': 'yellow',
                'ALLOW': 'green'
            }.get(action)
            action_text = self._color(action, fg=action_col, bold=True if action not in ('ALLOW',) else False)
            print(f"{sev_text:<12} {r['IP']:<18} {r['Attempts']:>12,} {rate_val:>6.2f}/min {action_text:<12}")
            # Limit summary output based on configured summary_limit
            if i >= (self.summary_limit - 1):
                remaining = len(display_results) - self.summary_limit
                if remaining > 0:
                    print("-" * line_width)
                    if not live_mode:
                        print(f"... and {remaining} more. Export to CSV to see all.")
                    else:
                        print(f"... and {remaining} more.")
                break

        print("=" * line_width)
        if hidden_count > 0:
            note = f"{hidden_count} IP(s) hidden by filter ({filter_severity}+)."
            print(self._color(note, fg='cyan', bold=True))
        # Count from display_results to reflect active filters
        suspicious_ips = [r for r in display_results if r['Severity'] != 'LOW']
        print(f"Total suspicious IPs: {len(suspicious_ips):,}")
        
        # Show blocklist summary if blocklist export is enabled
        if export_blocklist:
            blocked_count = len(blocked_ips_display)
            if blocked_count > 0:
                blocklist_msg = f"Blocklist: {blocked_count} IP(s) marked for blocking ({blocklist_threshold}+ severity)"
                print(self._color(blocklist_msg, fg='red', bold=True))
            else:
                print(self._color(f"Blocklist: No IPs meet {blocklist_threshold}+ threshold yet", fg='yellow'))
        
        # Verbose mode - detailed breakdown
        if verbose:
            print("\n" + "=" * line_width)
            print(self._color(f"DETAILED BREAKDOWN (Top {self.verbose_limit})", bold=True))
            print("=" * line_width)
            # Apply the same severity filter to verbose output
            allowed_ips = {r['IP'] for r in display_results}
            
            for i, (ip, usernames) in enumerate(sorted_ips):
                if ip not in allowed_ips:
                    continue
                if i >= self.verbose_limit:
                    break
                    
                total_attempts = sum(usernames.values())
                attempts = self.attempts_by_ip[ip]
                
                if attempts:
                    timestamps = [att['timestamp'] for att in attempts if isinstance(att.get('timestamp'), datetime)]
                    if not timestamps:
                        continue
                    first = min(timestamps)
                    last = max(timestamps)
                    duration = last - first
                    duration_str = self.format_duration(duration)
                    
                    total_minutes = max(duration.total_seconds() / 60, 1.0)
                    attack_rate = total_attempts / total_minutes
                    
                    print(f"\n[IP] {ip}")
                    print(f"  Attempts: {total_attempts:,}")
                    print(f"  Attack rate: {attack_rate:.2f} attempts/minute")
                    print(f"  Targeted users: {', '.join(usernames.keys())}")
                    print(f"  Window: {first.strftime('%Y-%m-%d %H:%M:%S')} to {last.strftime('%H:%M:%S')} ({duration_str})")
                    print("-" * line_width)
        
        # Export full results to CSV (with formula injection sanitization)
        if export_csv and all_results:
            try:
                with open(export_csv, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=all_results[0].keys())
                    writer.writeheader()
                    for row in all_results:
                        sanitized = {k: self._sanitize_csv_value(v) for k, v in row.items()}
                        writer.writerow(sanitized)
                print(f"\nResults exported to: {export_csv}")
            except PermissionError:
                print(f"[ERROR] Permission denied writing CSV: {export_csv}")
            except OSError as e:
                print(f"[ERROR] Could not write CSV: {e}")
        
        # Export blocklist for iptables/fail2ban (append-only for faster detection)
        if export_blocklist and all_results:
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            threshold = severity_order[blocklist_threshold]
            blocked_ips = [r['IP'] for r in all_results if severity_order[r['Severity']] <= threshold]
            
            # Filter out whitelisted IPs (user-specified)
            blocked_ips = [ip for ip in blocked_ips if ip not in whitelist]
            
            # SAFETY: Filter out localhost and private networks (always excluded)
            blocked_ips = [ip for ip in blocked_ips if not is_localhost_or_private(ip)]
            
            # Only append new IPs (not already written)
            new_ips = [ip for ip in blocked_ips if ip not in self.written_ips]
            
            if new_ips:
                try:
                    # Append mode for faster fail2ban polling detection
                    with open(export_blocklist, 'a') as f:
                        for ip in new_ips:
                            f.write(f"{ip}\n")
                            self.written_ips.add(ip)
                    total_in_blocklist = len(self.written_ips)
                    msg = f"[OK] Blocklist updated: {export_blocklist} (+{len(new_ips)} new | {total_in_blocklist} total)"
                    print(self._color(msg, fg='green', bold=True))
                except Exception as e:
                    print(f"[ERROR] Failed to update blocklist: {e}")
            # Else: no new IPs, skip writing
        
        return all_results  

def check_pid_lock(blocklist_path):
    """Check if another analyzer instance is using this blocklist (cross-platform)."""
    # Create unique lock name based on blocklist path
    lock_hash = hashlib.md5(blocklist_path.encode()).hexdigest()[:8]
    
    # Use platform-appropriate temp directory
    if os.name == 'nt':  # Windows
        pid_dir = os.path.expandvars(r'%TEMP%')
    else:  # Unix-like
        pid_dir = '/tmp'
    
    pid_file = os.path.join(pid_dir, f'ssh-analyzer-{lock_hash}.pid')
    
    if os.path.exists(pid_file):
        with open(pid_file, 'r') as f:
            try:
                pid = int(f.read().strip())
                # Check if process is still running (cross-platform)
                if is_process_running(pid):
                    return pid_file, pid  # Lock is active
                else:
                    # Stale lock file, clean it up
                    os.remove(pid_file)
            except (OSError, ValueError):
                # Stale lock file, clean it up
                try:
                    os.remove(pid_file)
                except OSError:
                    pass
    return pid_file, None

def is_process_running(pid):
    """Check if a process with given PID is still running (cross-platform)."""
    if os.name == 'nt':  # Windows
        try:
            import psutil # type: ignore[import]
            return psutil.pid_exists(pid)
        except ImportError:
            # psutil not available on Windows; assume process is running to be safe
            return True
        except Exception:
            return False
    else:  # Unix-like
        try:
            os.kill(pid, 0)  # Signal 0: check if process exists
            return True
        except OSError:
            return False

def create_pid_lock(pid_file):
    """Create PID lock file."""
    with open(pid_file, 'w') as f:
        f.write(str(os.getpid()))

def remove_pid_lock(pid_file):
    """Remove PID lock file on exit."""
    try:
        if os.path.exists(pid_file):
            os.remove(pid_file)
    except Exception:
        pass

def load_existing_blocklist(blocklist_path):
    """Load existing IPs from blocklist file."""
    ips = set()
    try:
        with open(blocklist_path, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip and is_valid_ip(ip):
                    ips.add(ip)
    except FileNotFoundError:
        pass
    return ips

def is_localhost_or_private(ip_str):
    """
    Check if an IP address is localhost or in a private network range.
    These IPs should ALWAYS be excluded from blocklists for safety.
    
    Returns True if the IP is in the safe whitelist, False otherwise.
    """
    # First check exact matches
    if ip_str in LOCALHOST_WHITELIST:
        return True
    
    # Then check if IP is in any private network range
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for network in PRIVATE_NETWORK_RANGES:
            if ip_obj in network:
                return True
    except ValueError:
        # Invalid IP format, don't whitelist it
        pass
    
    return False

def load_whitelist(whitelist_path):
    """Load whitelisted IPs from file."""
    whitelist = set()
    if not whitelist_path:
        return whitelist
    
    try:
        with open(whitelist_path, 'r') as f:
            for line in f:
                ip = line.strip()
                # Skip comments and empty lines
                if ip and not ip.startswith('#') and is_valid_ip(ip):
                    whitelist.add(ip)
        print(f"[OK] Loaded {len(whitelist)} whitelisted IPs from {whitelist_path}")
    except FileNotFoundError:
        print(f"[WARNING] Whitelist file not found: {whitelist_path}")
    except Exception as e:
        print(f"[WARNING] Error loading whitelist: {e}")
    
    return whitelist


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
        # Create jail config
        with open('/etc/fail2ban/jail.d/sshvigil.conf', 'w') as f:
            f.write(jail_config)
        print("[OK] Created /etc/fail2ban/jail.d/sshvigil.conf")
        
        # Create filter config
        with open('/etc/fail2ban/filter.d/sshvigil.conf', 'w') as f:
            f.write(filter_config)
        print("[OK] Created /etc/fail2ban/filter.d/sshvigil.conf")
        
        # Restart fail2ban
        import subprocess
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
        
        import subprocess
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

        script_dir = os.path.dirname(os.path.abspath(script_path))
        if script_dir:
                os.makedirs(script_dir, exist_ok=True)

        script_template = """#!/bin/bash
set -euo pipefail

LOG_FILE=\"{log_path}\"
BLOCKLIST=\"{blocklist}\"
PYTHON_BIN=\"{python_bin}\"
APP_DIR=\"{app_dir}\"
TOP_N=5
WHITELIST=\"{whitelist}\"

mkdir -p \"$(dirname \"$BLOCKLIST\")\"

if [ -n \"$WHITELIST\" ]; then
    WHITELIST_ARG=\"--whitelist $WHITELIST\"
else
    WHITELIST_ARG=\"\"
fi

\"$PYTHON_BIN\" \"$APP_DIR/main.py\" \\
    --log-file \"$LOG_FILE\" \\
    --non-interactive \\
    --export-blocklist \"$BLOCKLIST\" \\
    --blocklist-threshold {threshold} \\
    $WHITELIST_ARG

head -n \"$TOP_N\" \"$BLOCKLIST\" | while read -r ip; do
    [ -z \"$ip\" ] && continue
    sudo fail2ban-client set sshd banip \"$ip\"
    echo \"[$(date)] Banned $ip\"
done
"""

        script_content = script_template.format(
                log_path=log_path,
                blocklist=blocklist_path,
                python_bin=python_bin,
                app_dir=app_dir,
                threshold=threshold,
                whitelist=whitelist_path,
        )

        with open(script_path, 'w', newline='\n') as f:
                f.write(script_content)
        try:
                os.chmod(script_path, 0o755)
        except Exception:
                pass
        print(f"[OK] Generated fail2ban helper script: {script_path}")
        print("Run: sudo bash {script_path}  (or add to cron)".format(script_path=script_path))


def main():
    """
    Entry point: parse CLI args, read the log file, run analysis, and print
    results. Offers interactive prompts for verbosity and CSV export.
    """
    # CLI flags for non-interactive runs
    argp = argparse.ArgumentParser(
    description="SSHVigil - SSH Brute Force Detection & Defense",
    epilog="Examples:\n  python3 main.py --log-file /var/log/auth.log --live -f HIGH --compact --refresh 10\n  python3 main.py --log-file /var/log/auth.log --live --mode soc\n  python3 main.py --log-file /var/log/auth.log --live --follow-start --summary-limit 10\n  python3 main.py --log-file /var/log/auth.log --live --mode verbose\n"
    )
    argp.add_argument("--version", "-V", action="version", version=f"SSHVigil v{__version__}")
    argp.add_argument("--log-file", dest="log_file", help="Path to auth/secure log file")
    argp.add_argument("--summary-limit", dest="summary_limit", type=int, help="Max rows to show in terminal summary")
    argp.add_argument("--live", dest="live", action="store_true", help="Follow the log file and analyze in real-time")
    argp.add_argument("--follow-start", dest="follow_start", action="store_true", help="Start live mode from the beginning of the file")
    argp.add_argument("--refresh", dest="refresh", type=float, help="Seconds between summary refresh in live mode")
    argp.add_argument("--filter-severity", "-f", dest="filter_severity", choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], help="Only show threats at or above this severity level")
    argp.add_argument("--verbose", dest="verbose", action="store_true", help="Show detailed event breakdown")
    argp.add_argument("--compact", dest="compact", action="store_true", help="Skip event summaries, show only threat table")
    argp.add_argument("--quiet", dest="quiet", action="store_true", help="Preset: HIGH+ filter, compact output, 5s refresh")
    argp.add_argument("--noisy", dest="noisy", action="store_true", help="Preset: show everything (no filter, no compact)")
    argp.add_argument("--strict", dest="strict", action="store_true", help="Preset: SSH-key-only mode (max_attempts=1, flags any password attempt)")
    argp.add_argument("--mode", dest="mode", choices=['soc', 'verbose'], help="Preset: soc (HIGH+ compact fast refresh) or verbose (full detail)")
    argp.add_argument("--export-blocklist", dest="export_blocklist", help="Export IPs to blocklist file (one per line) for iptables/fail2ban")
    argp.add_argument("--blocklist-threshold", dest="blocklist_threshold", choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], default='HIGH', help="Minimum severity for blocklist (default: HIGH)")
    argp.add_argument("--generate-fail2ban-script", dest="generate_fail2ban_script", help="Generate a ready-to-run fail2ban updater script at this path and exit")
    argp.add_argument("--script-blocklist-path", dest="script_blocklist_path", help="Blocklist path to embed in generated fail2ban script (default: /var/lib/sshvigil/blocklist.txt)")
    argp.add_argument("--setup-fail2ban", dest="setup_fail2ban", action="store_true", help="Auto-create fail2ban jail and filter configs, then restart fail2ban (requires sudo)")
    argp.add_argument("--install-service", dest="install_service", action="store_true", help="Install SSHvigil as a systemd service for live monitoring (requires sudo)")
    argp.add_argument("--export-csv", dest="export_csv", help="Export results to CSV file (works in both live and batch mode)")
    argp.add_argument("--non-interactive", dest="non_interactive", action="store_true", help="Suppress prompts for automation (batch mode will skip verbose/export questions)")
    argp.add_argument("--whitelist", dest="whitelist", help="Path to whitelist file (one IP per line) to exclude from blocklist")
    args = argp.parse_args()
    print(f"SSHVigil v{__version__} - SSH Brute Force Analyzer")
    print("=" * 40)
    
    # Only import tkinter and show GUI if not in live mode and no log-file provided
    if args.live or args.log_file:
        log_path = args.log_file
    else:
        try:
            import tkinter as tk
            from tkinter import filedialog
            tk.Tk().withdraw()
            log_path = filedialog.askopenfilename(
                title="Select your auth.log file",
                filetypes=[("Log files", "*.log"), ("All files", "*.*")]
            )
        except ImportError:
            print("Error: tkinter not available for file picker.")
            print("Please specify a log file with --log-file")
            sys.exit(1)
        except Exception as e:
            print(f"Error opening file picker: {e}")
            print("Please specify a log file with --log-file")
            sys.exit(1)

    if not log_path:
        print("No file selected. Exiting.")
        sys.exit(1)

    # Validate log path early
    if not os.path.exists(log_path):
        print(f"Error: Log file not found: {log_path}")
        
        # Offer suggestions only if no explicit path was given
        if not args.log_file:
            possible_paths = [
                "/var/log/auth.log",        
                "/var/log/secure",           
                "auth.log",
            ]
            
            print("\nSearching for common log files...")
            found_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    print(f"Found log file at: {path}")
                    confirm = input("Use this file? (y/n): ").strip().lower()
                    if confirm == 'y':
                        log_path = path
                        found_path = path
                        break
            
            if not found_path:
                print("\nError: No common auth.log file found.")
                print("Please specify the path with --log-file")
                sys.exit(1)
        else:
            sys.exit(1)
    
    # Validate file is readable
    if not os.path.isfile(log_path):
        print(f"Error: Path is not a file: {log_path}")
        sys.exit(1)
    
    if not os.access(log_path, os.R_OK):
        print(f"Error: No read permission for: {log_path}")
        print("Try running with appropriate permissions (e.g., sudo)")
        sys.exit(1)
    
    print(f"Using log file: {log_path}")

    # Optional: setup fail2ban integration and exit
    if args.setup_fail2ban:
        blocklist_for_setup = args.export_blocklist or "/var/lib/sshvigil/blocklist.txt"
        setup_fail2ban_integration(blocklist_for_setup)
        sys.exit(0)
    
    # Optional: install as systemd service and exit
    if args.install_service:
        blocklist_for_service = args.export_blocklist or "/var/lib/sshvigil/blocklist.txt"
        install_systemd_service(
            log_path=log_path,
            blocklist_path=blocklist_for_service,
            threshold=args.blocklist_threshold,
            whitelist_path=args.whitelist
        )
        sys.exit(0)

    # Optional: generate fail2ban helper script and exit
    if args.generate_fail2ban_script:
        blocklist_for_script = args.script_blocklist_path or "/var/lib/sshvigil/blocklist.txt"
        generate_fail2ban_script(
            script_path=args.generate_fail2ban_script,
            log_path=log_path,
            blocklist_path=blocklist_for_script,
            threshold=args.blocklist_threshold,
            whitelist_path=args.whitelist
        )
        sys.exit(0)
    
    # Load whitelist if specified
    whitelist = load_whitelist(args.whitelist) if args.whitelist else set()
    
    # Initialize config, parser and detector
    config = Config()
    parser = SSHLogParser()
    # Allow CLI override of summary_limit
    summary_limit_val = args.summary_limit if args.summary_limit else config["summary_limit"]

    # Apply strict preset for SSH-key-only environments
    if args.strict:
        max_attempts_val = 1
        monitor_threshold_val = 1
        block_threshold_val = 5
        print("\n[WARNING] Strict mode enabled (SSH-key-only): Any password attempt will be flagged")
    else:
        max_attempts_val = config["max_attempts"]
        monitor_threshold_val = config["monitor_threshold"]
        block_threshold_val = config["block_threshold"]

    detector = BruteForceDetector(
        max_attempts=max_attempts_val,
        time_window_minutes=config["time_window_minutes"],
        block_threshold=block_threshold_val,
        monitor_threshold=monitor_threshold_val,
        summary_limit=summary_limit_val,
        verbose_limit=config["verbose_limit"]
    )
    # Apply color setting from config unless NO_COLOR env is set
    if os.environ.get('NO_COLOR'):
        detector.use_color = False
    else:
        detector.use_color = bool(config.get('color_enabled', True))

    # Live mode: follow file and periodically refresh summary
    if args.live:
        # Check for PID lock if blocklist is specified
        pid_file = None
        if args.export_blocklist:
            pid_file, existing_pid = check_pid_lock(args.export_blocklist)
            if existing_pid:
                print(f"\n[ERROR] Another analyzer instance (PID {existing_pid}) is already using this blocklist.")
                print(f"   Blocklist: {args.export_blocklist}")
                print(f"   Stop the other instance first, or use a different blocklist path.")
                sys.exit(1)
            
            # Check if blocklist exists and offer resume/clear
            if os.path.exists(args.export_blocklist):
                existing_ips = load_existing_blocklist(args.export_blocklist)
                if existing_ips:
                    print(f"\n[WARNING] Found existing blocklist with {len(existing_ips)} IPs: {args.export_blocklist}")
                    if args.non_interactive:
                        # In non-interactive mode (e.g., systemd service), resume by default
                        detector.written_ips = existing_ips
                        print(f"[OK] Resuming with {len(existing_ips)} existing IPs.")
                    else:
                        print("   [R]esume and append to it")
                        print("   [C]lear and start fresh")
                        print("   [A]bort")
                        choice = input("Choice (R/C/A): ").strip().upper()
                        if choice == 'A':
                            print("Aborted.")
                            sys.exit(0)
                        elif choice == 'C':
                            os.remove(args.export_blocklist)
                            print("Blocklist cleared.")
                        elif choice == 'R':
                            # Load existing IPs into detector's tracking set
                            detector.written_ips = existing_ips
                            print(f"Resuming with {len(existing_ips)} existing IPs.")
                        else:
                            print("Invalid choice. Aborting.")
                            sys.exit(1)
            
            # Create PID lock
            create_pid_lock(pid_file)
        
        print("\nLive mode: following log for new entries...")
        # Apply presets
        preset_filter = None
        preset_compact = False
        preset_refresh = None
        if args.quiet or (args.mode == 'soc'):
            preset_filter = 'HIGH'
            preset_compact = True
            preset_refresh = 5.0
        elif args.noisy or (args.mode == 'verbose'):
            preset_filter = None
            preset_compact = False
            preset_refresh = None

        # Resolve effective settings (CLI overrides presets)
        filter_sev = args.filter_severity if args.filter_severity else preset_filter
        compact_mode = bool(args.compact or preset_compact)
        refresh_interval = args.refresh if args.refresh else (preset_refresh if preset_refresh is not None else 5.0)

        # Startup hints
        if filter_sev:
            print(f"Filtering: showing only {filter_sev}+ threats (use -f LOW for all)")
        else:
            print("Filtering: none (use -f HIGH to reduce noise)")
        if compact_mode:
            print("Compact mode: event summaries disabled (omit --compact to show them)")
        else:
            print("Compact mode: off (add --compact to hide event summaries)")
        print(f"Refresh interval: {refresh_interval}s (use --refresh N to change)")
        print("Tip: Ctrl+C stops and prints a final summary\n")
        start_from_beginning = bool(args.follow_start)
        last_refresh = datetime.now()
        try:
            for line in follow_file(log_path, start_from_end=not start_from_beginning, poll_seconds=0.5):
                now = datetime.now()
                if (now - last_refresh).total_seconds() >= refresh_interval:
                    detector.analyze(verbose=False, export_csv=args.export_csv, filter_severity=filter_sev, compact=compact_mode, live_mode=True, export_blocklist=args.export_blocklist, blocklist_threshold=args.blocklist_threshold, whitelist=whitelist)
                    print("\n" * 5 + "=" * 100 + "\n" * 5)
                    last_refresh = now

                if not line:
                    continue
                line_attempts = parser.parse_line(line, auto_detect=True)
                for item in line_attempts:
                    if len(item) == 5:
                        ip, username, timestamp, success, event = item
                    else:
                        ip, username, timestamp, success = item
                        event = None
                    detector.add_attempt(ip, username, timestamp, success, event)
                # Update coverage from parser stats
                detector.coverage_start = parser.stats.get('first_timestamp')
                detector.coverage_end = parser.stats.get('last_timestamp')
        except KeyboardInterrupt:
            print("\nStopping live mode. Final summary:")
            detector.analyze(verbose=False, export_csv=args.export_csv, filter_severity=filter_sev, compact=compact_mode, live_mode=True, export_blocklist=args.export_blocklist, blocklist_threshold=args.blocklist_threshold, whitelist=whitelist)
        finally:
            # Clean up PID lock
            if pid_file:
                remove_pid_lock(pid_file)
        return

    # Batch mode: parse the log file
    print("Parsing log file...")
    t_parse_start = datetime.now()
    
    try:
        attempts, stats = parser.parse_file(log_path, auto_detect=True)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except PermissionError as e:
        print(f"Error: {e}")
        print("Try running with appropriate permissions (e.g., sudo)")
        sys.exit(1)
    except Exception as e:
        print(f"Error parsing log file: {e}")
        sys.exit(1)
    
    t_parse_end = datetime.now()
    
    print(f"\nProcessing stats:")
    print(f"Lines read: {stats['lines_read']}")
    print(f"Format matches: {stats['format_matches']}")
    print(f"Extract matches: {stats['extract_matches']}")
    print(f"Failed timestamps: {stats['failed_timestamps']}")
    
    if parser.get_detected_format():
        print(f"Detected format: {parser.get_detected_format()}")
    else:
        print("[WARNING] Could not auto-detect log format.")
        print("  This usually means:")
        print("    - The log file is in an unsupported format")
        print("    - The file is empty or corrupted")
        print("    - SSH logs are not present in this file")
        print("\n  Available formats:")
        for fmt in parser.list_formats():
            print(f"    - {fmt}")
        if stats['lines_read'] == 0:
            print("\n[ERROR] No lines were read. File may be empty or inaccessible.")
            sys.exit(1)
        elif stats['format_matches'] == 0:
            print("\n[ERROR] No SSH authentication events found in log file.")
            print("  Ensure this is the correct log file (e.g., /var/log/auth.log)")
            sys.exit(1)
    
    parse_elapsed = t_parse_end - t_parse_start
    print(f"Parse time: {parse_elapsed.total_seconds():.2f}s")
    print()
    
    # Add attempts to detector (supports optional event field)
    for item in attempts:
        if len(item) == 5:
            ip, username, timestamp, success, event = item
        else:
            ip, username, timestamp, success = item
            event = None
        detector.add_attempt(ip, username, timestamp, success, event)
    
    # Pass coverage timestamps from parser to detector for accurate window
    detector.coverage_start = stats.get('first_timestamp')
    detector.coverage_end = stats.get('last_timestamp')
    
    # Ask for verbosity and export (skip if non-interactive)
    if args.non_interactive:
        verbose = args.verbose
        export_csv = args.export_csv  # Use CLI arg if provided
    else:
        verbose_input = input("Show detailed breakdown? (y/n): ").strip().lower()
        verbose = verbose_input == 'y' or args.verbose
        
        # Only prompt for CSV if not already specified via CLI
        if args.export_csv:
            export_csv = args.export_csv
        else:
            export_input = input("Export to CSV? (y/n): ").strip().lower()
            export_csv = None
            if export_input == 'y':
                log_dir = os.path.dirname(log_path) or '.'
                export_csv = os.path.join(log_dir, 'brute_force_analysis.csv')
    
    t_analyze_start = datetime.now()
    # Apply CLI filters in batch mode too
    filter_sev = args.filter_severity if hasattr(args, 'filter_severity') else None
    compact_mode = bool(args.compact) if hasattr(args, 'compact') else False
    blocklist_path = args.export_blocklist if hasattr(args, 'export_blocklist') else None
    blocklist_thresh = args.blocklist_threshold if hasattr(args, 'blocklist_threshold') else 'HIGH'
    detector.analyze(verbose=verbose, export_csv=export_csv, filter_severity=filter_sev, compact=compact_mode, live_mode=False, export_blocklist=blocklist_path, blocklist_threshold=blocklist_thresh, whitelist=whitelist)
    t_analyze_end = datetime.now()
    analyze_elapsed = t_analyze_end - t_analyze_start
    print(f"\nAnalysis time: {analyze_elapsed.total_seconds():.2f}s")

if __name__ == "__main__":
    main()