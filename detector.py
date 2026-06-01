"""
Brute-force detection and reporting.

`BruteForceDetector` aggregates SSH auth attempts per IP, classifies each
IP's severity, prints a terminal summary, and optionally exports CSV results
and a fail2ban-style blocklist.
"""
import csv
import ipaddress
import os
import shutil
from collections import defaultdict
from datetime import datetime, timedelta

from utils import is_valid_ip


# Localhost whitelist — these IPs are ALWAYS excluded from blocklists for
# safety, to prevent accidental self-lockout via fail2ban integration.
LOCALHOST_WHITELIST = {
    '127.0.0.1',
    '::1',
}

PRIVATE_NETWORK_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
]


def is_localhost_or_private(ip_str):
    """Return True if `ip_str` is localhost or in a private network range.

    These addresses are always excluded from blocklists to avoid self-lockout.
    """
    if ip_str in LOCALHOST_WHITELIST:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for network in PRIVATE_NETWORK_RANGES:
            if ip_obj in network:
                return True
    except ValueError:
        pass
    return False


class BruteForceDetector:
    """
    Detects and summarizes brute-force behaviour in SSH authentication logs.

    See `analyze()` for the main entry point.
    """

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    VALID_SEVERITIES = frozenset(SEVERITY_ORDER)

    def __init__(self, max_attempts=5, time_window_minutes=10, block_threshold=50,
                 monitor_threshold=20, summary_limit=20, verbose_limit=10):
        self.max_attempts = max(0, int(max_attempts)) if max_attempts is not None else 5
        time_window_minutes = max(0, float(time_window_minutes)) if time_window_minutes is not None else 10
        self.time_window = timedelta(minutes=time_window_minutes)
        self.block_threshold = max(0, int(block_threshold)) if block_threshold is not None else 50
        self.monitor_threshold = max(0, int(monitor_threshold)) if monitor_threshold is not None else 20
        self.summary_limit = max(1, int(summary_limit)) if summary_limit is not None else 20
        self.verbose_limit = max(1, int(verbose_limit)) if verbose_limit is not None else 10
        self.use_color = not os.environ.get('NO_COLOR')
        self.attempts_by_ip = defaultdict(list)
        self.written_ips = set()

    def _color(self, text, fg=None, bold=False):
        """Return `text` decorated with ANSI color codes when enabled."""
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
        """Neutralize spreadsheet formula execution by prefixing dangerous leading chars."""
        if isinstance(value, str) and value and value[0] in ('=', '+', '-', '@', '\t', '\r', '\f'):
            return "'" + value
        return value

    def add_attempt(self, ip_address, username, timestamp, success, event=None):
        """Record a single SSH auth attempt parsed from the logs."""
        if not ip_address or not is_valid_ip(str(ip_address)):
            return
        if not isinstance(timestamp, datetime):
            return
        username = str(username) if username is not None else "<unknown>"
        self.attempts_by_ip[ip_address].append({
            "username": username,
            "timestamp": timestamp,
            "success": bool(success),
            "event": event,
        })

    def classify_threat(self, total_attempts, attack_rate, duration):
        """Classify threat severity from aggregate metrics."""
        if total_attempts >= self.max_attempts and duration <= self.time_window and attack_rate >= 2.0:
            return "CRITICAL"
        elif total_attempts >= self.max_attempts and duration <= self.time_window:
            return "HIGH"
        elif total_attempts >= self.block_threshold:
            return "HIGH"
        elif total_attempts >= self.monitor_threshold:
            return "MEDIUM"
        elif attack_rate > 1.0:
            return "MEDIUM"
        elif total_attempts >= self.max_attempts:
            return "LOW"
        return "LOW"

    def format_duration(self, delta):
        """Format a `timedelta` as a compact human-readable string."""
        total_seconds = int(abs(delta.total_seconds()))
        hours, remainder = divmod(total_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours:
            return f"{hours}h {minutes}m {seconds}s"
        return f"{minutes}m {seconds}s"

    def _compute_metrics(self, attempts, total_attempts):
        """Return (attack_rate, duration, first, last) for a set of attempts.

        Returns (0, timedelta(0), None, None) if no valid timestamps exist.
        """
        if not attempts:
            return 0.0, timedelta(0), None, None
        timestamps = [att['timestamp'] for att in attempts if isinstance(att.get('timestamp'), datetime)]
        if not timestamps:
            return 0.0, timedelta(0), None, None
        first = min(timestamps)
        last = max(timestamps)
        duration = last - first
        # 1-minute floor prevents inflated rates from tiny time windows
        total_minutes = max(duration.total_seconds() / 60, 1.0)
        return total_attempts / total_minutes, duration, first, last

    def analyze(self, verbose=False, export_csv=None, filter_severity=None, compact=False,
                live_mode=False, export_blocklist=None, blocklist_threshold='HIGH', whitelist=None):
        """Aggregate attempts, compute severity, and render summaries."""
        summary = defaultdict(lambda: defaultdict(int))
        whitelist = whitelist or set()

        if blocklist_threshold not in self.VALID_SEVERITIES:
            print(f"[WARNING] Invalid blocklist_threshold '{blocklist_threshold}', defaulting to HIGH")
            blocklist_threshold = "HIGH"
        if filter_severity is not None and filter_severity not in self.VALID_SEVERITIES:
            print(f"[WARNING] Invalid filter_severity '{filter_severity}', ignoring filter")
            filter_severity = None

        for ip, attempts in self.attempts_by_ip.items():
            for attempt in attempts:
                if not attempt.get('success', False):
                    summary[ip][attempt['username']] += 1

        # Pre-compute threat scores so we can sort by (severity, attempt count)
        threat_scores = {}
        for ip, usernames in summary.items():
            total_attempts = sum(usernames.values())
            attack_rate, duration, _, _ = self._compute_metrics(self.attempts_by_ip[ip], total_attempts)
            threat_level = self.classify_threat(total_attempts, attack_rate, duration)
            threat_scores[ip] = (self.SEVERITY_ORDER[threat_level], -total_attempts)

        sorted_ips = sorted(summary.items(), key=lambda x: threat_scores[x[0]])

        # Decide which IPs will be blocked (drives the "BLOCKED" action label)
        blocked_ips_display = set()
        if export_blocklist:
            severity_threshold = self.SEVERITY_ORDER[blocklist_threshold]
            for ip, usernames in sorted_ips:
                total_attempts = sum(usernames.values())
                attack_rate, duration, first, _ = self._compute_metrics(self.attempts_by_ip[ip], total_attempts)
                if first is None:
                    continue
                threat_level = self.classify_threat(total_attempts, attack_rate, duration)
                if (self.SEVERITY_ORDER[threat_level] <= severity_threshold
                        and ip not in whitelist
                        and not is_localhost_or_private(ip)):
                    blocked_ips_display.add(ip)

        # Build the full result table
        all_results = []
        for ip, usernames in sorted_ips:
            total_attempts = sum(usernames.values())
            attack_rate, duration, first, last = self._compute_metrics(self.attempts_by_ip[ip], total_attempts)
            if first is None:
                continue
            threat_level = self.classify_threat(total_attempts, attack_rate, duration)

            if ip in blocked_ips_display:
                action = "BLOCKED"
            elif threat_level in ("CRITICAL", "HIGH"):
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
                'Window_End': last.isoformat(),
            })

        # Overall coverage stats
        all_timestamps = []
        total_parsed_attempts = 0
        for attempts in self.attempts_by_ip.values():
            total_parsed_attempts += len(attempts)
            all_timestamps.extend(att['timestamp'] for att in attempts if isinstance(att.get('timestamp'), datetime))
        ip_count = len(self.attempts_by_ip)

        term_width = shutil.get_terminal_size((80, 20)).columns
        line_width = min(term_width, 100)

        print("\n" + "=" * line_width)
        print(self._color("LOG COVERAGE", bold=True))
        print("=" * line_width)
        coverage_start = getattr(self, 'coverage_start', None)
        coverage_end = getattr(self, 'coverage_end', None)
        if not coverage_start or not coverage_end:
            if all_timestamps:
                coverage_start = min(all_timestamps)
                coverage_end = max(all_timestamps)

        if coverage_start and coverage_end:
            coverage_duration = coverage_end - coverage_start
            coverage_str = self.format_duration(coverage_duration)
            print(f"Window: {coverage_start.strftime('%Y-%m-%d %H:%M:%S')} to "
                  f"{coverage_end.strftime('%Y-%m-%d %H:%M:%S')} ({coverage_str})")
            print(f"Parsed IPs: {ip_count:,} | Attempts: {total_parsed_attempts:,}")
        else:
            print("No parsed attempts found.")

        # Event summaries
        if not compact:
            print("\n" + "=" * line_width)
            print(self._color("EVENT SUMMARIES", bold=True))
            print("=" * line_width)

            invalid_counts = defaultdict(int)
            for ip, attempts in self.attempts_by_ip.items():
                for att in attempts:
                    if att.get('event') == 'invalid_user':
                        invalid_counts[ip] += 1
            if invalid_counts:
                top_invalid = sorted(invalid_counts.items(), key=lambda x: x[1], reverse=True)[:max(1, self.summary_limit // 2)]
                print(self._color(f"Invalid user attempts (top {len(top_invalid)}):", fg='cyan', bold=True))
                for ip, cnt in top_invalid:
                    print(f"  {ip:<18} {cnt:>7,} events")
            else:
                print("No invalid user events detected.")

            accepted_counts = defaultdict(int)
            for ip, attempts in self.attempts_by_ip.items():
                for att in attempts:
                    if att.get('success') is True:
                        accepted_counts[ip] += 1
            if accepted_counts:
                top_accepted = sorted(accepted_counts.items(), key=lambda x: x[1], reverse=True)[:max(1, self.summary_limit // 2)]
                print(self._color(f"Accepted password events (top {len(top_accepted)}):", fg='green', bold=True))
                for ip, cnt in top_accepted:
                    print(f"  {ip:<18} {cnt:>7,} events")
            else:
                print("No accepted password events detected.")

        # Threat summary
        print("\n" + "=" * line_width)
        print(self._color("THREAT ANALYSIS SUMMARY", bold=True))
        print("=" * line_width)

        display_results = all_results
        if filter_severity:
            threshold = self.SEVERITY_ORDER[filter_severity]
            display_results = [r for r in all_results if self.SEVERITY_ORDER[r['Severity']] <= threshold]
            display_results = sorted(
                display_results,
                key=lambda x: (self.SEVERITY_ORDER[x['Severity']], -int(x['Attempts'])),
            )
        hidden_count = len(all_results) - len(display_results)

        print(f"{'SEVERITY':<12} {'IP ADDRESS':<18} {'ATTEMPTS':<12} {'RATE':<12} {'ACTION':<12}")
        print("-" * line_width)

        sev_col = {
            'CRITICAL': ('red', True),
            'HIGH': ('yellow', True),
            'MEDIUM': ('cyan', False),
            'LOW': (None, False),
        }
        action_col = {'BLOCKED': 'red', 'BLOCK': 'red', 'MONITOR': 'yellow', 'ALLOW': 'green'}

        for i, r in enumerate(display_results):
            fg, bold = sev_col.get(r['Severity'], (None, False))
            sev_text = self._color(r['Severity'], fg=fg, bold=bold)
            rate_val = float(r['Attack_Rate'])
            action = r['Action']
            action_text = self._color(action, fg=action_col.get(action), bold=action != 'ALLOW')
            print(f"{sev_text:<12} {r['IP']:<18} {r['Attempts']:>12,} {rate_val:>6.2f}/min {action_text:<12}")
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
        suspicious_ips = [r for r in display_results if r['Severity'] != 'LOW']
        print(f"Total suspicious IPs: {len(suspicious_ips):,}")

        if export_blocklist:
            blocked_count = len(blocked_ips_display)
            if blocked_count > 0:
                blocklist_msg = f"Blocklist: {blocked_count} IP(s) marked for blocking ({blocklist_threshold}+ severity)"
                print(self._color(blocklist_msg, fg='red', bold=True))
            else:
                print(self._color(f"Blocklist: No IPs meet {blocklist_threshold}+ threshold yet", fg='yellow'))

        # Verbose breakdown
        if verbose:
            print("\n" + "=" * line_width)
            print(self._color(f"DETAILED BREAKDOWN (Top {self.verbose_limit})", bold=True))
            print("=" * line_width)
            allowed_ips = {r['IP'] for r in display_results}
            for i, (ip, usernames) in enumerate(sorted_ips):
                if ip not in allowed_ips:
                    continue
                if i >= self.verbose_limit:
                    break
                total_attempts = sum(usernames.values())
                attack_rate, duration, first, last = self._compute_metrics(self.attempts_by_ip[ip], total_attempts)
                if first is None:
                    continue
                duration_str = self.format_duration(duration)
                print(f"\n[IP] {ip}")
                print(f"  Attempts: {total_attempts:,}")
                print(f"  Attack rate: {attack_rate:.2f} attempts/minute")
                print(f"  Targeted users: {', '.join(usernames.keys())}")
                print(f"  Window: {first.strftime('%Y-%m-%d %H:%M:%S')} to {last.strftime('%H:%M:%S')} ({duration_str})")
                print("-" * line_width)

        # CSV export (with formula injection sanitization)
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

        # Blocklist export (append-only)
        if export_blocklist and all_results:
            threshold = self.SEVERITY_ORDER[blocklist_threshold]
            blocked_ips = [r['IP'] for r in all_results if self.SEVERITY_ORDER[r['Severity']] <= threshold]
            blocked_ips = [ip for ip in blocked_ips if ip not in whitelist]
            blocked_ips = [ip for ip in blocked_ips if not is_localhost_or_private(ip)]
            new_ips = [ip for ip in blocked_ips if ip not in self.written_ips]

            if new_ips:
                try:
                    with open(export_blocklist, 'a') as f:
                        for ip in new_ips:
                            f.write(f"{ip}\n")
                            self.written_ips.add(ip)
                    total_in_blocklist = len(self.written_ips)
                    msg = f"[OK] Blocklist updated: {export_blocklist} (+{len(new_ips)} new | {total_in_blocklist} total)"
                    print(self._color(msg, fg='green', bold=True))
                except Exception as e:
                    print(f"[ERROR] Failed to update blocklist: {e}")

        return all_results
