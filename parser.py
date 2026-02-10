"""
Multi-format SSH log parser supporting common Linux distributions and log formats.

The parser attempts auto-detection on first match and tracks coverage
timestamps, basic match statistics, and per-line extraction using rules
defined in rules.py. It returns normalized attempts suitable for analysis.
"""
import re
import os
from datetime import datetime
from rules import PATTERNS
from utils import is_valid_ip
from typing import List, Tuple, Optional


class LogFormat:
    """Defines a log format with its patterns and parsing logic."""
    
    def __init__(self, name, main_pattern, extract_pattern, timestamp_extractor):
        self.name = name
        self.main_pattern = re.compile(main_pattern)
        self.extract_pattern = re.compile(extract_pattern)
        self.timestamp_extractor = timestamp_extractor
    
    def parse_timestamp(self, line):
        """Extract and parse timestamp from line."""
        return self.timestamp_extractor(line)


class SSHLogParser:
    """
    Parse SSH authentication logs across multiple formats.

    Tracks statistics including:
    - lines_read, format_matches, extract_matches, failed_timestamps
    - first_timestamp, last_timestamp
    """
    
    # Ubuntu/Debian format (ISO 8601 style)
    UBUNTU_FORMAT = LogFormat(
        name="Ubuntu/Debian (ISO 8601)",
        main_pattern=r'^\d{4}-\d{1,2}-\d{1,2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?\s+(?P<hostname>\S+)\s+(?P<process>\S+?)(?:\[\d+\]):\s+(?P<info>.*)$',
        extract_pattern=r'Invalid user (\S+) from ([\d.]+)',
        timestamp_extractor=lambda line: datetime.fromisoformat(line.split(' ', 1)[0].replace('Z', '+00:00'))
    )
    
    # CentOS/RHEL format (syslog style)
    CENTOS_FORMAT = LogFormat(
        name="CentOS/RHEL (syslog)",
        main_pattern=r'^(\w+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>sshd)(?:\[\d+\])?:\s+(?P<info>.*)$',
        extract_pattern=r'Invalid user (\S+) from ([\d.]+)',
        timestamp_extractor=lambda line: _parse_syslog_timestamp(line)
    )
    
    # Generic syslog format
    SYSLOG_FORMAT = LogFormat(
        name="Generic syslog",
        main_pattern=r'^(\w+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>\S+?)(?:\[\d+\])?:\s+(?P<info>.*)$',
        extract_pattern=r'Invalid user (\S+) from ([\d.]+)',
        timestamp_extractor=lambda line: _parse_syslog_timestamp(line)
    )
    
    # Systemd journald (JSON-like)
    JOURNALD_FORMAT = LogFormat(
        name="systemd journald",
        main_pattern=r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})\s+(?P<hostname>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<info>.*)$',
        extract_pattern=r'Invalid user (\S+) from ([\d.]+)',
        timestamp_extractor=lambda line: datetime.fromisoformat(line.split()[0])
    )
    
    # All formats in order of specificity (most specific first)
    FORMATS = [UBUNTU_FORMAT, JOURNALD_FORMAT, CENTOS_FORMAT, SYSLOG_FORMAT]
    
    def __init__(self):
        self.detected_format = None
        self.stats = {
            'lines_read': 0,
            'format_matches': 0,
            'extract_matches': 0,
            'failed_timestamps': 0,
            'first_timestamp': None,
            'last_timestamp': None
        }
    
    def parse_file(self, log_path: str, auto_detect: bool = True) -> Tuple[List[Tuple], dict]:
        """
        Parse a log file and extract SSH auth attempts.
        
        Args:
            log_path: Path to log file
            auto_detect: Auto-detect format (default True)
        
        Returns:
            Tuple of (attempts list, stats dict)
            Each attempt is (ip, username, timestamp, success)
        """        # Validate file exists and is readable
        if not os.path.exists(log_path):
            raise FileNotFoundError(f"Log file not found: {log_path}")
        
        if not os.path.isfile(log_path):
            raise ValueError(f"Path is not a file: {log_path}")
        
        if not os.access(log_path, os.R_OK):
            raise PermissionError(f"No read permission for: {log_path}")
        
        # Check if file is empty
        file_size = os.path.getsize(log_path)
        if file_size == 0:
            print(f"[WARNING] Log file is empty: {log_path}")
            return [], {
                'lines_read': 0,
                'format_matches': 0,
                'extract_matches': 0,
                'failed_timestamps': 0,
                'first_timestamp': None,
                'last_timestamp': None
            }
                # Reset detection for each parse to avoid stale formats across runs
        self.detected_format = None
        attempts = []
        # Reset stats at start, ensuring coverage keys exist
        self.stats = {
            'lines_read': 0,
            'format_matches': 0,
            'extract_matches': 0,
            'failed_timestamps': 0,
            'first_timestamp': None,
            'last_timestamp': None
        }
        
        with open(log_path, 'r', errors='ignore') as f:
            for line in f:
                self.stats['lines_read'] += 1
                
                # Auto-detect format on first match
                if self.detected_format is None and auto_detect:
                    for fmt in self.FORMATS:
                        if fmt.main_pattern.search(line):
                            self.detected_format = fmt
                            break
                
                if self.detected_format is None:
                    continue
                
                # Try to parse with detected format
                match = self.detected_format.main_pattern.search(line)
                if not match:
                    continue
                
                self.stats['format_matches'] += 1
                info = match.group('info')
                
                try:
                    timestamp = self.detected_format.parse_timestamp(line)
                except (ValueError, IndexError):
                    self.stats['failed_timestamps'] += 1
                    continue
                
                # Track coverage timestamps from any main match
                if self.stats['first_timestamp'] is None:
                    self.stats['first_timestamp'] = timestamp
                self.stats['last_timestamp'] = timestamp
                
                # Extract IP and username from info using format-specific or generic patterns
                if info:
                    # Try format-specific pattern first
                    extracted = False
                    fmt_match = self.detected_format.extract_pattern.search(info) if hasattr(self.detected_format, 'extract_pattern') and self.detected_format.extract_pattern else None
                    if fmt_match:
                        username = fmt_match.group(1)
                        ip = fmt_match.group(2)
                        if is_valid_ip(ip):
                            self.stats['extract_matches'] += 1
                            # Default event label for format-specific extractor
                            attempts.append((ip, username, timestamp, False, 'invalid_user'))
                            extracted = True
                    else:
                        # Fall back to generic patterns from rules
                        for p in PATTERNS:
                            m = p['regex'].search(info)
                            if m:
                                try:
                                    username = m.group('username') or '<unknown>'
                                except IndexError:
                                    username = '<unknown>'
                                ip = m.group('ip')
                                if is_valid_ip(ip):
                                    self.stats['extract_matches'] += 1
                                    attempts.append((ip, username, timestamp, p['success'], p['name']))
                                    extracted = True
                                break
        
        return attempts, self.stats
    
    def parse_line(self, line: str, auto_detect: bool = True) -> List[Tuple]:
        """Parse a single log line, updating stats and returning extracted attempts."""
        attempts = []
        self.stats['lines_read'] += 1
        
        # Auto-detect format on first match
        if self.detected_format is None and auto_detect:
            for fmt in self.FORMATS:
                if fmt.main_pattern.search(line):
                    self.detected_format = fmt
                    break
        
        if self.detected_format is None:
            return attempts
        
        # Try to parse with detected format
        match = self.detected_format.main_pattern.search(line)
        if not match:
            return attempts
        
        self.stats['format_matches'] += 1
        info = match.group('info')
        
        try:
            timestamp = self.detected_format.parse_timestamp(line)
        except (ValueError, IndexError):
            self.stats['failed_timestamps'] += 1
            return attempts
        
        # Track coverage timestamps from any main match
        if self.stats['first_timestamp'] is None:
            self.stats['first_timestamp'] = timestamp
        self.stats['last_timestamp'] = timestamp
        
        # Extract IP and username from info using format-specific or generic patterns
        if info:
            # Try format-specific pattern first
            fmt_match = self.detected_format.extract_pattern.search(info) if hasattr(self.detected_format, 'extract_pattern') and self.detected_format.extract_pattern else None
            if fmt_match:
                username = fmt_match.group(1)
                ip = fmt_match.group(2)
                if is_valid_ip(ip):
                    self.stats['extract_matches'] += 1
                    attempts.append((ip, username, timestamp, False, 'invalid_user'))
            else:
                # Fall back to generic patterns from rules
                for p in PATTERNS:
                    m = p['regex'].search(info)
                    if m:
                        try:
                            username = m.group('username') or '<unknown>'
                        except IndexError:
                            username = '<unknown>'
                        ip = m.group('ip')
                        if is_valid_ip(ip):
                            self.stats['extract_matches'] += 1
                            attempts.append((ip, username, timestamp, p['success'], p['name']))
                        break
        
        return attempts
    
    def set_format(self, format_name: str) -> bool:
        """
        Manually set log format by name.
        
        Returns:
            True if format found, False otherwise
        """
        for fmt in self.FORMATS:
            if fmt.name.lower() == format_name.lower():
                self.detected_format = fmt
                return True
        return False
    
    def list_formats(self) -> List[str]:
        """List available log formats."""
        return [fmt.name for fmt in self.FORMATS]
    
    def get_detected_format(self) -> Optional[str]:
        """Get name of detected format, or None if not detected yet."""
        return self.detected_format.name if self.detected_format else None


def _parse_syslog_timestamp(line: str) -> datetime:
    """
    Parse syslog-style timestamp (no year, current year assumed).
    
    Handles year rollover: if the log month is ahead of current month,
    assumes the entry is from the previous year (e.g., Dec logs read in Jan).
    
    Validates day, hour, minute, second ranges to reject garbage data.
    """
    parts = line.split()
    if len(parts) < 3:
        raise ValueError("Invalid syslog timestamp: not enough fields")
    
    month_str = parts[0]
    day_str = parts[1]
    time_str = parts[2]
    
    # Month names
    months = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
        'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }
    
    month = months.get(month_str)
    if month is None:
        raise ValueError(f"Invalid month: {month_str}")
    
    try:
        day = int(day_str)
    except ValueError:
        raise ValueError(f"Invalid day: {day_str}")
    
    time_parts = time_str.split(':')
    if len(time_parts) != 3:
        raise ValueError(f"Invalid time format: {time_str}")
    
    try:
        hour, minute, second = int(time_parts[0]), int(time_parts[1]), int(time_parts[2])
    except ValueError:
        raise ValueError(f"Invalid time components: {time_str}")
    
    # Validate ranges (datetime constructor will also catch, but explicit is better)
    if not (1 <= day <= 31 and 0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59):
        raise ValueError(f"Time/date values out of range: day={day}, time={hour}:{minute}:{second}")
    
    now = datetime.now()
    year = now.year
    # Handle year rollover: if log month is ahead of current month, assume previous year
    if month > now.month:
        year = year - 1
    
    return datetime(year, month, day, hour, minute, second)
