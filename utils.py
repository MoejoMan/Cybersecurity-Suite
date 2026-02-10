"""
Minimal utility helpers placeholder.

We'll add small, reusable functions here over time (e.g., formatting,
color helpers, CSV export), keeping this module lightweight.
"""

import os
import time
import ipaddress
from typing import Iterator, Optional


def is_valid_ip(ip_str: str) -> bool:
    """
    Validate if a string is a valid IPv4 or IPv6 address.
    
    Args:
        ip_str: String to validate
        
    Returns:
        True if valid IP, False otherwise
    """
    if not ip_str or not isinstance(ip_str, str):
        return False
    # Quick reject for obviously invalid strings (CIDR notation, etc.)
    if '/' in ip_str:
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except (ValueError, TypeError):
        return False


def follow_file(path: str, start_from_end: bool = True, poll_seconds: float = 0.5) -> Iterator[Optional[str]]:
    """
    Yield new lines appended to `path` in a loop, similar to `tail -f`.
    Handles simple truncation/rotation by reopening when file size shrinks
    or the path temporarily disappears. Emits `None` during idle periods so
    callers can still run periodic tasks (heartbeats/refreshes).
    """
    # Clamp poll_seconds to sane range
    poll_seconds = max(0.1, min(float(poll_seconds), 60.0))
    
    while True:
        try:
            with open(path, 'r', errors='ignore') as f:
                if start_from_end:
                    f.seek(0, os.SEEK_END)
                else:
                    f.seek(0)
                try:
                    last_size = os.path.getsize(path)
                except OSError:
                    last_size = 0
                while True:
                    line = f.readline()
                    if line:
                        yield line
                    else:
                        time.sleep(poll_seconds)
                        yield None
                        try:
                            current_size = os.path.getsize(path)
                            if current_size < last_size:
                                # truncated or rotated; reopen
                                break
                            last_size = current_size
                        except OSError:
                            # path missing or inaccessible; retry outer loop
                            time.sleep(poll_seconds)
                            break
        except FileNotFoundError:
            time.sleep(poll_seconds)
            continue
        except PermissionError:
            time.sleep(poll_seconds)
            continue

