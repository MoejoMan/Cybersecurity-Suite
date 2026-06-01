"""
Runtime state helpers: PID locks, blocklist/whitelist file I/O.

These are small file-level helpers that don't belong inside the detector
class but aren't pure utilities either (they touch /tmp, the filesystem,
and the running process).
"""
import hashlib
import os

from utils import is_valid_ip


WHITELIST_MAX_BYTES = 10 * 1024 * 1024  # 10 MB cap to prevent memory exhaustion


def is_process_running(pid):
    """Check if a process with given PID is still running (cross-platform)."""
    if os.name == 'nt':
        try:
            import psutil  # type: ignore[import]
            return psutil.pid_exists(pid)
        except ImportError:
            # psutil not available on Windows; assume process is running to be safe
            return True
        except Exception:
            return False
    try:
        os.kill(pid, 0)  # Signal 0: check if process exists
        return True
    except OSError:
        return False


def check_pid_lock(blocklist_path):
    """Check if another analyzer instance is using this blocklist.

    Returns (pid_file_path, existing_pid_or_None). If the recorded PID is
    no longer alive, the stale lock file is removed.
    """
    lock_hash = hashlib.md5(blocklist_path.encode()).hexdigest()[:8]
    pid_dir = os.path.expandvars(r'%TEMP%') if os.name == 'nt' else '/tmp'
    pid_file = os.path.join(pid_dir, f'ssh-analyzer-{lock_hash}.pid')

    if os.path.exists(pid_file):
        with open(pid_file, 'r') as f:
            try:
                pid = int(f.read().strip())
                if is_process_running(pid):
                    return pid_file, pid
                os.remove(pid_file)
            except (OSError, ValueError):
                try:
                    os.remove(pid_file)
                except OSError:
                    pass
    return pid_file, None


def create_pid_lock(pid_file):
    """Create PID lock file containing the current process's PID."""
    with open(pid_file, 'w') as f:
        f.write(str(os.getpid()))


def remove_pid_lock(pid_file):
    """Remove PID lock file on exit; ignores errors."""
    try:
        if os.path.exists(pid_file):
            os.remove(pid_file)
    except Exception:
        pass


def load_existing_blocklist(blocklist_path):
    """Load existing IPs from a blocklist file (returns set; missing file → empty)."""
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


def load_whitelist(whitelist_path):
    """Load whitelisted IPs from file (capped at WHITELIST_MAX_BYTES)."""
    whitelist = set()
    if not whitelist_path:
        return whitelist

    try:
        size = os.path.getsize(whitelist_path)
        if size > WHITELIST_MAX_BYTES:
            print(f"[WARNING] Whitelist file too large ({size} bytes > {WHITELIST_MAX_BYTES}); refusing to load.")
            return whitelist
        with open(whitelist_path, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith('#') and is_valid_ip(ip):
                    whitelist.add(ip)
        print(f"[OK] Loaded {len(whitelist)} whitelisted IPs from {whitelist_path}")
    except FileNotFoundError:
        print(f"[WARNING] Whitelist file not found: {whitelist_path}")
    except Exception as e:
        print(f"[WARNING] Error loading whitelist: {e}")

    return whitelist
