"""
SSHVigil - Lightweight SSH brute-force detection.

CLI entry point: parses arguments, wires together the parser, detector, and
optional integrations (fail2ban / systemd / live monitoring), then prints
a summary or runs continuously.

Heavy lifting lives in:
- detector.py      → BruteForceDetector class
- parser.py        → SSH log parsing
- state.py         → PID locks, blocklist/whitelist I/O
- integrations.py  → fail2ban configs, systemd install, helper script gen
"""
import argparse
import os
import sys
from datetime import datetime

from config import Config
from detector import BruteForceDetector
from integrations import (
    generate_fail2ban_script,
    install_systemd_service,
    setup_fail2ban_integration,
)
from models import __version__
from parser import SSHLogParser
from state import (
    check_pid_lock,
    create_pid_lock,
    load_existing_blocklist,
    load_whitelist,
    remove_pid_lock,
)
from utils import follow_file


def _build_argparser():
    argp = argparse.ArgumentParser(
        description="SSHVigil - SSH Brute Force Detection & Defense",
        epilog=(
            "Examples:\n"
            "  python3 main.py --log-file /var/log/auth.log --live -f HIGH --compact --refresh 10\n"
            "  python3 main.py --log-file /var/log/auth.log --live --mode soc\n"
            "  python3 main.py --log-file /var/log/auth.log --live --follow-start --summary-limit 10\n"
            "  python3 main.py --log-file /var/log/auth.log --live --mode verbose\n"
        ),
    )
    argp.add_argument("--version", "-V", action="version", version=f"SSHVigil v{__version__}")
    argp.add_argument("--log-file", dest="log_file", help="Path to auth/secure log file")
    argp.add_argument("--summary-limit", dest="summary_limit", type=int, help="Max rows to show in terminal summary")
    argp.add_argument("--live", dest="live", action="store_true", help="Follow the log file and analyze in real-time")
    argp.add_argument("--follow-start", dest="follow_start", action="store_true", help="Start live mode from the beginning of the file")
    argp.add_argument("--refresh", dest="refresh", type=float, help="Seconds between summary refresh in live mode")
    argp.add_argument("--filter-severity", "-f", dest="filter_severity",
                      choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                      help="Only show threats at or above this severity level")
    argp.add_argument("--verbose", dest="verbose", action="store_true", help="Show detailed event breakdown")
    argp.add_argument("--compact", dest="compact", action="store_true", help="Skip event summaries, show only threat table")
    argp.add_argument("--quiet", dest="quiet", action="store_true", help="Preset: HIGH+ filter, compact output, 5s refresh")
    argp.add_argument("--noisy", dest="noisy", action="store_true", help="Preset: show everything (no filter, no compact)")
    argp.add_argument("--strict", dest="strict", action="store_true",
                      help="Preset: SSH-key-only mode (max_attempts=1, flags any password attempt)")
    argp.add_argument("--mode", dest="mode", choices=['soc', 'verbose'],
                      help="Preset: soc (HIGH+ compact fast refresh) or verbose (full detail)")
    argp.add_argument("--export-blocklist", dest="export_blocklist",
                      help="Export IPs to blocklist file (one per line) for iptables/fail2ban")
    argp.add_argument("--blocklist-threshold", dest="blocklist_threshold",
                      choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], default='HIGH',
                      help="Minimum severity for blocklist (default: HIGH)")
    argp.add_argument("--generate-fail2ban-script", dest="generate_fail2ban_script",
                      help="Generate a ready-to-run fail2ban updater script at this path and exit")
    argp.add_argument("--script-blocklist-path", dest="script_blocklist_path",
                      help="Blocklist path to embed in generated fail2ban script (default: /var/lib/sshvigil/blocklist.txt)")
    argp.add_argument("--setup-fail2ban", dest="setup_fail2ban", action="store_true",
                      help="Auto-create fail2ban jail and filter configs, then restart fail2ban (requires sudo)")
    argp.add_argument("--install-service", dest="install_service", action="store_true",
                      help="Install SSHvigil as a systemd service for live monitoring (requires sudo)")
    argp.add_argument("--export-csv", dest="export_csv",
                      help="Export results to CSV file (works in both live and batch mode)")
    argp.add_argument("--non-interactive", dest="non_interactive", action="store_true",
                      help="Suppress prompts for automation (batch mode will skip verbose/export questions)")
    argp.add_argument("--whitelist", dest="whitelist",
                      help="Path to whitelist file (one IP per line) to exclude from blocklist")
    return argp


def _resolve_log_path(args):
    """Pick the log file from --log-file, a GUI picker, or common fallbacks."""
    if args.live or args.log_file:
        log_path = args.log_file
    else:
        try:
            import tkinter as tk
            from tkinter import filedialog
            tk.Tk().withdraw()
            log_path = filedialog.askopenfilename(
                title="Select your auth.log file",
                filetypes=[("Log files", "*.log"), ("All files", "*.*")],
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

    if not os.path.exists(log_path):
        print(f"Error: Log file not found: {log_path}")
        if not args.log_file:
            for candidate in ("/var/log/auth.log", "/var/log/secure", "auth.log"):
                if os.path.exists(candidate):
                    print(f"Found log file at: {candidate}")
                    if input("Use this file? (y/n): ").strip().lower() == 'y':
                        return candidate
            print("\nError: No common auth.log file found.")
            print("Please specify the path with --log-file")
        sys.exit(1)

    if not os.path.isfile(log_path):
        print(f"Error: Path is not a file: {log_path}")
        sys.exit(1)
    if not os.access(log_path, os.R_OK):
        print(f"Error: No read permission for: {log_path}")
        print("Try running with appropriate permissions (e.g., sudo)")
        sys.exit(1)
    return log_path


def _build_detector(args, config):
    """Construct a BruteForceDetector from config + CLI overrides."""
    summary_limit_val = args.summary_limit if args.summary_limit else config["summary_limit"]

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
        verbose_limit=config["verbose_limit"],
    )
    if os.environ.get('NO_COLOR'):
        detector.use_color = False
    else:
        detector.use_color = bool(config.get('color_enabled', True))
    return detector


def _resolve_live_settings(args):
    """Resolve filter/compact/refresh from presets and CLI overrides."""
    preset_filter, preset_compact, preset_refresh = None, False, None
    if args.quiet or args.mode == 'soc':
        preset_filter, preset_compact, preset_refresh = 'HIGH', True, 5.0
    elif args.noisy or args.mode == 'verbose':
        preset_filter, preset_compact, preset_refresh = None, False, None

    filter_sev = args.filter_severity or preset_filter
    compact_mode = bool(args.compact or preset_compact)
    refresh_interval = args.refresh or (preset_refresh if preset_refresh is not None else 5.0)
    return filter_sev, compact_mode, refresh_interval


def _add_parsed_attempts(detector, attempts):
    """Feed parsed attempt tuples (4- or 5-element) into the detector."""
    for item in attempts:
        if len(item) == 5:
            ip, username, timestamp, success, event = item
        else:
            ip, username, timestamp, success = item
            event = None
        detector.add_attempt(ip, username, timestamp, success, event)


def _handle_existing_blocklist(detector, args):
    """Prompt to resume/clear/abort if blocklist already has IPs."""
    existing_ips = load_existing_blocklist(args.export_blocklist)
    if not existing_ips:
        return
    print(f"\n[WARNING] Found existing blocklist with {len(existing_ips)} IPs: {args.export_blocklist}")
    if args.non_interactive:
        detector.written_ips = existing_ips
        print(f"[OK] Resuming with {len(existing_ips)} existing IPs.")
        return
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
        detector.written_ips = existing_ips
        print(f"Resuming with {len(existing_ips)} existing IPs.")
    else:
        print("Invalid choice. Aborting.")
        sys.exit(1)


def _run_live(detector, parser, log_path, args, whitelist):
    """Live mode: follow the file and refresh the summary at intervals."""
    pid_file = None
    if args.export_blocklist:
        pid_file, existing_pid = check_pid_lock(args.export_blocklist)
        if existing_pid:
            print(f"\n[ERROR] Another analyzer instance (PID {existing_pid}) is already using this blocklist.")
            print(f"   Blocklist: {args.export_blocklist}")
            print(f"   Stop the other instance first, or use a different blocklist path.")
            sys.exit(1)
        if os.path.exists(args.export_blocklist):
            _handle_existing_blocklist(detector, args)
        create_pid_lock(pid_file)

    print("\nLive mode: following log for new entries...")
    filter_sev, compact_mode, refresh_interval = _resolve_live_settings(args)

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
                detector.analyze(
                    verbose=False, export_csv=args.export_csv, filter_severity=filter_sev,
                    compact=compact_mode, live_mode=True,
                    export_blocklist=args.export_blocklist,
                    blocklist_threshold=args.blocklist_threshold, whitelist=whitelist,
                )
                print("\n" * 5 + "=" * 100 + "\n" * 5)
                last_refresh = now

            if not line:
                continue
            _add_parsed_attempts(detector, parser.parse_line(line, auto_detect=True))
            detector.coverage_start = parser.stats.get('first_timestamp')
            detector.coverage_end = parser.stats.get('last_timestamp')
    except KeyboardInterrupt:
        print("\nStopping live mode. Final summary:")
        detector.analyze(
            verbose=False, export_csv=args.export_csv, filter_severity=filter_sev,
            compact=compact_mode, live_mode=True,
            export_blocklist=args.export_blocklist,
            blocklist_threshold=args.blocklist_threshold, whitelist=whitelist,
        )
    finally:
        if pid_file:
            remove_pid_lock(pid_file)


def _run_batch(detector, parser, log_path, args, whitelist):
    """Batch mode: parse the whole file once, then analyze."""
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

    print(f"Parse time: {(t_parse_end - t_parse_start).total_seconds():.2f}s")
    print()

    _add_parsed_attempts(detector, attempts)
    detector.coverage_start = stats.get('first_timestamp')
    detector.coverage_end = stats.get('last_timestamp')

    if args.non_interactive:
        verbose = args.verbose
        export_csv = args.export_csv
    else:
        verbose = input("Show detailed breakdown? (y/n): ").strip().lower() == 'y' or args.verbose
        if args.export_csv:
            export_csv = args.export_csv
        else:
            export_csv = None
            if input("Export to CSV? (y/n): ").strip().lower() == 'y':
                log_dir = os.path.dirname(log_path) or '.'
                export_csv = os.path.join(log_dir, 'brute_force_analysis.csv')

    t_analyze_start = datetime.now()
    detector.analyze(
        verbose=verbose, export_csv=export_csv, filter_severity=args.filter_severity,
        compact=bool(args.compact), live_mode=False,
        export_blocklist=args.export_blocklist,
        blocklist_threshold=args.blocklist_threshold, whitelist=whitelist,
    )
    print(f"\nAnalysis time: {(datetime.now() - t_analyze_start).total_seconds():.2f}s")


def main():
    """Entry point: parse CLI args, dispatch to live or batch mode."""
    args = _build_argparser().parse_args()
    print(f"SSHVigil v{__version__} - SSH Brute Force Analyzer")
    print("=" * 40)

    log_path = _resolve_log_path(args)
    print(f"Using log file: {log_path}")

    # One-shot integrations: do the thing and exit
    if args.setup_fail2ban:
        setup_fail2ban_integration(args.export_blocklist or "/var/lib/sshvigil/blocklist.txt")
        sys.exit(0)
    if args.install_service:
        install_systemd_service(
            log_path=log_path,
            blocklist_path=args.export_blocklist or "/var/lib/sshvigil/blocklist.txt",
            threshold=args.blocklist_threshold,
            whitelist_path=args.whitelist,
        )
        sys.exit(0)
    if args.generate_fail2ban_script:
        generate_fail2ban_script(
            script_path=args.generate_fail2ban_script,
            log_path=log_path,
            blocklist_path=args.script_blocklist_path or "/var/lib/sshvigil/blocklist.txt",
            threshold=args.blocklist_threshold,
            whitelist_path=args.whitelist,
        )
        sys.exit(0)

    whitelist = load_whitelist(args.whitelist) if args.whitelist else set()
    config = Config()
    parser = SSHLogParser()
    detector = _build_detector(args, config)

    if args.live:
        _run_live(detector, parser, log_path, args, whitelist)
    else:
        _run_batch(detector, parser, log_path, args, whitelist)


if __name__ == "__main__":
    main()
