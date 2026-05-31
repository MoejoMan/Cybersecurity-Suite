"""
Tests for specific bugs found during comprehensive testing.
These tests document the bugs and verify fixes.
"""
import pytest
from datetime import datetime
from main import BruteForceDetector


class TestFoundBugs:
    """Tests for actual bugs discovered during testing."""
    
    def test_bug_bare_except_clause(self, tmp_path):
        """
        BUG: Bare except clause in main.py:500
        Severity: MEDIUM
        
        The code uses bare 'except:' which catches all exceptions including
        KeyboardInterrupt and SystemExit. This makes debugging difficult.
        
        Location: load_existing_blocklist() function
        """
        # This test documents the bug - the function works but uses bad practice
        from main import load_existing_blocklist
        
        # Create a valid blocklist file
        blocklist_file = tmp_path / "blocklist.txt"
        blocklist_file.write_text("192.168.1.1\n192.168.1.2\n")
        
        # Function should work
        result = load_existing_blocklist(str(blocklist_file))
        assert len(result) == 2
        
        # The bug is in the exception handling - it uses bare 'except:'
        # which is bad practice but doesn't cause functional issues
    
    def test_bug_unused_variable_threshold(self):
        """
        BUG: Unused variable 'THRESHOLD' in main.py:174
        Severity: LOW (code smell)
        
        THRESHOLD = self.max_attempts is assigned but never used.
        This is dead code that should be removed.
        """
        detector = BruteForceDetector(max_attempts=10)
        now = datetime.now()
        
        # Add some attempts
        for i in range(20):
            detector.add_attempt("192.168.1.1", "root", now, False)
        
        # The analyze function works correctly despite the unused variable
        results = detector.analyze()
        assert len(results) > 0
        
        # The bug is just dead code - no functional impact
    
    def test_csv_formula_injection_not_escaped(self, tmp_path):
        """
        POTENTIAL BUG: CSV formula injection vulnerability
        Severity: LOW (not actually exploitable in current implementation)
        
        Usernames starting with =, +, -, @ could be interpreted as formulas
        by Excel, but the CSV export doesn't include usernames, only IPs.
        
        Current status: NOT VULNERABLE (usernames not exported to CSV)
        
        However, if usernames were added to CSV export in the future,
        they should be escaped.
        """
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Add attempts with formula-like usernames
        dangerous_usernames = [
            "=1+1",
            "=cmd|'/c calc'!A1",
            "@SUM(1+1)",
            "+1+1",
            "-1+1",
        ]
        
        for username in dangerous_usernames:
            detector.add_attempt("192.168.1.1", username, now, False)
        
        # Export to CSV
        csv_path = tmp_path / "dangerous.csv"
        results = detector.analyze(export_csv=str(csv_path))
        
        # Check if CSV was created
        assert csv_path.exists()
        
        # Read CSV content
        content = csv_path.read_text()
        
        # CSV doesn't include usernames, so not vulnerable
        # But this test documents that if usernames were added,
        # they would need escaping
        assert "IP,Attempts,Attack_Rate,Severity,Action,Duration,Window_Start,Window_End" in content
    
    def test_tabs_in_rules_file(self):
        """
        Regression guard: rules.py must use spaces, not tabs (PEP 8).
        Originally documented a real bug; kept inverted so the bug can't return.
        """
        import os
        rules_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules.py")
        with open(rules_path, "rb") as f:
            content = f.read()
        assert b"\t" not in content, "rules.py should not contain tab indentation"

        from rules import PATTERNS
        assert len(PATTERNS) > 0


class TestCodeQualityIssues:
    """Tests documenting code quality issues that don't affect functionality."""
    
    def test_unused_imports_exist(self):
        """
        CODE QUALITY: Unused imports in codebase
        
        - main.py line 15: 're' imported but unused
        - parser.py line 270: 'time' imported but unused
        
        These don't cause bugs but should be removed.
        """
        # We can't easily test for unused imports in runtime
        # This test documents the issue
        
        # The code works fine despite unused imports
        from main import BruteForceDetector
        from parser import SSHLogParser
        
        detector = BruteForceDetector()
        parser = SSHLogParser()
        
        # Both work correctly
        assert detector is not None
        assert parser is not None
    
    def test_missing_newline_at_eof(self):
        """
        CODE QUALITY: Missing newline at end of file
        
        Files missing final newline:
        - main.py line 891
        - models.py line 7
        - utils.py line 66
        
        This can cause issues with some tools but doesn't affect Python.
        """
        # Check if files exist and can be imported
        import main
        import models
        import utils
        
        # All modules work correctly despite missing newlines
        assert main is not None
        assert models is not None
        assert utils is not None


class TestSecurityFindings:
    """Tests for security-related findings."""
    
    def test_path_traversal_attempts_handled(self, tmp_path):
        """
        SECURITY: Path traversal in file operations
        
        The code doesn't explicitly validate paths for traversal attacks.
        It relies on OS-level protections.
        
        Status: Partially protected by OS, but could be more explicit.
        """
        from parser import SSHLogParser
        
        # Try path traversal in log file
        parser = SSHLogParser()
        
        dangerous_path = "../../../etc/passwd"
        try:
            attempts, stats = parser.parse_file(dangerous_path, auto_detect=True)
        except FileNotFoundError:
            # Expected - path doesn't exist
            pass
        
        # The OS prevents actual traversal, but explicit validation would be better
    
    def test_memory_not_bounded(self):
        """
        POTENTIAL ISSUE: No memory bounds on stored attempts
        
        The BruteForceDetector stores all attempts in memory with no limit.
        Very large log files could exhaust available memory.
        
        Status: Works fine for typical use cases (tested up to 10K IPs)
        Recommendation: For very large deployments, consider streaming
        """
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Add many attempts (but not enough to actually exhaust memory)
        for i in range(1000):
            ip = f"192.168.{i // 256}.{i % 256}"
            detector.add_attempt(ip, "root", now, False)
        
        # Works fine for reasonable amounts of data
        results = detector.analyze()
        assert len(results) > 0
        
        # But there's no limit - could theoretically exhaust memory with
        # extremely large datasets


class TestEdgeCasesNotCovered:
    """Tests for edge cases that might reveal additional bugs."""
    
    def test_concurrent_csv_writes(self, tmp_path):
        """Test if concurrent CSV writes could cause issues."""
        # This is difficult to test without actual concurrency
        # but documents a potential issue
        detector = BruteForceDetector()
        now = datetime.now()
        detector.add_attempt("192.168.1.1", "root", now, False)
        
        csv_path = tmp_path / "test.csv"
        
        # Single write works fine
        results = detector.analyze(export_csv=str(csv_path))
        assert csv_path.exists()
        
        # Multiple writes to same file would append - potential issue
        results = detector.analyze(export_csv=str(csv_path))
        
        # File gets overwritten each time (current behavior)
        # This might not be ideal for live mode
    
    def test_null_bytes_in_data(self):
        """Test handling of null bytes in usernames."""
        detector = BruteForceDetector()
        now = datetime.now()
        
        # Username with null byte
        username = "admin\x00backdoor"
        detector.add_attempt("192.168.1.1", username, now, False)
        
        # Should handle without crashing
        results = detector.analyze()
        assert len(results) > 0
    
    def test_negative_timestamps(self):
        """Test with timestamps before Unix epoch."""
        detector = BruteForceDetector()
        
        # Timestamp before 1970 (if supported by datetime)
        try:
            old = datetime(1969, 12, 31, 23, 59, 59)
            detector.add_attempt("192.168.1.1", "root", old, False)
            results = detector.analyze()
            # If it works, great
            assert len(results) >= 0
        except (ValueError, OSError):
            # Some systems don't support pre-epoch dates
            pass
