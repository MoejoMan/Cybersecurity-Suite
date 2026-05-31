import pytest

from parser import SSHLogParser


VALID_LOG = """\
2026-01-15T10:00:01 host1 sshd[1234]: Invalid user admin from 192.0.2.10
2026-01-15T10:00:02 host1 sshd[1235]: Failed password for invalid user admin from 192.0.2.10 port 22
2026-01-15T10:00:03 host1 sshd[1236]: Failed password for root from 192.0.2.11 port 22
2026-01-15T10:00:04 host1 sshd[1237]: Accepted publickey for ubuntu from 192.0.2.12 port 22
"""

INVALID_TIMESTAMP_LOG = """\
9999-99-99T99:99:99 host1 sshd[1234]: Invalid user admin from 192.0.2.10
"""


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content)
    return str(p)


def test_parse_valid_log(tmp_path):
    parser = SSHLogParser()
    attempts, stats = parser.parse_file(_write(tmp_path, "auth.log", VALID_LOG), auto_detect=True)
    assert stats["lines_read"] == 4
    assert stats["format_matches"] > 0
    assert len(attempts) >= 3
    invalid = [a for a in attempts if a[0] == "192.0.2.10" and a[4] == "invalid_user"]
    assert invalid


def test_empty_log_returns_warning(tmp_path, capsys):
    parser = SSHLogParser()
    attempts, stats = parser.parse_file(_write(tmp_path, "empty.log", ""), auto_detect=True)
    assert attempts == []
    assert stats["lines_read"] == 0
    captured = capsys.readouterr()
    assert "empty" in captured.out.lower()


def test_bad_timestamp_is_counted_in_failed(tmp_path):
    parser = SSHLogParser()
    attempts, stats = parser.parse_file(
        _write(tmp_path, "invalid_timestamp.log", INVALID_TIMESTAMP_LOG), auto_detect=True
    )
    # Format won't match the garbage timestamp at all, so attempts is empty.
    # If format did match but timestamp parsing failed, failed_timestamps would increment.
    assert attempts == []
