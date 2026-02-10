"""
Core data models for SSHVigil threat detection.

Provides type-safe dataclasses and enums used across the analyzer:
- ThreatLevel: severity classification enum
- Attempt: single SSH auth event
- IPSummary: aggregated per-IP threat analysis result
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import IntEnum
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------
__version__ = "1.1.0"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class ThreatLevel(IntEnum):
    """
    Severity classification for an IP address based on its SSH behaviour.

    Ordering is descending severity so comparisons work naturally:
        ThreatLevel.CRITICAL < ThreatLevel.HIGH  →  True  (more severe)
    """
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3

    @classmethod
    def from_string(cls, value: str) -> "ThreatLevel":
        """
        Parse a severity string (case-insensitive) into a ThreatLevel.

        >>> ThreatLevel.from_string("HIGH")
        <ThreatLevel.HIGH: 1>
        >>> ThreatLevel.from_string("low")
        <ThreatLevel.LOW: 3>

        Raises ValueError for unknown strings.
        """
        try:
            return cls[value.upper()]
        except KeyError:
            valid = ", ".join(member.name for member in cls)
            raise ValueError(f"Unknown threat level '{value}'. Valid levels: {valid}")

    @property
    def color(self) -> Optional[str]:
        """ANSI color name for terminal display."""
        return {
            ThreatLevel.CRITICAL: "red",
            ThreatLevel.HIGH: "yellow",
            ThreatLevel.MEDIUM: "cyan",
            ThreatLevel.LOW: None,
        }[self]

    @property
    def bold(self) -> bool:
        """Whether to render this level in bold."""
        return self in (ThreatLevel.CRITICAL, ThreatLevel.HIGH)

    @property
    def action(self) -> str:
        """Default recommended action for this severity."""
        return {
            ThreatLevel.CRITICAL: "BLOCK",
            ThreatLevel.HIGH: "BLOCK",
            ThreatLevel.MEDIUM: "MONITOR",
            ThreatLevel.LOW: "ALLOW",
        }[self]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Attempt:
    """
    A single parsed SSH authentication event.

    Attributes:
        ip: source IP address (validated before construction)
        username: target account name
        timestamp: when the attempt occurred
        success: True if authentication succeeded
        event: rule name that matched (e.g. 'invalid_user', 'accepted_publickey')
    """
    ip: str
    username: str
    timestamp: datetime
    success: bool = False
    event: Optional[str] = None


@dataclass
class IPSummary:
    """
    Aggregated analysis result for a single IP address.

    Built by the detector after grouping attempts and computing metrics.

    Attributes:
        ip: source IP address
        total_attempts: count of failed login attempts
        attack_rate: failed attempts per minute (1-minute floor)
        threat_level: classified severity
        action: recommended response (BLOCK / MONITOR / ALLOW / BLOCKED)
        duration: time between first and last attempt
        window_start: timestamp of first attempt
        window_end: timestamp of last attempt
        targeted_users: mapping of username → attempt count
    """
    ip: str
    total_attempts: int = 0
    attack_rate: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.LOW
    action: str = "ALLOW"
    duration: timedelta = field(default_factory=lambda: timedelta(0))
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    targeted_users: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, str]:
        """
        Flatten to the dict format expected by CSV export and analyze() return.
        """
        return {
            "IP": self.ip,
            "Attempts": str(self.total_attempts),
            "Attack_Rate": f"{self.attack_rate:.2f}",
            "Severity": self.threat_level.name,
            "Action": self.action,
            "Duration": _format_duration(self.duration),
            "Window_Start": self.window_start.isoformat() if self.window_start else "",
            "Window_End": self.window_end.isoformat() if self.window_end else "",
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _format_duration(delta: timedelta) -> str:
    """Compact human-readable duration string."""
    total_seconds = int(abs(delta.total_seconds()))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m {seconds}s"
    return f"{minutes}m {seconds}s"

