"""
Canonical SSH info-line parsing rules.

Each rule provides:
- name: short identifier for the event type
- regex: compiled pattern with named groups `username` and `ip`
- success: whether the event indicates a successful authentication

Rules are evaluated in order — more specific patterns should come first
(e.g. 'failed_password_invalid' before 'failed_password_user') to avoid
the broader pattern consuming the match.

Add new dicts to extend coverage for additional sshd messages.
"""
import re

PATTERNS = [
    # ------------------------------------------------------------------
    # Failed authentication events (order matters: specific before generic)
    # ------------------------------------------------------------------
    {
        'name': 'failed_password_invalid',
        'regex': re.compile(
            r"Failed password for invalid user (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
        ),
        'success': False,
    },
    {
        'name': 'failed_password_user',
        'regex': re.compile(
            r"Failed password for (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
        ),
        'success': False,
    },
    {
        'name': 'invalid_user',
        'regex': re.compile(
            r"Invalid user (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
        ),
        'success': False,
    },
    {
        'name': 'failed_none',
        'regex': re.compile(
            r"Failed none for (?:invalid user )?(?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
        ),
        'success': False,
    },
    {
        'name': 'failed_publickey',
        'regex': re.compile(
            r"Failed publickey for (?:invalid user )?(?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
        ),
        'success': False,
    },
    {
        'name': 'authentication_failure',
        'regex': re.compile(
            r"pam_unix\(sshd:auth\): authentication failure;.*ruser=(?P<username>\S*)\s+rhost=(?P<ip>[0-9a-fA-F:.]+)"
        ),
        'success': False,
    },
    {
        'name': 'connection_closed_preauth',
        'regex': re.compile(
            r"Connection closed by (?:authenticating user )?(?P<username>\S+)?\s*(?P<ip>[0-9a-fA-F:.]+) port \d+ \[preauth\]"
        ),
        'success': False,
    },
    {
        'name': 'disconnected_preauth',
        'regex': re.compile(
            r"Disconnected from (?:authenticating user )?(?P<username>\S+)?\s*(?P<ip>[0-9a-fA-F:.]+) port \d+ \[preauth\]"
        ),
        'success': False,
    },
    {
        'name': 'connection_reset_preauth',
        'regex': re.compile(
            r"Connection reset by (?P<username>\S+)?\s*(?P<ip>[0-9a-fA-F:.]+) port \d+ \[preauth\]"
        ),
        'success': False,
    },
    {
        'name': 'max_auth_attempts',
        'regex': re.compile(
            r"error: maximum authentication attempts exceeded for (?:invalid user )?(?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
        ),
        'success': False,
    },
    {
        'name': 'too_many_auth_failures',
        'regex': re.compile(
            r"Disconnecting (?:invalid user )?(?P<username>\S+) (?P<ip>[0-9a-fA-F:.]+).*Too many authentication failures"
        ),
        'success': False,
    },
    {
        'name': 'break_in_attempt',
        'regex': re.compile(
            r"reverse mapping checking .* for (?P<ip>[0-9a-fA-F:.]+) .* POSSIBLE BREAK-IN ATTEMPT"
        ),
        'success': False,
        'no_username': True,  # This pattern has no username; detector uses '<unknown>'
    },

    # ------------------------------------------------------------------
    # Successful authentication events
    # ------------------------------------------------------------------
    {
        'name': 'accepted_password',
        'regex': re.compile(
            r"Accepted password for (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
        ),
        'success': True,
    },
    {
        'name': 'accepted_publickey',
        'regex': re.compile(
            r"Accepted publickey for (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
        ),
        'success': True,
    },
    {
        'name': 'accepted_keyboard_interactive',
        'regex': re.compile(
            r"Accepted keyboard-interactive(?:/pam)? for (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
        ),
        'success': True,
    },
    {
        'name': 'accepted_gssapi',
        'regex': re.compile(
            r"Accepted gssapi-with-mic for (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
        ),
        'success': True,
    },
]

