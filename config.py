"""
Configuration management for the SSH Brute Force Analyzer.

Loads settings from config.json when present; otherwise writes and uses
well-chosen defaults. Exposes dict-like access and a helper for converting
the active configuration to a plain dict.
"""
import json
import os
from typing import Dict, Any


class Config:
    """
    Load and manage analyzer configuration.

    Keys:
    - max_attempts: threshold for short-window brute-force detection
    - time_window_minutes: size of detection window in minutes
    - summary_limit: max rows to display in the summary table
    - verbose_limit: max IPs to include in verbose mode
    - block_threshold: persistent attempts threshold to recommend blocking
    - monitor_threshold: persistent attempts threshold to recommend monitoring
    - color_enabled: enable ANSI colors in terminal output
    """
    
    # Default configuration
    DEFAULTS = {
        "max_attempts": 5,
        "time_window_minutes": 10,
        "summary_limit": 20,
        "verbose_limit": 10,
        "block_threshold": 50,
        "monitor_threshold": 20,
        "color_enabled": True
    }
    
    def __init__(self, config_path: str = "config.json"):
        """
        Initialize config from file or defaults.
        
        Args:
            config_path: Path to config.json file
        """
        self.config = self.DEFAULTS.copy()
        self.config_path = config_path
        self.loaded_from_file = False
        
        if os.path.exists(config_path):
            self._load_from_file(config_path)
        else:
            self._create_default_config(config_path)
    
    def _load_from_file(self, config_path: str):
        """Load configuration values from a JSON file at `config_path`."""
        try:
            with open(config_path, 'r') as f:
                file_config = json.load(f)
            
            # Validate that loaded config is a dict
            if not isinstance(file_config, dict):
                print(f"[WARNING] Invalid config format in {config_path}: expected JSON object, got {type(file_config).__name__}")
                print(f"  Using default configuration")
                return
            
            # Validate and sanitize each key
            for key, value in file_config.items():
                if key not in self.DEFAULTS:
                    print(f"[WARNING] Unknown config key '{key}' - ignoring")
                    continue
                
                # Type validation (bool check must come first since bool is subclass of int)
                expected_type = type(self.DEFAULTS[key])
                if expected_type == int and isinstance(value, bool):
                    # bool is subclass of int in Python, but we want strict int for numeric fields
                    print(f"[WARNING] Invalid type for '{key}': expected int, got bool")
                    print(f"  Using default value: {self.DEFAULTS[key]}")
                    continue
                if expected_type == bool and isinstance(value, int) and not isinstance(value, bool):
                    # Accept int 0/1 as bool values
                    value = bool(value)
                elif not isinstance(value, expected_type):
                    print(f"[WARNING] Invalid type for '{key}': expected {expected_type.__name__}, got {type(value).__name__}")
                    print(f"  Using default value: {self.DEFAULTS[key]}")
                    continue
                
                # Range validation for numeric values
                if key in ['max_attempts', 'time_window_minutes', 'summary_limit', 'verbose_limit', 'block_threshold', 'monitor_threshold']:
                    if value < 1:
                        print(f"[WARNING] Invalid value for '{key}': must be >= 1, got {value}")
                        print(f"  Using default value: {self.DEFAULTS[key]}")
                        continue
                
                # Update with validated value
                self.config[key] = value
            
            self.loaded_from_file = True
            print(f"[OK] Loaded config from {config_path}")
            
        except json.JSONDecodeError as e:
            print(f"[WARNING] Malformed JSON in {config_path}: {e}")
            print(f"  Using default configuration")
        except PermissionError:
            print(f"[WARNING] Permission denied reading {config_path}")
            print(f"  Using default configuration")
        except Exception as e:
            print(f"[WARNING] Error loading config: {e}")
            print(f"  Using default configuration")
    
    def _create_default_config(self, config_path: str):
        """Write DEFAULTS to `config_path` to bootstrap configuration."""
        try:
            with open(config_path, 'w') as f:
                json.dump(self.DEFAULTS, f, indent=2)
            print(f"[OK] Created default config at {config_path}")
            # Treat freshly written defaults as loaded so callers know config is ready
            self.loaded_from_file = True
        except Exception as e:
            print(f"[WARNING] Could not create config file: {e}")
    
    def get(self, key: str, default=None) -> Any:
        """Return the value for `key`, or `default` if the key is missing."""
        return self.config.get(key, default)
    
    def __getitem__(self, key: str) -> Any:
        """Dict-style access to configuration values (e.g., config["summary_limit"])."""
        return self.config[key]
    
    def __str__(self) -> str:
        """Return a human-readable representation of the active configuration."""
        lines = ["Current Configuration:"]
        for key, value in self.config.items():
            lines.append(f"  {key}: {value}")
        return "\n".join(lines)
    
    def to_dict(self) -> Dict[str, Any]:
        """Return a shallow copy of the active configuration as a dict."""
        return self.config.copy()
