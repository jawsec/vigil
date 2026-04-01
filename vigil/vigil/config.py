"""Configuration loader with validation.

Loads config.yaml from the current directory (or a specified path) and validates
that all required keys exist and have sensible values before any monitor starts.
This prevents raw KeyError tracebacks from confusing users.
"""

import yaml
from pathlib import Path


class ConfigError(Exception):
    """Raised when config.yaml is missing, unparseable, or invalid."""
    pass


def _get_nested(d: dict, dotted_key: str):
    """Traverse a dict by dotted key path like 'monitors.crypto.thresholds'.

    Returns the value if found, None if any level is missing or not a dict.
    """
    val = d
    for k in dotted_key.split("."):
        if not isinstance(val, dict):
            return None
        val = val.get(k)
        if val is None:
            return None
    return val


def load_config(path: str = "config.yaml") -> dict:
    """Load and validate configuration.

    Args:
        path: Path to config file.

    Returns:
        Validated config dict.

    Raises:
        ConfigError: On missing file, bad YAML, or missing/invalid keys.
    """
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(
            f"{path} not found.\n"
            f"  cp config.yaml.example config.yaml  # then edit with your settings"
        )

    try:
        with open(config_path) as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigError(f"Failed to parse {path}: {e}")

    if not isinstance(config, dict):
        raise ConfigError(f"{path} is empty or not a valid YAML mapping.")

    # --- Alert config ---
    if _get_nested(config, "alert.type") is None:
        raise ConfigError("Missing required key: alert.type")

    valid_alert_types = {"slack", "matrix", "json", "stdout"}
    alert_type = config["alert"]["type"]
    if alert_type not in valid_alert_types:
        raise ConfigError(
            f"Invalid alert.type '{alert_type}'. Must be one of: {', '.join(sorted(valid_alert_types))}"
        )

    if alert_type in {"slack", "matrix"}:
        url = config["alert"].get("webhook_url", "")
        if not url or "YOUR" in url:
            raise ConfigError(
                f"alert.type is '{alert_type}' but webhook_url is missing or placeholder.\n"
                f"  Set a real webhook URL, or use alert.type: json for testing."
            )

    # --- Monitor config (at least one must be enabled) ---
    monitors = config.get("monitors")
    if not isinstance(monitors, dict):
        raise ConfigError("Missing or invalid 'monitors' section in config.")

    any_enabled = False

    # Crypto monitor validation
    crypto = monitors.get("crypto")
    if isinstance(crypto, dict) and crypto.get("enabled", False):
        any_enabled = True
        if _get_nested(crypto, "thresholds.large_transfer_usd") is None:
            raise ConfigError(
                "Crypto monitor enabled but monitors.crypto.thresholds.large_transfer_usd is missing."
            )
        wallets = crypto.get("wallets")
        if not isinstance(wallets, dict) or not any(wallets.values()):
            raise ConfigError(
                "Crypto monitor enabled but monitors.crypto.wallets is missing or empty."
            )

    # File integrity monitor validation
    fim = monitors.get("file_integrity")
    if isinstance(fim, dict) and fim.get("enabled", False):
        any_enabled = True
        watch = fim.get("watch_paths")
        if not isinstance(watch, list) or len(watch) == 0:
            raise ConfigError(
                "File integrity monitor enabled but monitors.file_integrity.watch_paths is empty."
            )

    if not any_enabled:
        raise ConfigError(
            "No monitors enabled. Enable at least one monitor in config.yaml.\n"
            "  Set monitors.crypto.enabled: true or monitors.file_integrity.enabled: true"
        )

    return config
