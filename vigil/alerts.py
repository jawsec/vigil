"""Shared alert pipeline for all vigil monitors.

Supports four output modes:
  - slack:  POST to a Slack incoming webhook
  - matrix: POST to a Matrix webhook (e.g. maubot or hookshot)
  - json:   Print structured JSON to stdout (for SIEM ingestion)
  - stdout: Print plain text to terminal

Every alert includes a timestamp and the monitor source. Delivery failures
are logged but never crash the tool — monitoring continues regardless.
"""

import json
import logging
import requests
from datetime import datetime, timezone

logger = logging.getLogger("vigil")


def send_alert(message: str, config: dict, source: str = "unknown") -> None:
    """Send an alert through the configured output channel.

    Args:
        message: Human-readable alert text.
        config: Full vigil config dict (needs alert.type and alert.webhook_url).
        source: Which monitor generated this alert (e.g. 'crypto', 'file_integrity').
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    alert_type = config["alert"]["type"]

    if alert_type == "json":
        record = {
            "timestamp": timestamp,
            "source": source,
            "alert": message,
        }
        print(json.dumps(record))
        return

    if alert_type == "stdout":
        print(f"[{timestamp}] [{source}] {message}")
        return

    # Webhook delivery (slack or matrix)
    url = config["alert"].get("webhook_url", "")

    if alert_type == "slack":
        payload = {"text": f":rotating_light: *vigil [{source}]* {message}"}
    elif alert_type == "matrix":
        payload = {"body": f"vigil [{source}] {message}"}
    else:
        logger.warning(f"Unknown alert type '{alert_type}', falling back to stdout.")
        print(f"[{timestamp}] [{source}] {message}")
        return

    try:
        resp = requests.post(url, json=payload, timeout=10)
        resp.raise_for_status()
    except requests.RequestException as e:
        # Log the failure but never crash — monitoring is more important than alerting
        logger.error(f"Failed to deliver {alert_type} alert: {e}")
        # Fall back to stdout so the alert isn't lost entirely
        print(f"[{timestamp}] [{source}] (webhook failed) {message}")
