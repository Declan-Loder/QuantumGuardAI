"""
Alert Dispatch Tool
===================

Sends notifications when threats are detected or responses executed.

Supported channels (configurable):
- console (always available – structured JSON log)
- slack (webhook)
- pagerduty (events API)
- email (SMTP – future)
- siem_webhook (generic POST)

Configuration keys (from tools.alert_dispatch):
- channels: list of active channels (default: ["console"])
- slack_webhook_url: str (env: SLACK_WEBHOOK_URL)
- pagerduty_routing_key: str (env: PAGERDUTY_ROUTING_KEY)
- severity_mapping: dict (maps internal levels to channel-specific severity)

Usage:
    dispatch_alert(
        message="High-confidence threat detected",
        details={"score": 0.92, "node": "192.168.1.100"},
        severity="critical"
    )
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
from requests.exceptions import RequestException

from quantumguard.utils.logging import get_logger

logger = get_logger(__name__)

class AlertDispatcher:
    """
    Tool for dispatching alerts across configured channels.

    Dispatches structured JSON payloads with:
    - timestamp
    - severity (info/warning/critical)
    - message
    - details (threat score, nodes, actions, etc.)
    - source (agent name, cycle ID)
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.channels: List[str] = config.get("channels", ["console"])
        self.severity_mapping: Dict[str, str] = config.get(
            "severity_mapping",
            {
                "info": "info",
                "warning": "warning",
                "critical": "critical",
            }
        )

        # Load secrets from env (never hard-code)
        self.slack_webhook: Optional[str] = os.getenv("SLACK_WEBHOOK_URL")
        self.pagerduty_routing_key: Optional[str] = os.getenv("PAGERDUTY_ROUTING_KEY")

        if "slack" in self.channels and not self.slack_webhook:
            logger.warning("Slack configured but SLACK_WEBHOOK_URL missing – Slack disabled")
            self.channels = [c for c in self.channels if c != "slack"]

        if "pagerduty" in self.channels and not self.pagerduty_routing_key:
            logger.warning("PagerDuty configured but PAGERDUTY_ROUTING_KEY missing – PagerDuty disabled")
            self.channels = [c for c in self.channels if c != "pagerduty"]

        self.dry_run: bool = config.get("dry_run", True)  # Default: simulate only

        logger.info(
            "AlertDispatcher initialized",
            active_channels=self.channels,
            dry_run=self.dry_run
        )

    def dispatch_alert(
        self,
        message: str,
        details: Dict[str, Any],
        severity: str = "info",
        source: str = "QuantumGuard",
        channel_override: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Send alert through all configured channels.

        Args:
            message: Short human-readable summary
            details: Structured context (score, nodes, actions, graph_id, etc.)
            severity: "info" | "warning" | "critical"
            source: Agent or component name
            channel_override: Optional list to send only to specific channels

        Returns:
            Dict with dispatch results per channel {"channel": success_bool or error_msg}
        """
        channels_to_use = channel_override or self.channels
        if not channels_to_use:
            logger.warning("No active alert channels configured")
            return {}

        payload = {
            "timestamp": datetime.utcnow().isoformat(),
            "severity": severity,
            "message": message,
            "source": source,
            "details": details,
        }

        results: Dict[str, Any] = {}

        for channel in channels_to_use:
            try:
                if self.dry_run:
                    logger.info(f"[DRY RUN] Alert dispatched to {channel}", **payload)
                    results[channel] = True
                    continue

                if channel == "console":
                    logger.critical(json.dumps(payload, indent=2))
                    results[channel] = True

                elif channel == "slack" and self.slack_webhook:
                    slack_payload = {
                        "text": f"*{severity.upper()}*: {message}",
                        "blocks": [
                            {
                                "type": "section",
                                "text": {"type": "mrkdwn", "text": f"*{severity.upper()}*: {message}"},
                            },
                            {
                                "type": "section",
                                "text": {"type": "mrkdwn", "text": f"```json\n{json.dumps(details, indent=2)}\n```"},
                            },
                        ],
                    }
                    resp = requests.post(self.slack_webhook, json=slack_payload, timeout=10)
                    resp.raise_for_status()
                    results[channel] = True
                    logger.debug("Slack alert sent", status=resp.status_code)

                elif channel == "pagerduty" and self.pagerduty_routing_key:
                    pd_payload = {
                        "routing_key": self.pagerduty_routing_key,
                        "event_action": "trigger",
                        "payload": {
                            "summary": message,
                            "severity": self.severity_mapping.get(severity, "warning"),
                            "source": source,
                            "custom_details": details,
                        },
                    }
                    resp = requests.post(
                        "https://events.pagerduty.com/v2/enqueue",
                        json=pd_payload,
                        timeout=10,
                    )
                    resp.raise_for_status()
                    results[channel] = True
                    logger.debug("PagerDuty event triggered", status=resp.status_code)

                else:
                    logger.warning(f"Unknown or unconfigured channel: {channel}")
                    results[channel] = f"unsupported"

            except RequestException as e:
                logger.error(f"Alert dispatch failed for {channel}", error=str(e))
                results[channel] = str(e)
            except Exception as e:
                logger.exception(f"Unexpected error dispatching to {channel}")
                results[channel] = "unexpected_error"

        if any(not isinstance(v, bool) or not v for v in results.values() if isinstance(v, bool)):
            logger.warning("One or more alert channels failed", results=results)

        return results


# Singleton / global instance (optional – can also instantiate per agent)
# For simplicity, agents can create their own or use a shared one via dependency injection
alert_dispatcher: Optional[AlertDispatcher] = None


def init_alert_dispatcher(config: Dict[str, Any]) -> AlertDispatcher:
    """Initialize the global alert dispatcher (call once at startup)."""
    global alert_dispatcher
    alert_dispatcher = AlertDispatcher(config)
    return alert_dispatcher


def dispatch_alert(
    message: str,
    details: Dict[str, Any],
    severity: str = "info",
    source: str = "QuantumGuard",
    channel_override: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Convenience global function to dispatch alerts."""
    if alert_dispatcher is None:
        raise RuntimeError("AlertDispatcher not initialized. Call init_alert_dispatcher first.")
    return alert_dispatcher.dispatch_alert(
        message=message,
        details=details,
        severity=severity,
        source=source,
        channel_override=channel_override,
    )
