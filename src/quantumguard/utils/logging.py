"""
Structured Logging Setup
========================

Uses structlog for JSON-structured, contextual logging.

Features:
- JSON output in production (machine-readable)
- Colored, human-readable console in development
- Bound context (agent_name, cycle_id, etc.)
- Sensitive field redaction (IPs, tokens, secrets)
- Global logger factory (get_logger(__name__))
- Level filtering from config

Usage:
    from quantumguard.utils.logging import get_logger

    logger = get_logger(__name__)
    logger.info("Detection cycle started", cycle_id=42, target="192.168.1.100")
"""

import logging
import sys
from typing import Any

import structlog
from structlog import BoundLoggerBase
from structlog.processors import JSONRenderer, StackInfoRenderer, format_exc_info
from structlog.stdlib import LoggerFactory

from quantumguard.utils.config import config

# ────────────────────────────────────────────────
# Processors
# ────────────────────────────────────────────────

def redact_sensitive_fields(
    logger: Any,
    method_name: str,
    event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Redact sensitive fields (e.g. IP addresses, tokens, keys) in logs.
    """
    sensitive_keys = {
        "ip", "src_ip", "dst_ip", "token", "key", "secret", "password",
        "api_key", "webhook", "routing_key"
    }

    for key, value in event_dict.items():
        if isinstance(key, str) and any(s in key.lower() for s in sensitive_keys):
            event_dict[key] = "[REDACTED]"
        elif isinstance(value, str) and ("://" in value or "@" in value):
            # Rough URL / auth redaction
            event_dict[key] = "[REDACTED_URL_OR_AUTH]"

    return event_dict


def add_log_level(
    logger: Any,
    method_name: str,
    event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """Add numeric log level for easier filtering in log systems."""
    level_to_number = {
        "debug": 10,
        "info": 20,
        "warning": 30,
        "error": 40,
        "critical": 50,
    }
    event_dict["level_number"] = level_to_number.get(event_dict.get("level", "info"), 20)
    return event_dict


# ────────────────────────────────────────────────
# Setup once at startup
# ────────────────────────────────────────────────

def setup_logging() -> None:
    """Configure structlog globally (call once at app startup)."""
    log_level_name = config().app.log_level.upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    # Root Python logging config
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

    # Structlog processors (order matters)
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        StackInfoRenderer(),
        format_exc_info,
        redact_sensitive_fields,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.dict_tracebacks,
    ]

    if config().app.environment == "development":
        # Pretty console output in dev
        processors.extend([
            structlog.dev.set_exc_info,
            structlog.dev.ConsoleRenderer(colors=True),
        ])
    else:
        # JSON in production/staging
        processors.append(JSONRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    logger = get_logger(__name__)
    logger.info(
        "Logging configured",
        level=log_level_name,
        environment=config().app.environment,
        json_output=(config().app.environment != "development")
    )


# ────────────────────────────────────────────────
# Public API
# ────────────────────────────────────────────────

def get_logger(name: str) -> BoundLoggerBase:
    """
    Get a structured logger for a module.

    Usage:
        logger = get_logger(__name__)
        logger.bind(agent_name="threat-detector-01").info("Cycle started", score=0.92)
    """
    return structlog.get_logger(name)


# Auto-setup on first import (safe idempotent)
setup_logging()
