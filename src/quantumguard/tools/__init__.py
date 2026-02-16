"""
QuantumGuard AI - Tools Package
===============================

This submodule contains reusable, callable tools that agents can invoke during execution.

Tools follow the standard pattern:
- Accept keyword arguments
- Return serializable results (dicts, lists, primitives, bytes)
- Are registered in BaseAgent._define_tools()
- Designed for cybersecurity domain (network ops, log parsing, alerting, etc.)

Current tools (implement in individual files):
- network_scan.py     → Scan networks (nmap/scapy wrappers)
- log_analyzer.py     → Parse and extract features from logs (Suricata, Zeek, etc.)
- alert_dispatch.py   → Send notifications (console, Slack, PagerDuty, SIEM)

Future tools (planned):
- packet_capture.py   → Live pcap collection
- edr_query.py        → Query EDR APIs (CrowdStrike, Carbon Black, etc.)
- firewall_manager.py → Apply dynamic firewall rules
- threat_intel.py     → Query external feeds (VirusTotal, AbuseIPDB, etc.)

Public API:
    (Exported functions/classes will appear here as implemented)

All tools should:
- Be pure or have minimal side effects
- Include type hints and docstrings
- Raise meaningful exceptions
- Be testable in isolation
"""

from __future__ import annotations

# Import and expose public tools as they are implemented
# from .network_scan import network_scan, port_scan  # Example
# from .log_analyzer import parse_zeek_log, extract_features
# from .alert_dispatch import dispatch_alert

__all__ = [
    # Add tool functions/classes here once implemented, e.g.
    # "network_scan",
    # "parse_zeek_log",
    # "dispatch_alert",
    # ...
]

# Optional submodule version (useful for tooling/debugging)
__version__ = "0.1.0-dev"
