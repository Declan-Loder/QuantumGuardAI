"""
QuantumGuard AI
===============

Privacy-preserving, self-optimizing multi-agent cybersecurity framework.

Core capabilities:
- Graph-based threat detection (GNNs)
- Graduated autonomous response
- Federated learning across distributed nodes
- Post-quantum cryptography & differential privacy
- Modular tools (scanning, log parsing, alerting)

Public API (most commonly used):
    - config()                  → Access validated configuration
    - get_logger(__name__)      → Structured logger
    - get_viz()                 → Threat graph visualizer
    - ThreatDetector            → Main detection agent
    - ResponseEngine            → Mitigation & alerting agent
    - Optimizer                 → Self-improvement meta-agent

Quick usage example:
    from quantumguard import config, get_logger, ThreatDetector

    cfg = config()
    logger = get_logger(__name__)
    detector = ThreatDetector("detector-01", config=cfg.agents.threat_detector)

Version: {__version__}
License: MIT (open-source) + commercial/enterprise options available
"""

from __future__ import annotations

# Core utilities (always available)
from .utils.config import config, get_config
#from .utils.logging import get_logger, setup_logging
from .utils.viz import get_viz, plot_threat_graph, save_threat_viz, show_threat_viz

# Agents (main public classes)
from .agents.base import BaseAgent
from .agents.threat_detector import ThreatDetector
from .agents.response_engine import ResponseEngine
from .agents.optimizer import Optimizer

# Models
from .models.gnn import GNNTthreatModel
from .models.federated import QuantumGuardClient, start_federated_server
from .models.quantum_resistant import QuantumResistantCrypto

# Privacy
from .privacy.differential import DifferentialPrivacy
from .privacy.encryption import PrivacyEncryption

# Tools
from .tools.alert_dispatch import dispatch_alert, AlertDispatcher
from .tools.log_analyzer import LogAnalyzer
from .tools.network_scan import NetworkScanTool

# Package metadata
__version__ = "0.1.0-dev"
__author__ = "Declan Loder"
__license__ = "MIT (open-source core) — contact for enterprise/commercial licensing"

# Explicit public API (controls what `from quantumguard import *` brings in)
__all__ = [
    # Utilities
    "config",
    "get_config",
    "get_logger",
    "setup_logging",
    "get_viz",
    "plot_threat_graph",
    "save_threat_viz",
    "show_threat_viz",

    # Agents
    "BaseAgent",
    "ThreatDetector",
    "ResponseEngine",
    "Optimizer",

    # Models
    "GNNTthreatModel",
    "QuantumGuardClient",
    "start_federated_server",
    "QuantumResistantCrypto",

    # Privacy
    "DifferentialPrivacy",
    "PrivacyEncryption",

    # Tools
    "dispatch_alert",
    "AlertDispatcher",
    "LogAnalyzer",
    "NetworkScanTool",

    # Metadata
    "__version__",
    "__author__",
    "__license__",
]

# Optional: auto-setup on import (logging, etc.)
import sys

#if "pytest" not in sys.modules:  # Don't run setup in tests
  #  from .utils.logging import setup_logging
   # setup_logging()
