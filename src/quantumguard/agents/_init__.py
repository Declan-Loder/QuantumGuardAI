"""
QuantumGuard AI - Agents Package
================================

This submodule contains the autonomous, tool-using agents that form the decision-making core of the framework.

Agents are designed following the ReAct / tool-calling pattern with memory and state management,
but specialized for cybersecurity: threat detection, graduated response, and meta-optimization.

Public API:
    - BaseAgent: Abstract base class for all agents
    - ThreatDetector: GNN-powered anomaly & threat prediction
    - ResponseEngine: Policy-driven mitigation & alerting
    - Optimizer: Self-improvement via RL / evolutionary methods (opt-in)

All agents inherit from BaseAgent and implement execute() or similar entry points.
"""

from __future__ import annotations

from .base import BaseAgent
from .threat_detector import ThreatDetector
from .response_engine import ResponseEngine
from .optimizer import Optimizer

__all__ = [
    "BaseAgent",
    "ThreatDetector",
    "ResponseEngine",
    "Optimizer",
]

# Optional: submodule version (useful for debugging or dependency checks)
__version__ = "0.1.0-dev"  # Will be overridden by top-level package version in most cases
