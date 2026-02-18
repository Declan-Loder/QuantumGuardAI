"""
Optimizer Agent (Self-Improvement Meta-Agent)
=============================================

This agent continuously improves the system by analyzing past real detections
and adjusting key thresholds (e.g. confidence_threshold) to reduce false positives
or catch more threats.

For MVP: rule-based adaptation based on real detection history.
Future: full RL / evolutionary strategies with real simulations.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from quantumguard.agents.base import BaseAgent
from quantumguard.utils.logging import get_logger
from quantumguard.utils.storage import load_history  # Your history storage

logger = get_logger(__name__)

class Optimizer(BaseAgent):
    """
    Self-improvement agent that learns from real past detections to tune parameters.
    """

    description: str = (
        "Analyzes historical real detections to automatically adjust detection thresholds "
        "and policies for better performance over time."
    )

    def __init__(
        self,
        name: str = "optimizer-01",
        config: Optional[Dict[str, Any]] = None,
        memory: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(name, config, memory)

        self.enabled: bool = True
        if not self.enabled:
            logger.warning("Optimizer disabled in config (agents.optimizer.enabled: false)")

        self.min_history: int = self.config.get("min_history", 3)
        self.target_ratio: float = self.config.get("target_high_conf_ratio", 0.60)  # Aim for ~60% high-confidence

        # Current tunable parameters (will be adjusted)
        self.confidence_threshold: float = self.config.get("confidence_threshold", 0.85)

    def execute(self, input_data: Any = None) -> Dict[str, Any]:
        """
        Run one optimization cycle: analyze history → adjust threshold.
        """
        if not self.enabled:
            return {"status": "disabled", "message": "Optimizer not enabled in config"}

        history = load_history()
        if not history or len(history) < self.min_history:
            return {
                "status": "insufficient_data",
                "message": f"Need at least {self.min_history} detections to learn. Have: {len(history)}",
                "history_count": len(history),
            }

        # Analyze real past performance
        high_conf_count = sum(1 for d in history if d.get("high_confidence", False))
        total = len(history)
        high_conf_ratio = high_conf_count / total if total > 0 else 0.0

        improved = False
        old_threshold = self.confidence_threshold
        message = ""

        # Simple, safe rule-based learning
        if high_conf_ratio > self.target_ratio + 0.20:  # Too many alerts → raise threshold
            self.confidence_threshold = min(0.98, self.confidence_threshold + 0.03)
            improved = True
            message = f"Too many high-confidence detections ({high_conf_ratio:.1%}). Raised threshold to {self.confidence_threshold:.3f}"
        elif high_conf_ratio < self.target_ratio - 0.20:  # Too few alerts → lower threshold
            self.confidence_threshold = max(0.60, self.confidence_threshold - 0.03)
            improved = True
            message = f"Too few high-confidence detections ({high_conf_ratio:.1%}). Lowered threshold to {self.confidence_threshold:.3f}"
        else:
            message = f"Threshold stable at {self.confidence_threshold:.3f} (ratio {high_conf_ratio:.1%} near target)"

        # Log result
        if improved:
            logger.info(
                "Optimizer updated threshold",
                old=old_threshold,
                new=self.confidence_threshold,
                ratio=high_conf_ratio,
                history_count=total
            )
        else:
            logger.debug("No change needed", ratio=high_conf_ratio, threshold=self.confidence_threshold)

        # Optional: run one mock simulation episode (for future expansion)
        # mock_result = self._run_mock_episode()

        return {
            "status": "success",
            "improved": improved,
            "old_threshold": old_threshold,
            "new_threshold": self.confidence_threshold,
            "high_confidence_ratio": round(high_conf_ratio, 3),
            "history_count": total,
            "message": message,
        }

    def _run_mock_episode(self) -> Dict:
        """Placeholder for future simulation-based evaluation."""
        # Can be expanded later with real mock attacks
        return {"reward": random.uniform(-10, 20), "note": "mock episode"}

    def finalize(self) -> None:
        super().finalize()
        logger.info("Optimizer finalizing", current_threshold=self.confidence_threshold)
        # Future: save updated threshold to persistent config file