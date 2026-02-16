"""
Optimizer Agent (Self-Improvement Meta-Agent)
=============================================

This agent is responsible for continuously improving the performance of other agents
through simulated episodes, reinforcement learning, or evolutionary strategies.

Key responsibilities:
- Run controlled simulations of network attacks and defenses
- Evaluate how well current ThreatDetector + ResponseEngine configurations perform
- Propose / apply improvements (hyperparameter tuning, policy adjustments)
- Maintain safety: only apply changes with human approval or in sandbox mode
- Store improvement trajectories for analysis

Configuration keys used:
- enabled (bool) – must be explicitly set to true
- rl_algorithm (str) – 'ppo', 'evolution', 'grid_search' (MVP: simple evolution)
- simulation_episodes (int)
- training_interval_hours (float)

For MVP: uses a simple evolutionary strategy (perturb parameters → evaluate → keep better)
"""

from __future__ import annotations

import copy
import random
import time
from typing import Any, Dict, List, Optional, Tuple

from quantumguard.agents.base import BaseAgent
from quantumguard.utils.logging import get_logger

logger = get_logger(__name__)

class Optimizer(BaseAgent):
    """
    Meta-agent for self-optimization of the QuantumGuard system.

    It runs offline/scheduled simulations to test variations of detection/response
    policies and gradually improves overall system performance.

    Safety note: This agent should NEVER run in production without strict controls,
    human oversight, or sandbox isolation.
    """

    description: str = (
        "Self-improvement agent that runs simulations to refine detection thresholds, "
        "response policies, and model hyperparameters. Uses evolutionary or RL methods "
        "to evolve better configurations over time."
    )

    def __init__(
        self,
        name: str = "optimizer-01",
        config: Optional[Dict[str, Any]] = None,
        memory: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(name, config, memory)

        self.enabled: bool = self.config.get("enabled", False)
        if not self.enabled:
            logger.warning(
                "Optimizer disabled by configuration. "
                "Set agents.optimizer.enabled: true to activate."
            )

        self.algorithm: str = self.config.get("rl_algorithm", "evolution")
        self.episodes_per_cycle: int = self.config.get("simulation_episodes", 50)
        self.interval_hours: float = self.config.get("training_interval_hours", 24.0)

        self.best_config: Dict[str, Any] = {}          # Current champion config
        self.best_score: float = -float("inf")         # Higher = better
        self.improvement_history: List[Dict[str, Any]] = []

        self._initialize_baseline()

    def _initialize_baseline(self) -> None:
        """Capture the initial/default configuration as baseline."""
        # For MVP: hard-coded example metrics to optimize
        # In real: would pull from config of ThreatDetector / ResponseEngine
        baseline = {
            "detection_threshold": 0.85,
            "response_delay_sec": 300,
            "false_positive_penalty": 10.0,
            "missed_threat_penalty": 50.0,
        }
        self.best_config = baseline.copy()
        self.remember("baseline_config", baseline)
        logger.info("Baseline configuration captured", **baseline)

    def _define_tools(self) -> Dict[str, Any]:
        """Optimizer-specific tools."""
        return {
            "run_simulation_episode": self._run_simulation_episode,
            "evaluate_policy": self._evaluate_policy,
            "propose_config_perturbation": self._propose_config_perturbation,
        }

    def _run_simulation_episode(self, config_variant: Dict[str, Any]) -> Dict[str, float]:
        """
        Tool: Simulate one episode of attack-defense in a mock environment.

        Returns dict with performance metrics:
        - true_positives
        - false_positives
        - false_negatives
        - reward (negative penalties)
        """
        # MVP: very simplified mock simulation
        # Real version would use a network simulator (e.g. mininet-like) or replay datasets

        # Mock attack patterns (randomized)
        attack_success_prob = random.uniform(0.1, 0.6)
        detection_rate = 1.0 - (config_variant["detection_threshold"] * 0.8)  # Higher threshold → fewer detections

        tp = int(100 * detection_rate * (1 - attack_success_prob))
        fp = int(50 * config_variant["detection_threshold"])  # More aggressive → more FPs
        fn = 100 - tp

        reward = (
            tp * 20.0
            - fp * config_variant["false_positive_penalty"]
            - fn * config_variant["missed_threat_penalty"]
        )

        episode_result = {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "reward": reward,
            "config": config_variant,
        }

        self.logger.debug("Simulation episode completed", **episode_result)
        return episode_result

    def _evaluate_policy(self, config_variant: Dict[str, Any]) -> float:
        """Run multiple episodes and average reward."""
        rewards = []
        for _ in range(self.episodes_per_cycle // 10):  # Sub-sample for speed in MVP
            result = self.call_tool("run_simulation_episode", config_variant=config_variant)
            rewards.append(result["reward"])

        avg_reward = sum(rewards) / len(rewards) if rewards else 0.0
        return avg_reward

    def _propose_config_perturbation(self) -> Dict[str, Any]:
        """Generate a small random change to current best config (evolution step)."""
        variant = copy.deepcopy(self.best_config)

        # Small Gaussian noise on numeric params
        for key in variant:
            if isinstance(variant[key], (int, float)):
                variant[key] += random.gauss(0, 0.05 * abs(variant[key]) + 0.01)

        # Clip to reasonable ranges
        variant["detection_threshold"] = max(0.5, min(0.98, variant["detection_threshold"]))
        variant["response_delay_sec"] = max(60, min(1800, variant["response_delay_sec"]))

        return variant

    def execute(self, input_data: Any = None) -> Dict[str, Any]:
        """
        Main optimization cycle (called periodically or manually).

        1. Propose new config variant
        2. Evaluate it via simulations
        3. If better than current best → update champion
        4. Store trajectory

        Returns:
            Dict with improvement results, new best score, etc.
        """
        if not self.enabled:
            return {"status": "disabled", "message": "Optimizer not enabled in config"}

        start_time = time.time()

        # Propose & evaluate a new candidate
        candidate_config = self.call_tool("propose_config_perturbation")
        candidate_score = self.call_tool("evaluate_policy", config_variant=candidate_config)

        improved = False
        if candidate_score > self.best_score:
            self.best_config = candidate_config
            self.best_score = candidate_score
            self.update_state("best_config", candidate_config)
            self.update_state("best_score", candidate_score)
            improved = True
            logger.info(
                "New best configuration found",
                new_score=candidate_score,
                improvement=(candidate_score - self.best_score),
                **candidate_config
            )

        # Record history
        history_entry = {
            "timestamp": time.time(),
            "score": candidate_score,
            "improved": improved,
            "config": candidate_config,
        }
        self.improvement_history.append(history_entry)
        self.remember("improvement_history", self.improvement_history[-50:])  # Keep last 50

        duration = time.time() - start_time
        return {
            "status": "success",
            "improved": improved,
            "current_best_score": self.best_score,
            "candidate_score": candidate_score,
            "cycle_duration_sec": duration,
            "episodes_evaluated": self.episodes_per_cycle // 10,
        }

    def finalize(self) -> None:
        """Save best config / history on shutdown."""
        super().finalize()
        logger.info(
            "Optimizer finalizing",
            best_score=self.best_score,
            history_length=len(self.improvement_history)
        )
        # Future: persist best_config to disk / model registry
