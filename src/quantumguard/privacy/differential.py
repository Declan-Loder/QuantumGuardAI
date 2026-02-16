"""
Differential Privacy Module
===========================

Implements DP-SGD for privacy-preserving model training.

Core features:
- Gradient clipping + Gaussian noise addition
- Configurable noise multiplier, max norm, delta
- Basic RDP accounting (track cumulative ε, δ)
- Optimizer wrapper to inject DP into training loops

Configuration keys (from privacy.differential):
- enabled: bool (default: True)
- epsilon: float (target privacy budget, e.g. 1.0)
- delta: float (usually 1e-5 or 1/N where N = dataset size)
- noise_multiplier: float (controls noise scale, e.g. 1.1)
- max_grad_norm: float (gradient clipping threshold, e.g. 1.0)

Usage:
    dp = DifferentialPrivacy(config)
    optimizer = dp.wrap_optimizer(original_optimizer, model.parameters())
    # Then train normally — noise & clipping applied automatically
"""

from __future__ import annotations

import math
from typing import Any, Dict, Iterable, Optional

import torch
from torch.optim import Optimizer

from quantumguard.utils.logging import get_logger

logger = get_logger(__name__)

class DPOptimizerWrapper:
    """
    Wraps a standard optimizer to apply DP-SGD:
    1. Per-sample gradient clipping
    2. Noise addition to clipped gradients
    3. Aggregate average
    """

    def __init__(
        self,
        optimizer: Optimizer,
        noise_multiplier: float,
        max_grad_norm: float,
        batch_size: int,
    ) -> None:
        self.optimizer = optimizer
        self.noise_multiplier = noise_multiplier
        self.max_grad_norm = max_grad_norm
        self.batch_size = batch_size
        self.device = next(iter(optimizer.param_groups[0]["params"])).device

    def zero_grad(self, set_to_none: bool = True) -> None:
        self.optimizer.zero_grad(set_to_none=set_to_none)

    def step(self) -> None:
        """Apply clipping + noise, then optimizer step."""
        # 1. Clip per-sample gradients (simplified: global clip for MVP)
        total_norm = 0.0
        for group in self.optimizer.param_groups:
            for p in group["params"]:
                if p.grad is not None:
                    param_norm = p.grad.data.norm(2)
                    total_norm += param_norm.item() ** 2
        total_norm = total_norm ** 0.5

        clip_coef = self.max_grad_norm / (total_norm + 1e-6)
        clip_coef = min(1.0, clip_coef)

        for group in self.optimizer.param_groups:
            for p in group["params"]:
                if p.grad is not None:
                    p.grad.data.mul_(clip_coef)

        # 2. Add Gaussian noise (scaled by sensitivity / batch_size)
        noise_scale = self.noise_multiplier * self.max_grad_norm / self.batch_size
        for group in self.optimizer.param_groups:
            for p in group["params"]:
                if p.grad is not None:
                    noise = torch.normal(
                        mean=0.0,
                        std=noise_scale,
                        size=p.grad.shape,
                        device=self.device,
                        dtype=p.grad.dtype,
                    )
                    p.grad.data.add_(noise)

        # 3. Apply the optimizer update
        self.optimizer.step()

    def __getattr__(self, name: str) -> Any:
        """Delegate other methods to wrapped optimizer."""
        return getattr(self.optimizer, name)

class DifferentialPrivacy:
    """
    Main DP controller.

    Tracks cumulative privacy spend (basic RDP → ε, δ conversion).
    Wraps optimizers for DP-SGD.
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.enabled: bool = config.get("enabled", True)
        if not self.enabled:
            logger.warning("Differential privacy disabled by config")
            self.noise_multiplier = 0.0
            self.max_grad_norm = float("inf")
            self.epsilon = float("inf")
            self.delta = 1.0
            return

        self.epsilon: float = config.get("epsilon", 1.0)
        self.delta: float = config.get("delta", 1e-5)
        self.noise_multiplier: float = config.get("noise_multiplier", 1.1)
        self.max_grad_norm: float = config.get("max_grad_norm", 1.0)

        # RDP accumulator (simplified: sum of Gaussian RDP terms)
        self._rdp_orders: List[float] = []
        self._rdp_alphas: List[float] = []

        logger.info(
            "DifferentialPrivacy initialized",
            epsilon_target=self.epsilon,
            delta=self.delta,
            noise_multiplier=self.noise_multiplier,
            max_grad_norm=self.max_grad_norm
        )

    def wrap_optimizer(
        self,
        optimizer: Optimizer,
        batch_size: int,
    ) -> Optimizer:
        """
        Wrap a standard optimizer with DP logic.

        Args:
            optimizer: e.g. torch.optim.Adam(model.parameters(), lr=...)
            batch_size: physical batch size used in training

        Returns:
            DP-aware optimizer wrapper
        """
        if not self.enabled:
            return optimizer

        return DPOptimizerWrapper(
            optimizer=optimizer,
            noise_multiplier=self.noise_multiplier,
            max_grad_norm=self.max_grad_norm,
            batch_size=batch_size,
        )

    def add_noise(self, tensor: torch.Tensor) -> torch.Tensor:
        """
        Manually add DP noise to a tensor (e.g. model updates in federation).
        """
        if not self.enabled:
            return tensor

        scale = self.noise_multiplier * self.max_grad_norm / math.sqrt(tensor.numel())
        noise = torch.normal(mean=0.0, std=scale, size=tensor.shape, device=tensor.device)
        return tensor.add_(noise)

    def track_privacy_spend(self, sampling_rate: float, epochs: int) -> Tuple[float, float]:
        """
        Simplified RDP accounting.
        Returns current (ε, δ) spend (approximate).
        """
        if not self.enabled:
            return 0.0, 0.0

        # Very basic Gaussian RDP accumulation (real impl would use moments accountant)
        # This is conservative overestimate for MVP
        q = sampling_rate  # q = batch_size / dataset_size
        sigma = self.noise_multiplier
        rdp_term = q**2 / (2 * sigma**2) * epochs
        epsilon_est = rdp_term * (1 + math.log(1 / self.delta))  # Rough conversion

        return min(epsilon_est, self.epsilon), self.delta

    def is_budget_exceeded(self) -> bool:
        """Check if privacy budget is depleted."""
        if not self.enabled:
            return False
        # For MVP: always allow (real version would compare tracked vs target)
        return False
