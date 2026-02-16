"""
QuantumGuard AI - Models Package
================================

This submodule contains the core trainable / inferable ML models used by agents.

Current models:
- GNNTthreatModel: Graph Neural Network backbone for threat/anomaly detection
  (GraphSAGE / GAT / GIN variants, PyTorch Geometric)

Future extensions (planned):
- FederatedAggregator: Wrapper around Flower strategies
- QuantumResistantCrypto: Post-quantum primitives (Kyber, Dilithium wrappers)
- PolicyNetwork: For reinforcement learning in Optimizer agent

Public API:
    GNNTthreatModel          → Main GNN for network threat modeling
    (add more as implemented)

All models should:
- Accept config dicts for hyperparameter flexibility
- Support .from_config() classmethod for easy instantiation
- Be compatible with torch.save / torch.load for checkpointing
- Provide .eval() / .train() modes and device placement
"""

from __future__ import annotations

from .gnn import GNNTthreatModel

__all__ = [
    "GNNTthreatModel",
    # Add new models here as they are implemented, e.g.
    # "FederatedAggregator",
    # "QuantumResistantCrypto",
]

# Optional submodule version (useful for debugging or when models have breaking changes)
__version__ = "0.1.0-dev"
