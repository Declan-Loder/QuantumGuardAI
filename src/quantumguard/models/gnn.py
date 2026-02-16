"""
Graph Neural Network (GNN) Threat Model
=======================================

Core GNN model for network threat detection.

Architecture (MVP):
- GraphSAGE convolutional layers (mean aggregator)
- Optional: GAT (attention) or GIN (isomorphism-aware)
- Multi-layer MLP readout for node-level predictions
- Output: per-node anomaly scores / malicious probabilities

Features (node):
- Degree, centrality measures
- Port statistics, protocol counts
- Behavioral vectors (bytes in/out, timing anomalies)

Features (edge):
- Protocol type (one-hot)
- Bytes transferred, duration, packet count

Tasks (configurable):
- Node classification (benign/malicious)
- Link prediction (potential C2 channels)
- Subgraph classification (attack patterns) – future

Usage:
    model = GNNTthreatModel.from_config(config)
    model.to(device)
    out = model(x, edge_index)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Tuple

import torch
import torch.nn.functional as F
from torch import nn
from torch_geometric.nn import GraphSAGE, GATConv, GINConv
from torch_geometric.nn import global_mean_pool

logger = logging.getLogger(__name__)

class GNNTthreatModel(nn.Module):
    """
    Flexible GNN for cybersecurity threat detection on network graphs.

    Args:
        config: Dict with hyperparameters (from models.gnn section)
            - type: 'graphsage' | 'gat' | 'gin' (default: graphsage)
            - hidden_channels: int (default: 128)
            - num_layers: int (default: 3)
            - dropout: float (default: 0.2)
            - out_channels: int (default: 2 for binary classification)
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__()

        self.config = config
        self.type: str = config.get("type", "graphsage").lower()
        self.hidden_channels: int = config.get("hidden_channels", 128)
        self.num_layers: int = config.get("num_layers", 3)
        self.dropout: float = config.get("dropout", 0.2)
        self.out_channels: int = config.get("out_channels", 2)  # Binary: benign/malicious

        # Input channels (node feature dim) – set dynamically or fixed
        self.in_channels: int = config.get("in_channels", 16)  # Default dummy size

        self.convs = nn.ModuleList()
        self._build_convs()

        # Readout MLP for node-level predictions
        self.readout = nn.Sequential(
            nn.Linear(self.hidden_channels, self.hidden_channels // 2),
            nn.ReLU(),
            nn.Dropout(self.dropout),
            nn.Linear(self.hidden_channels // 2, self.out_channels),
        )

        logger.info(
            "GNNTthreatModel initialized",
            type=self.type,
            layers=self.num_layers,
            hidden=self.hidden_channels,
            dropout=self.dropout,
            out_channels=self.out_channels
        )

    def _build_convs(self) -> None:
        """Build convolutional layers based on type."""
        in_ch = self.in_channels
        for i in range(self.num_layers):
            if self.type == "graphsage":
                conv = GraphSAGE(
                    in_channels=in_ch,
                    hidden_channels=self.hidden_channels,
                    num_layers=1,
                    aggr="mean",
                )
            elif self.type == "gat":
                conv = GATConv(
                    in_channels=in_ch,
                    out_channels=self.hidden_channels,
                    heads=4,
                    concat=True,
                    dropout=self.dropout,
                )
                # Adjust for multi-head concat
                if i < self.num_layers - 1:
                    self.hidden_channels *= 4
            elif self.type == "gin":
                mlp = nn.Sequential(
                    nn.Linear(in_ch, self.hidden_channels),
                    nn.ReLU(),
                    nn.Linear(self.hidden_channels, self.hidden_channels),
                )
                conv = GINConv(mlp, train_eps=True)
            else:
                raise ValueError(f"Unsupported GNN type: {self.type}")

            self.convs.append(conv)
            in_ch = self.hidden_channels

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> 'GNNTthreatModel':
        """Factory method for easy instantiation from YAML config."""
        return cls(config)

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """
        Forward pass.

        Args:
            x: Node feature matrix [num_nodes, in_channels]
            edge_index: Edge indices [2, num_edges]
            batch: Batch vector for graph pooling (optional)

        Returns:
            Node-level logits/scores [num_nodes, out_channels]
        """
        h = x

        for conv in self.convs:
            h = conv(h, edge_index)
            h = F.relu(h)
            h = F.dropout(h, p=self.dropout, training=self.training)

        # Readout: node-level prediction
        out = self.readout(h)

        # Optional: graph-level pooling if batch provided
        if batch is not None:
            out = global_mean_pool(out, batch)

        return out

    def get_parameters(self) -> Dict[str, torch.Tensor]:
        """Return state dict for serialization / federation."""
        return self.state_dict()

    def load_checkpoint(self, path: str) -> None:
        """Load model weights from checkpoint."""
        state_dict = torch.load(path, map_location="cpu")
        self.load_state_dict(state_dict)
        logger.info(f"Loaded checkpoint from {path}")

    def save_checkpoint(self, path: str) -> None:
        """Save current weights."""
        torch.save(self.state_dict(), path)
        logger.info(f"Saved checkpoint to {path}")
