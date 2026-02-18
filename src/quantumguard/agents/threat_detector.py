"""
Threat Detector Agent
=====================

Core agent for real-time threat detection using Graph Neural Networks (GNNs).

Workflow:
1. Ingest network data (logs, flows, pcaps)
2. Build or update dynamic interaction graph (NetworkX)
3. Convert to torch_geometric Data format
4. Run GNN inference for node/edge/subgraph anomaly scoring
5. Filter high-confidence threats
6. Store detections and recent graphs in memory for temporal correlation

Configuration keys (from agents.threat_detector):
- confidence_threshold (float): minimum score to raise alert
- max_graph_nodes (int): safety cap to prevent OOM
- model (str): reference to GNN model type/config

For MVP: uses simple random outputs + dummy conversion.
Will be replaced with real GNN forward pass once models/gnn.py is implemented.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import networkx as nx
import torch
from torch_geometric.data import Data

from quantumguard.agents.base import BaseAgent
from quantumguard.models.gnn import GNNTthreatModel
from quantumguard.utils.logging import get_logger

logger = get_logger(__name__)

class ThreatDetector(BaseAgent):
    """
    GNN-based threat detection agent.

    Primary inputs:
    - List[Dict]: raw log entries (Zeek, Suricata, NetFlow, etc.)
    - nx.Graph: pre-constructed network graph
    - torch_geometric.Data: ready-to-infer graph

    Outputs:
    - Dict containing anomaly_score, top_suspicious_nodes, confidence, etc.
    - Stores high-confidence detections in memory/state
    """

    description: str = (
        "Analyzes network interaction graphs using Graph Neural Networks to detect "
        "anomalies, malicious nodes, command-and-control channels, and lateral movement. "
        "Produces scored threat signals for the ResponseEngine."
    )

    def __init__(
        self,
        name: str = "threat-detector-01",
        config: Optional[Dict[str, Any]] = None,
        memory: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(name, config, memory)

        self.confidence_threshold: float = self.config.get("confidence_threshold", 0.85)
        self.max_graph_nodes: int = self.config.get("max_graph_nodes", 5000)

        self.model: Optional[GNNTthreatModel] = None
        self._load_model()

    def _load_model(self) -> None:
        """Initialize or load the GNN threat model."""
        gnn_config = self.config.get("models", {}).get("gnn", {})
        try:
            self.model = GNNTthreatModel(gnn_config)
            self.logger.info("Threat model loaded", model_type=self.model.__class__.__name__)
        except Exception as e:
            self.logger.error("Failed to initialize GNN model", error=str(e))
            raise RuntimeError("GNN model failed to load") from e

    def _define_tools(self) -> Dict[str, Any]:
        return {
            "build_graph_from_logs": self._build_graph_from_logs,
            "convert_nx_to_geometric": self._convert_nx_to_geometric,
            "run_gnn_inference": self._run_gnn_inference,
        }

    def _build_graph_from_logs(self, logs: List[Dict[str, Any]]) -> nx.Graph:
        """
        Tool: Construct NetworkX graph from batch of log entries.
        """
        G = nx.Graph()

        for entry in logs:
            src = entry.get("src_ip")
            dst = entry.get("dst_ip")
            if not src or not dst or src == dst:
                continue

            if src not in G:
                G.add_node(src, type="device", bytes_out=0, bytes_in=0, anomalies=0)
            if dst not in G:
                G.add_node(dst, type="device", bytes_out=0, bytes_in=0, anomalies=0)

            key = (src, dst)
            if not G.has_edge(*key):
                G.add_edge(src, dst,
                           protocol=entry.get("protocol", "unknown"),
                           bytes=entry.get("bytes", 0),
                           duration=entry.get("duration", 0),
                           count=1)
            else:
                data = G.edges[src, dst]
                data["bytes"] += entry.get("bytes", 0)
                data["count"] += 1

            G.nodes[src]["bytes_out"] += entry.get("bytes", 0)
            G.nodes[dst]["bytes_in"] += entry.get("bytes", 0)

            if entry.get("anomaly", False):
                G.nodes[src]["anomalies"] += 1
                G.nodes[dst]["anomalies"] += 1

        if len(G) > self.max_graph_nodes:
            self.logger.warning("Graph exceeds max nodes – applying simple trim")
            to_remove = sorted(G.degree, key=lambda x: x[1])[:len(G) - self.max_graph_nodes]
            G.remove_nodes_from([n for n, _ in to_remove])

        self.remember("last_built_graph", G)
        self.logger.debug("Graph constructed", nodes=G.number_of_nodes(), edges=G.number_of_edges())
        return G

    def _convert_nx_to_geometric(self, G: nx.Graph) -> Data:
        """
        Tool: Convert NetworkX graph to torch_geometric.Data.
        MVP: dummy features (real version extracts meaningful node/edge attrs)
        """
        if len(G) == 0:
            return Data(x=torch.empty((0, 16)), edge_index=torch.empty((2, 0), dtype=torch.long))

        # Dummy node features (16-dim)
        x = torch.rand((G.number_of_nodes(), 16), dtype=torch.float)

        # Edge index (undirected → bidirectional)
        edge_index = []
        for u, v in G.edges():
            i = list(G.nodes).index(u)
            j = list(G.nodes).index(v)
            edge_index.extend([[i, j], [j, i]])

        edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous() if edge_index else torch.empty((2, 0), dtype=torch.long)

        data = Data(x=x, edge_index=edge_index, num_nodes=G.number_of_nodes())
        return data

    def _run_gnn_inference(self, data: Data) -> Dict[str, Any]:
        """
        Tool: Execute GNN forward pass.
        Returns high-level threat metrics.
        MVP: random scores (replace with real model forward pass)
        """
        if self.model is None:
            raise RuntimeError("No GNN model loaded")

        if data.num_nodes == 0:
            self.logger.warning("Empty graph - skipping inference")
            return {
                "anomaly_score": 0.0,
                "max_confidence": 0.0,
                "top_suspicious_nodes": [],
                "node_count": 0,
            }

        self.model.eval()
        with torch.no_grad():
            # Use real node features and edge_index from data
            # If edge_index is empty, skip or use dummy
            if data.edge_index.numel() == 0:
                dummy_edge_index = torch.empty((2, 0), dtype=torch.long)
                output = self.model(data.x, dummy_edge_index)
            else:
                output = self.model(data.x, data.edge_index)

        # Placeholder scoring (real model will return proper logits/scores)
        node_scores = torch.rand(data.num_nodes)  # Dummy anomaly probabilities
        mean_score = node_scores.mean().item()
        max_score = node_scores.max().item()
        top_k_indices = torch.topk(node_scores, k=min(5, data.num_nodes)).indices.tolist()

        result = {
            "anomaly_score": mean_score,
            "max_confidence": max_score,
            "top_suspicious_nodes": top_k_indices,
            "node_count": data.num_nodes,
        }

        if max_score >= self.confidence_threshold:
            self.update_state("last_high_confidence_detection", result)
            self.logger.info("High-confidence threat signal", **result)

        return result

    def execute(self, input_data: Any) -> Dict[str, Any]:
        """
        Main detection cycle.

        Supported input_data types:
        - List[Dict]: raw logs → build graph → infer
        - nx.Graph: pre-built graph → convert → infer
        - Data: ready geometric data → infer directly

        Returns standardized detection result for ResponseEngine.
        """
        start = time.time()

        if isinstance(input_data, list):
            graph = self.call_tool("build_graph_from_logs", logs=input_data)
            data = self.call_tool("convert_nx_to_geometric", G=graph)
        elif isinstance(input_data, nx.Graph):
            data = self.call_tool("convert_nx_to_geometric", G=input_data)
        elif isinstance(input_data, Data):
            data = input_data
        else:
            raise ValueError(f"Unsupported input type for ThreatDetector: {type(input_data)}")

        inference_result = self.call_tool("run_gnn_inference", data=data)

        duration = time.time() - start

        full_result = {
            "status": "success",
            "detection_result": inference_result,
            "graph_nodes": data.num_nodes,
            "execution_time_seconds": round(duration, 3),
            "high_confidence": inference_result["max_confidence"] >= self.confidence_threshold,
        }

        self.logger.info("Threat detection cycle completed", **full_result)

        return full_result

    def finalize(self) -> None:
        super().finalize()
        if self.model is not None:
            self.logger.info("ThreatDetector finalizing – model state preserved")
            