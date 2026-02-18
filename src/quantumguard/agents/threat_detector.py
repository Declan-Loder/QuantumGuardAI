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
        """Construct NetworkX graph from batch of log entries."""
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
            self.logger.warning("Graph exceeds max nodes – trimming")
            to_remove = sorted(G.degree, key=lambda x: x[1])[:len(G) - self.max_graph_nodes]
            G.remove_nodes_from([n for n, _ in to_remove])

        self.remember("last_built_graph", G)
        self.logger.debug("Graph constructed", nodes=G.number_of_nodes(), edges=G.number_of_edges())
        return G

    def _convert_nx_to_geometric(self, G: nx.Graph) -> Data:
        """Convert NetworkX graph to torch_geometric.Data."""
        if len(G) == 0:
            return Data(x=torch.empty((0, 16)), edge_index=torch.empty((2, 0), dtype=torch.long))

        x = torch.rand((G.number_of_nodes(), 16), dtype=torch.float)

        edge_index = []
        for u, v in G.edges():
            i = list(G.nodes).index(u)
            j = list(G.nodes).index(v)
            edge_index.extend([[i, j], [j, i]])

        edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous() if edge_index else torch.empty((2, 0), dtype=torch.long)

        data = Data(x=x, edge_index=edge_index, num_nodes=G.number_of_nodes())
        return data

    def _run_gnn_inference(self, data: Data, graph: nx.Graph = None, events: List[Dict] = None) -> Dict[str, Any]:
        """
        Execute GNN forward pass and compute meaningful threat scores.
        """
        if self.model is None:
            raise RuntimeError("No GNN model loaded")

        if data.num_nodes == 0:
            self.logger.warning("Empty graph - skipping inference")
            return {
                "anomaly_score": 0.0,
                "max_confidence": 0.0,
                "top_suspicious_nodes": [],
                "suspicious_ips": [],
                "node_count": 0,
            }

        self.model.eval()
        with torch.no_grad():
            if data.edge_index.numel() == 0:
                dummy_edge_index = torch.empty((2, 0), dtype=torch.long)
                output = self.model(data.x, dummy_edge_index)
            else:
                output = self.model(data.x, data.edge_index)

        # Meaningful scoring
        if graph is not None:
            degrees = torch.tensor([d for n, d in graph.degree()], dtype=torch.float)
            degrees_norm = degrees / (degrees.max() + 1e-6)
        else:
            degrees_norm = torch.zeros(data.num_nodes)

        # Anomaly boost from events
        anomaly_boost = torch.zeros(data.num_nodes)
        if events and graph:
            node_map = {ip: idx for idx, ip in enumerate(graph.nodes())}
            for event in events:
                if event.get("anomaly", False):
                    src = event.get("src_ip")
                    dst = event.get("dst_ip")
                    if src in node_map:
                        anomaly_boost[node_map[src]] += 0.7
                    if dst in node_map:
                        anomaly_boost[node_map[dst]] += 0.7

        anomaly_boost = torch.clamp(anomaly_boost, 0.0, 1.0)

        # Combine scores
        gnn_contrib = torch.sigmoid(output.mean(dim=1))
        combined_scores = 0.5 * degrees_norm + 0.4 * anomaly_boost + 0.1 * gnn_contrib
        node_scores = combined_scores / (combined_scores.max() + 1e-6)

        mean_score = node_scores.mean().item()
        max_score = node_scores.max().item()
        top_k_indices = torch.topk(node_scores, k=min(5, data.num_nodes)).indices.tolist()

        # Map top indices to real IPs
        suspicious_ips = []
        if graph is not None:
            node_list = list(graph.nodes())
            for idx in top_k_indices:
                if idx < len(node_list):
                    suspicious_ips.append(node_list[idx])

        result = {
            "anomaly_score": mean_score,
            "max_confidence": max_score,
            "top_suspicious_nodes": top_k_indices,
            "suspicious_ips": suspicious_ips,
            "node_count": data.num_nodes,
        }

        if max_score >= self.confidence_threshold:
            self.update_state("last_high_confidence_detection", result)
            self.logger.info("High-confidence threat signal", **result)

        return result

    def execute(self, input_data: Any) -> Dict[str, Any]:
        """
        Main detection cycle.
        """
        start = time.time()

        graph = None
        events = None

        if isinstance(input_data, list):
            events = input_data
            graph = self.call_tool("build_graph_from_logs", logs=input_data)
            data = self.call_tool("convert_nx_to_geometric", G=graph)
        elif isinstance(input_data, nx.Graph):
            graph = input_data
            data = self.call_tool("convert_nx_to_geometric", G=graph)
        elif isinstance(input_data, Data):
            data = input_data
        else:
            raise ValueError(f"Unsupported input type for ThreatDetector: {type(input_data)}")

        inference_result = self.call_tool("run_gnn_inference", data=data, graph=graph, events=events)

        duration = time.time() - start

        full_result = {
            "status": "success",
            "detection_result": inference_result,
            "graph_nodes": data.num_nodes,
            "execution_time_seconds": round(duration, 3),
            "high_confidence": inference_result["max_confidence"] >= self.confidence_threshold,
            "suspicious_ips": inference_result.get("suspicious_ips", []),
        }

        self.logger.info("Threat detection cycle completed", **full_result)

        return full_result

    def finalize(self) -> None:
        super().finalize()
        if self.model is not None:
            self.logger.info("ThreatDetector finalizing – model state preserved")