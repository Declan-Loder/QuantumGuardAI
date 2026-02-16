"""
Visualization Utilities
=======================

Tools for rendering interactive network/threat graphs.

Uses:
- NetworkX for graph operations
- Plotly for interactive HTML visualizations

Key functions:
- plot_threat_graph(nx.Graph) → interactive Plotly figure
- save_threat_viz(fig, path) → HTML or PNG export
- show_in_browser(fig) → open in default browser

Configuration keys (from utils.viz):
- default_layout: 'spring' | 'kamada_kawai' | 'circular' (default: spring)
- node_color_scale: str (Plotly colorscale, default: 'Viridis')
- output_format: 'html' | 'png' (default: html)
"""

from __future__ import annotations

import json
import webbrowser
from pathlib import Path
from typing import Any, Dict, Optional

import networkx as nx
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from quantumguard.utils.config import config
from quantumguard.utils.logging import get_logger

logger = get_logger(__name__)

class ThreatGraphVisualizer:
    """
    Helper class for visualizing threat graphs with Plotly.
    """

    def __init__(self) -> None:
        self.layout_type: str = config().utils.viz.get("default_layout", "spring")
        self.color_scale: str = config().utils.viz.get("node_color_scale", "Viridis")
        self.output_format: str = config().utils.viz.get("output_format", "html")

    def plot_threat_graph(
        self,
        graph: nx.Graph,
        anomaly_scores: Optional[Dict[Any, float]] = None,
        title: str = "Threat Network Graph",
        node_size: int = 20,
        edge_width: float = 1.0,
        height: int = 800,
        width: int = 1200,
    ) -> go.Figure:
        """
        Create interactive Plotly visualization of a NetworkX graph.

        - Nodes colored by anomaly score (if provided) or degree
        - Hover shows IP, degree, anomaly, ports, etc.
        - Edges sized by traffic volume or count
        """
        if not graph.nodes:
            logger.warning("Empty graph – returning blank figure")
            return go.Figure()

        # Compute positions
        pos_methods = {
            "spring": nx.spring_layout,
            "kamada_kawai": nx.kamada_kawai_layout,
            "circular": nx.circular_layout,
        }
        layout_func = pos_methods.get(self.layout_type, nx.spring_layout)
        pos = layout_func(graph)

        # Node properties
        node_x, node_y = [], []
        node_text, node_color, node_size_list = [], [], []

        for node in graph.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)

            # Hover text
            degree = graph.degree(node)
            anomaly = anomaly_scores.get(node, 0.0) if anomaly_scores else 0.0
            ports = graph.nodes[node].get("ports", set())
            text = f"IP: {node}<br>Degree: {degree}<br>Anomaly: {anomaly:.3f}"
            if ports:
                text += f"<br>Ports: {', '.join(map(str, sorted(ports)))}"
            node_text.append(text)

            # Color by anomaly or degree
            color_value = anomaly if anomaly_scores else degree
            node_color.append(color_value)
            node_size_list.append(node_size + 5 * anomaly)  # Bigger for high anomaly

        # Edge properties
        edge_x, edge_y = [], []
        for edge in graph.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(
            x=edge_x,
            y=edge_y,
            line=dict(width=edge_width, color="#888"),
            hoverinfo="none",
            mode="lines",
        )

        node_trace = go.Scatter(
            x=node_x,
            y=node_y,
            mode="markers+text",
            hoverinfo="text",
            marker=dict(
                showscale=True,
                colorscale=self.color_scale,
                color=node_color,
                size=node_size_list,
                colorbar=dict(
                    thickness=15,
                    title="Anomaly / Degree",
                    xanchor="left",
                    titleside="right",
                ),
                line_width=2,
            ),
            text=node_text,
            textposition="top center",
        )

        fig = go.Figure(
            data=[edge_trace, node_trace],
            layout=go.Layout(
                title=title,
                titlefont_size=16,
                showlegend=False,
                hovermode="closest",
                margin=dict(b=20, l=5, r=5, t=40),
                height=height,
                width=width,
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            ),
        )

        logger.debug("Threat graph figure created", nodes=graph.number_of_nodes(), edges=graph.number_of_edges())
        return fig

    def save_viz(
        self,
        fig: go.Figure,
        filename: str = "threat_graph",
        directory: Optional[str] = None,
    ) -> Path:
        """
        Save visualization to file.

        - HTML: interactive
        - PNG: static (requires kaleido)
        """
        out_dir = Path(directory or config().paths.outputs_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        path = out_dir / f"{filename}.{self.output_format}"
        if self.output_format == "html":
            fig.write_html(path, include_plotlyjs="cdn")
        elif self.output_format == "png":
            fig.write_image(path)
        else:
            raise ValueError(f"Unsupported output format: {self.output_format}")

        logger.info("Visualization saved", path=str(path))
        return path

    def show_in_browser(self, fig: go.Figure) -> None:
        """Open interactive graph in default web browser."""
        temp_path = Path("temp_threat_viz.html")
        fig.write_html(temp_path, include_plotlyjs="cdn")
        webbrowser.open(f"file://{temp_path.absolute()}")
        logger.info("Visualization opened in browser")

# Global singleton instance (lazy-loaded)
_viz_instance: Optional[ThreatGraphVisualizer] = None


def get_viz() -> ThreatGraphVisualizer:
    """Get the visualization helper (singleton)."""
    global _viz_instance
    if _viz_instance is None:
        _viz_instance = ThreatGraphVisualizer()
    return _viz_instance


def plot_threat_graph(
    graph: nx.Graph,
    anomaly_scores: Optional[Dict[Any, float]] = None,
    **kwargs: Any
) -> go.Figure:
    """Convenience function to plot a threat graph."""
    return get_viz().plot_threat_graph(graph, anomaly_scores, **kwargs)


def save_threat_viz(fig: go.Figure, filename: str = "threat_graph") -> Path:
    """Convenience: save figure to outputs dir."""
    return get_viz().save_viz(fig, filename)


def show_threat_viz(fig: go.Figure) -> None:
    """Convenience: open figure in browser."""
    get_viz().show_in_browser(fig)
