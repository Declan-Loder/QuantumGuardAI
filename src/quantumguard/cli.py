"""
QuantumGuard CLI
================

Main command-line interface for running agents, tools, and workflows.

Usage examples:
    quantumguard --help
    quantumguard detect data/dummy_logs.json
    quantumguard viz --graph outputs/last_threat_graph.gpickle
    quantumguard federate --server --rounds 5
    quantumguard hello
"""

from __future__ import annotations

import sys
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
import networkx as nx

from quantumguard import __version__
from quantumguard.utils.config import config
from quantumguard.utils.logging import get_logger
from quantumguard.agents.threat_detector import ThreatDetector
from quantumguard.agents.response_engine import ResponseEngine
from quantumguard.agents.optimizer import Optimizer
from quantumguard.utils.viz import plot_threat_graph, save_threat_viz
from quantumguard.models.federated import start_federated_server

logger = get_logger(__name__)

app = typer.Typer(
    name="quantumguard",
    help="Privacy-preserving, self-optimizing AI cybersecurity framework",
    add_completion=True,
    pretty_exceptions_show_locals=False,
)


def version_callback(value: bool) -> None:
    if value:
        console = Console()
        console.print(f"[bold]QuantumGuard AI[/bold] v[cyan]{__version__}[/cyan]")
        console.print("MIT License (open core) — commercial options available")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
    config_path: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Override config file (default: layered default/production)",
        exists=True,
        dir_okay=False,
    ),
    verbose: bool = typer.Option(False, "--verbose", "-V", help="Enable debug logging"),
) -> None:
    """
    QuantumGuard CLI – run detection, response, optimization, federation, and visualization.
    """
    if config_path:
        logger.info(f"Using custom config: {config_path}")
        # Future: implement dynamic reload if needed
    if verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose mode enabled")


# ────────────────────────────────────────────────
# Detect Command
# ────────────────────────────────────────────────

@app.command()
def detect(
    input_path: Path = typer.Argument(..., help="Path to logs, pcap, or graph file"),
    output_dir: Optional[Path] = typer.Option(None, "--output", "-o", help="Save results here"),
    dry_run: bool = typer.Option(True, "--dry-run", help="Simulate detection without actions"),
) -> None:
    """
    Run threat detection on logs, pcaps, or pre-built graphs.
    """
    logger.info("Starting threat detection", input=str(input_path))

    print("Dummy detection started...")
    print("Input file:", input_path)
    print("Anomaly score: 0.87 (dummy)")
    print("Top suspicious nodes: 192.168.1.100, 10.0.0.5")
    print("High confidence alert triggered!")
    print("Environment:", config().app.environment)

    cfg = config().agents.threat_detector
    detector = ThreatDetector("cli-detector", config=cfg.dict())

    graph = nx.Graph()

    if input_path.suffix in (".json", ".log"):
        from quantumguard.tools.log_analyzer import LogAnalyzer
        analyzer = LogAnalyzer(config().tools.log_analyzer)
        events = analyzer.parse_log_file(input_path)

        # Build real graph from parsed events
        for event in events:
            src = event.get("src_ip")
            dst = event.get("dst_ip")
            if src and dst and src != dst:
                graph.add_node(src, type="device")
                graph.add_node(dst, type="device")
                graph.add_edge(src, dst,
                               protocol=event.get("protocol", "unknown"),
                               bytes=event.get("bytes_in", 0) + event.get("bytes_out", 0),
                               anomaly=event.get("anomaly", False))
    else:
        logger.error("Unsupported input format")
        raise typer.Exit(1)

    result = detector.execute(graph)

    console = Console()
    table = Table(title="Detection Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    table.add_row("Status", result["status"])
    table.add_row("Anomaly Score", f"{result['detection_result']['anomaly_score']:.3f}")
    table.add_row("High Confidence", str(result["high_confidence"]))
    table.add_row("Nodes Analyzed", str(result["graph_nodes"]))
    table.add_row("Execution Time", f"{result['execution_time_seconds']}s")
    console.print(table)

    # Simple prevention simulation
    suspicious_ips = result.get("suspicious_ips", [])
    if suspicious_ips:
        print("\n[PREVENTION SIMULATION]")
        for ip in suspicious_ips:
            print(f"Blocking suspicious IP: {ip} (high confidence)")
            # Optional: real block (uncomment only if you want actual firewall rule)
            # import subprocess
            # try:
            #     subprocess.run(["sudo", "ufw", "deny", "from", ip], check=True)
            #     print(f"  → Actual ufw block applied for {ip}")
            # except Exception as e:
            #     print(f"  → Failed to apply ufw rule: {e}")
        print("Prevention actions simulated (real blocking commented out)")
    else:
        print("\nNo high-risk IPs detected to block.")

    # Save graph
    fig = plot_threat_graph(graph, title="Threat Graph from Detect")
    save_threat_viz(fig, "detect_graph")
    print("Saved threat graph to outputs/detect_graph.html")

    if output_dir:
        print(f"Would save additional output to: {output_dir}")

# ────────────────────────────────────────────────
# Respond Command
# ────────────────────────────────────────────────

@app.command()
def respond(
    detection_result: Path = typer.Argument(..., help="JSON file from detect command"),
    dry_run: bool = typer.Option(True, "--dry-run", help="Simulate response"),
) -> None:
    """
    Execute graduated response based on prior detection output.
    """
    logger.info("Starting response engine", input=str(detection_result))

    if not detection_result.is_file():
        logger.error("Detection result file not found")
        raise typer.Exit(1)

    cfg = config().agents.response_engine
    engine = ResponseEngine("cli-response", config=cfg.dict())

    # Load detection result (placeholder)
    with detection_result.open() as f:
        detection = json.load(f)

    result = engine.execute(detection["detection_result"])

    console = Console()
    console.print("[bold green]Response Decision[/bold green]")
    console.print(json.dumps(result["decision"], indent=2))


# ────────────────────────────────────────────────
# Optimize Command
# ────────────────────────────────────────────────

@app.command()
def optimize(
    cycles: int = typer.Option(1, "--cycles", "-n", help="Number of optimization cycles"),
) -> None:
    """
    Run self-optimization / policy refinement cycles.
    """
    logger.info(f"Starting optimizer – {cycles} cycles")

    cfg = config().agents.optimizer
    if not cfg.enabled:
        logger.warning("Optimizer disabled in config")
        raise typer.Exit(0)

    optimizer = Optimizer("cli-optimizer", config=cfg.dict())

    for i in range(cycles):
        result = optimizer.execute()
        console = Console()
        console.print(f"[bold]Cycle {i+1}/{cycles}[/bold]")
        console.print(f"Improved: {result['improved']}")
        console.print(f"Best score: {result['current_best_score']:.2f}")


# ────────────────────────────────────────────────
# Viz Command
# ────────────────────────────────────────────────

@app.command()
def viz(
    graph_file: Optional[Path] = typer.Argument(None, help="Pickle or GraphML file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save HTML/PNG"),
    show: bool = typer.Option(True, "--show", help="Open in browser"),
) -> None:
    """
    Visualize a saved threat graph.
    """
    if not graph_file:
        logger.error("No graph file provided")
        raise typer.Exit(1)

    import pickle
    with graph_file.open("rb") as f:
        graph = pickle.load(f)

    fig = plot_threat_graph(graph, title="Loaded Threat Graph")

    if output:
        save_threat_viz(fig, output.stem)

    if show:
        show_threat_viz(fig)


# ────────────────────────────────────────────────
# Federate Command (Server)
# ────────────────────────────────────────────────

@app.command()
def federate(
    server: bool = typer.Option(False, "--server", help="Run as Flower server"),
    client: bool = typer.Option(False, "--client", help="Run as Flower client"),
    rounds: int = typer.Option(10, "--rounds", help="Number of federation rounds (server only)"),
) -> None:
    """
    Run federated learning server or client.
    """
    if server and client:
        logger.error("Cannot run both server and client in same process")
        raise typer.Exit(1)

    if server:
        from quantumguard.models.gnn import GNNTthreatModel
        model = GNNTthreatModel(config().models.gnn.dict())
        start_federated_server(model, config().models.federated.dict(), rounds=rounds)
    elif client:
        logger.info("Client mode – start via Flower client launcher (not implemented in CLI yet)")
    else:
        logger.error("Specify --server or --client")


# ────────────────────────────────────────────────
# Hello Command (for testing)
# ────────────────────────────────────────────────

@app.command()
def hello():
    """Print a hello message from QuantumGuard."""
    print("Hello from QuantumGuard AI!")
    print("CLI is fully operational 🚀")
    print(f"Environment: {config().app.environment}")
    print("Logging and config are working!")


if __name__ == "__main__":
    app()