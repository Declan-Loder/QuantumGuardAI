"""
Federated Learning Module
=========================

Implements privacy-preserving model training across distributed clients using Flower (flwr).

Key components:
- FlowerStrategy: Custom FedAvg wrapper with configurable parameters
- Client: Local training logic (fit, evaluate on private data)
- Server-side aggregation (standard FedAvg for MVP)
- Checkpointing & model serialization

This module is used by:
- Optimizer agent (for periodic federated improvement rounds)
- Future: dedicated federation CLI / daemon

Configuration keys (from models.federated):
- strategy: 'fedavg' (extensible to fedprox, fednova, etc.)
- num_rounds: total federation rounds
- clients_per_round: fraction or number of clients sampled per round
- local_epochs: epochs each client trains locally
- min_fit_clients / min_available_clients: safety thresholds

Dependencies: flwr, torch, torch_geometric
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, cast

import flwr as fl
import torch
from flwr.common import NDArrays, Parameters, Scalar, ndarrays_to_parameters
from flwr.server.strategy import FedAvg
from torch.utils.data import DataLoader

from quantumguard.models.gnn import GNNTthreatModel
from quantumguard.utils.config import Config  # We'll implement this later
from quantumguard.utils.logging import get_logger

logger = get_logger(__name__)

class QuantumGuardClient(fl.client.NumPyClient):
    """
    Flower client for local training on private network data.

    Each client (e.g., per organization/network segment):
    - Receives global model parameters
    - Trains locally on its private dataset
    - Returns updated parameters + metrics
    """

    def __init__(
        self,
        cid: str,                           # Client ID (e.g. "org-1", "node-42")
        model: GNNTthreatModel,
        trainloader: DataLoader,
        valloader: DataLoader,
        local_epochs: int = 5,
    ) -> None:
        self.cid = cid
        self.model = model
        self.trainloader = trainloader
        self.valloader = valloader
        self.local_epochs = local_epochs
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        logger.info(f"Client {cid} initialized", device=self.device.type, epochs=local_epochs)

    def get_parameters(self, config: Dict[str, Scalar]) -> NDArrays:
        """Return local model parameters as NumPy arrays."""
        return [val.cpu().numpy() for _, val in self.model.state_dict().items()]

    def set_parameters(self, parameters: NDArrays) -> None:
        """Update local model with global parameters."""
        params_dict = zip(self.model.state_dict().keys(), parameters)
        state_dict = {k: torch.tensor(v) for k, v in params_dict}
        self.model.load_state_dict(state_dict, strict=True)
        logger.debug(f"Client {self.cid} received global parameters")

    def fit(
        self,
        parameters: NDArrays,
        config: Dict[str, Scalar],
    ) -> Tuple[NDArrays, int, Dict[str, Scalar]]:
        """Local training loop."""
        self.set_parameters(parameters)

        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)  # Configurable later
        criterion = torch.nn.CrossEntropyLoss()  # Or BCEWithLogitsLoss for multi-label

        self.model.train()
        total_loss = 0.0
        total_samples = 0

        for epoch in range(self.local_epochs):
            for batch in self.trainloader:
                x, edge_index, y = batch.x.to(self.device), batch.edge_index.to(self.device), batch.y.to(self.device)

                optimizer.zero_grad()
                out = self.model(x, edge_index)
                loss = criterion(out, y)
                loss.backward()
                optimizer.step()

                total_loss += loss.item() * x.size(0)
                total_samples += x.size(0)

            logger.debug(f"Client {self.cid} epoch {epoch+1}/{self.local_epochs} completed", loss=loss.item())

        # Return updated parameters, number of examples, metrics
        metrics = {"loss": total_loss / total_samples if total_samples > 0 else 0.0}
        return self.get_parameters(config={}), total_samples, metrics

    def evaluate(
        self,
        parameters: NDArrays,
        config: Dict[str, Scalar],
    ) -> Tuple[float, int, Dict[str, Scalar]]:
        """Local evaluation on validation set."""
        self.set_parameters(parameters)
        self.model.eval()

        total_loss = 0.0
        correct = 0
        total = 0

        criterion = torch.nn.CrossEntropyLoss()

        with torch.no_grad():
            for batch in self.valloader:
                x, edge_index, y = batch.x.to(self.device), batch.edge_index.to(self.device), batch.y.to(self.device)
                out = self.model(x, edge_index)
                loss = criterion(out, y)
                total_loss += loss.item() * x.size(0)
                pred = out.argmax(dim=1)
                correct += (pred == y).sum().item()
                total += y.size(0)

        loss = total_loss / total if total > 0 else 0.0
        accuracy = correct / total if total > 0 else 0.0

        return loss, total, {"accuracy": accuracy, "loss": loss}

def get_flower_strategy(config: Dict[str, Any]) -> fl.server.strategy.Strategy:
    """
    Factory for Flower strategy (FedAvg for MVP).

    Configurable via models.federated section.
    """
    fraction_fit = config.get("clients_per_round", 0.3)  # Fraction of available clients
    min_fit_clients = config.get("min_fit_clients", 2)
    min_available_clients = config.get("min_available_clients", 2)

    return FedAvg(
        fraction_fit=fraction_fit,
        min_fit_clients=min_fit_clients,
        min_available_clients=min_available_clients,
        min_evaluate_clients=min_available_clients,
        fraction_evaluate=1.0,
        evaluate_fn=None,  # Centralized eval optional
        on_fit_config_fn=None,
        on_evaluate_config_fn=None,
        accept_failures=True,
        initial_parameters=None,  # Set later
    )

def start_federated_server(
    model: GNNTthreatModel,
    config: Dict[str, Any],
    server_address: str = "0.0.0.0:8080",
    checkpoint_dir: Optional[Path] = None,
) -> None:
    """
    Launch Flower server for federation rounds.

    Call this from CLI or orchestrator script.
    """
    strategy = get_flower_strategy(config)

    # Initial parameters from fresh model
    initial_parameters = ndarrays_to_parameters(model.get_parameters({}))

    fl.server.start_server(
        server_address=server_address,
        config=fl.server.ServerConfig(num_rounds=config.get("num_rounds", 10)),
        strategy=strategy,
        client_resources={"num_cpus": 2, "num_gpus": 0.0},  # Configurable
    )

    # Optional: save final aggregated model
    if checkpoint_dir:
        final_path = checkpoint_dir / "final_federated_model.pt"
        torch.save(model.state_dict(), final_path)
        logger.info(f"Final federated model saved to {final_path}")

# Client factory (used by Flower client launcher)
def client_fn(cid: str) -> fl.client.Client:
    """Flower client instantiation function."""
    # In real setup: load private dataset based on cid
    # For MVP: placeholder - real impl would use DataLoader from local data dir
    from torch.utils.data import random_split, SubsetRandomSampler  # Example

    # Dummy dataset (replace with real network graph dataset)
    dummy_dataset = [...]  # Placeholder: list of torch_geometric.Data
    trainset, valset = random_split(dummy_dataset, [0.8, 0.2])

    trainloader = DataLoader(trainset, batch_size=32, shuffle=True)
    valloader = DataLoader(valset, batch_size=32, shuffle=False)

    model = GNNTthreatModel({})  # Load or init from config

    return QuantumGuardClient(
        cid=cid,
        model=model,
        trainloader=trainloader,
        valloader=valloader,
        local_epochs=5,
    )
