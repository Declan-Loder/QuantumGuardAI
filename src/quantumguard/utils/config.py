"""
Configuration Loader
====================

Type-safe config with Pydantic and YAML loading.
No logging to avoid cycles.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from pydantic import BaseModel, Field, ValidationError

# ────────────────────────────────────────────────
# Pydantic Models
# ────────────────────────────────────────────────

class AppConfig(BaseModel):
    name: str = "QuantumGuard AI"
    version: str = "0.1.0"
    log_level: str = "INFO"
    environment: str = "development"


class PathsConfig(BaseModel):
    models_dir: str = "models/"
    data_dir: str = "data/"
    outputs_dir: str = "outputs/"


class AgentThreatDetectorConfig(BaseModel):
    enabled: bool = True
    confidence_threshold: float = Field(0.85, ge=0.0, le=1.0)
    max_graph_nodes: int = Field(5000, gt=0)


class AgentResponseEngineConfig(BaseModel):
    enabled: bool = True
    actions: list[str] = Field(default_factory=lambda: ["alert_only"])
    escalation_delay_seconds: int = Field(300, ge=0)
    dry_run: bool = True


class AgentOptimizerConfig(BaseModel):
    enabled: bool = True  # default to True now
    rl_algorithm: str = "ppo"
    simulation_episodes: int = 100
    training_interval_hours: float = 24.0


class AgentsConfig(BaseModel):
    threat_detector: AgentThreatDetectorConfig = AgentThreatDetectorConfig()
    response_engine: AgentResponseEngineConfig = AgentResponseEngineConfig()
    optimizer: AgentOptimizerConfig = AgentOptimizerConfig()


class ModelsGNNConfig(BaseModel):
    type: str = "graphsage"
    hidden_channels: int = 128
    num_layers: int = 3
    dropout: float = 0.2


class ModelsFederatedConfig(BaseModel):
    strategy: str = "fedavg"
    num_rounds: int = 10
    clients_per_round: float = 0.3


class ModelsConfig(BaseModel):
    gnn: ModelsGNNConfig = ModelsGNNConfig()
    federated: ModelsFederatedConfig = ModelsFederatedConfig()


class PrivacyDifferentialConfig(BaseModel):
    enabled: bool = True
    epsilon: float = Field(1.0, ge=0.1)
    delta: float = Field(1e-5, gt=0)
    noise_multiplier: float = 1.1
    max_grad_norm: float = 1.0


class PrivacyEncryptionConfig(BaseModel):
    post_quantum: bool = True
    kem_algorithm: str = "ML-KEM-768"
    sig_algorithm: str = "ML-DSA-65"
    hybrid: bool = True


class PrivacyConfig(BaseModel):
    differential: PrivacyDifferentialConfig = PrivacyDifferentialConfig()
    encryption: PrivacyEncryptionConfig = PrivacyEncryptionConfig()


class ToolsAlertDispatchConfig(BaseModel):
    channels: list[str] = Field(default_factory=lambda: ["console"])
    dry_run: bool = True


class ToolsNetworkScanConfig(BaseModel):
    enabled: bool = True
    privileged: bool = False
    timeout_seconds: float = 2.0
    dry_run: bool = True


class ToolsConfig(BaseModel):
    alert_dispatch: ToolsAlertDispatchConfig = ToolsAlertDispatchConfig()
    network_scan: ToolsNetworkScanConfig = ToolsNetworkScanConfig()
    log_analyzer: Dict[str, Any] = Field(default_factory=dict)


class VizConfig(BaseModel):
    default_layout: str = "spring"
    node_color_scale: str = "Viridis"
    output_format: str = "html"


class UtilsConfig(BaseModel):
    viz: VizConfig = VizConfig()


# ────────────────────────────────────────────────
# RootConfig
# ────────────────────────────────────────────────

class RootConfig(BaseModel):
    app: AppConfig = AppConfig()
    paths: PathsConfig = PathsConfig()
    agents: AgentsConfig = AgentsConfig()
    models: ModelsConfig = ModelsConfig()
    privacy: PrivacyConfig = PrivacyConfig()
    tools: ToolsConfig = ToolsConfig()
    utils: UtilsConfig = UtilsConfig()


# ────────────────────────────────────────────────
# Utility: Deep Merge Dictionaries
# ────────────────────────────────────────────────

def deep_merge(base: dict, override: dict) -> dict:
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            base[key] = deep_merge(base[key], value)
        else:
            base[key] = value
    return base


# ────────────────────────────────────────────────
# Loader
# ────────────────────────────────────────────────

@lru_cache()
def get_config() -> RootConfig:
    base_dir = Path(__file__).parent.parent.parent / "configs"
    env = os.getenv("QUANTUMGUARD_ENVIRONMENT", "development").lower()

    # 1. Load default.yaml
    default_path = base_dir / "default.yaml"
    raw_config: Dict[str, Any] = {}
    if default_path.is_file():
        with default_path.open("r", encoding="utf-8") as f:
            raw_config = yaml.safe_load(f) or {}

    # 2. Load environment-specific YAML
    env_path = base_dir / f"{env}.yaml"
    if env_path.is_file():
        with env_path.open("r", encoding="utf-8") as f:
            env_config = yaml.safe_load(f) or {}
            raw_config = deep_merge(raw_config, env_config)

    # 3. Environment variables (optional, keep simple)
    for key, value in os.environ.items():
        if key.startswith("QUANTUMGUARD_"):
            parts = key.lower().split("_")[1:]git status
            current = raw_config
            for part in parts[:-1]:
                current = current.setdefault(part, {})
            current[parts[-1]] = value  # simple set (no deep bool/int parsing yet)

    try:
        return RootConfig(**raw_config)
    except ValidationError as e:
        raise ValueError(f"Config validation failed: {e}")


_config_instance: Optional[RootConfig] = None

def config() -> RootConfig:
    global _config_instance
    if _config_instance is None:
        _config_instance = get_config()
    return _config_instance
