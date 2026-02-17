"""
Minimal Configuration Loader
============================

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

class AppConfig(BaseModel):
    name: str = "QuantumGuard AI"
    version: str = "0.1.0"
    log_level: str = "INFO"
    environment: str = "development"

class RootConfig(BaseModel):
    app: AppConfig = AppConfig()

@lru_cache()
def get_config(env: str = os.getenv("QUANTUMGUARD_ENVIRONMENT", "development")) -> RootConfig:
    base_dir = Path(__file__).parent.parent.parent / "configs"
    default_path = base_dir / "default.yaml"

    raw_config: Dict[str, Any] = {}

    if default_path.is_file():
        with default_path.open("r", encoding="utf-8") as f:
            raw_config = yaml.safe_load(f) or {}

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