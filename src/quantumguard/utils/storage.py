from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Dict, Any, List

HISTORY_FILE = Path("outputs/detections_history.json")

def save_detection(result: Dict):
    """Save detection result to history."""
    history = load_history()
    history.append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "anomaly_score": result["detection_result"]["anomaly_score"],
        "max_confidence": result["detection_result"]["max_confidence"],
        "high_confidence": result["high_confidence"],
        "suspicious_ips": result.get("suspicious_ips", []),
        "node_count": result["graph_nodes"],
    })
    # Keep only last 10
    if len(history) > 10:
        history = history[-10:]
    HISTORY_FILE.parent.mkdir(exist_ok=True)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

def load_history() -> List[Dict]:
    if HISTORY_FILE.exists():
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    return []
