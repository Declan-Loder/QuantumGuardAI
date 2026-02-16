"""
Response Engine Agent
=====================

The decision and execution layer for threat mitigation.

It:
- Receives threat signals from ThreatDetector (scores, subgraphs, nodes)
- Applies policy-based graduated response (alert → notify → isolate → block)
- Enforces escalation timers and human-in-the-loop safeguards
- Dispatches real actions via tools (alerts, network commands, SIEM integration)
- Logs all decisions with justification for audit/compliance

Configuration keys used:
- actions: list of allowed responses (e.g. ['alert_only', 'isolate_node', 'block_ip'])
- escalation_delay_seconds: time before allowing next level
- dry_run: bool – simulate actions without executing
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from quantumguard.agents.base import BaseAgent
from quantumguard.utils.logging import get_logger

logger = get_logger(__name__)

class ResponseEngine(BaseAgent):
    """
    Policy-driven response and mitigation agent.

    Graduated response levels (configurable):
    0. alert_only          (log + notify)
    1. notify_admin        (Slack/PagerDuty/email)
    2. isolate_node        (quarantine device/port)
    3. block_ip            (firewall rule)
    4. escalate            (alert SOC / shutdown)

    Escalation only occurs after delay or repeated detections.
    """

    description: str = (
        "Evaluates threat signals and executes graduated, policy-controlled responses. "
        "Ensures safe, auditable, and configurable mitigation — from alerts to automated isolation."
    )

    def __init__(
        self,
        name: str = "response-engine-01",
        config: Optional[Dict[str, Any]] = None,
        memory: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(name, config, memory)

        self.allowed_actions: List[str] = self.config.get("actions", ["alert_only"])
        self.escalation_delay_sec: int = self.config.get("escalation_delay_seconds", 300)
        self.dry_run: bool = self.config.get("dry_run", True)  # Safety default: True

        self.last_escalation_time: Optional[float] = None
        self.escalation_level: int = 0
        self.decision_history: List[Dict[str, Any]] = []

        self.logger.info(
            "ResponseEngine initialized",
            allowed_actions=self.allowed_actions,
            dry_run=self.dry_run,
            escalation_delay_sec=self.escalation_delay_sec
        )

    def _define_tools(self) -> Dict[str, Any]:
        """Response-specific action tools (stubs for now - real impl later)."""
        return {
            "send_alert": self._send_alert,
            "notify_admin": self._notify_admin,
            "isolate_node": self._isolate_node,
            "block_ip": self._block_ip,
            "escalate": self._escalate,
        }

    def _can_escalate(self) -> bool:
        """Check if enough time has passed since last escalation."""
        if self.last_escalation_time is None:
            return True
        return (time.time() - self.last_escalation_time) >= self.escalation_delay_sec

    def _determine_action_level(self, threat_level: float) -> int:
        """
        Map threat confidence/anomaly score to response level.

        Simple linear mapping for MVP — future: policy engine / RL-tuned
        """
        if threat_level < 0.7:
            return 0  # alert_only
        elif threat_level < 0.85:
            return 1  # notify_admin
        elif threat_level < 0.95:
            return 2  # isolate_node
        else:
            return 3  # block_ip or escalate

    def _send_alert(self, details: Dict[str, Any]) -> bool:
        """Tool: Log structured alert (console/file). Real: integrate with alert_dispatch tool."""
        logger.critical("ALERT: Threat detected", **details)
        return True

    def _notify_admin(self, details: Dict[str, Any]) -> bool:
        """Tool: Send notification (stub). Real: Slack/PagerDuty/email."""
        self.logger.warning("NOTIFY ADMIN: Potential incident", **details)
        return True  # Simulate success

    def _isolate_node(self, node_ip: str) -> bool:
        """Tool: Isolate device/port (stub). Real: call network tool / SDN API."""
        if self.dry_run:
            self.logger.info("[DRY RUN] Isolating node", ip=node_ip)
            return True
        self.logger.info("Isolating node", ip=node_ip)
        # Future: self.call_tool_from_tools_layer("network_isolate", ip=node_ip)
        return True

    def _block_ip(self, ip: str) -> bool:
        """Tool: Add firewall block (stub)."""
        if self.dry_run:
            self.logger.info("[DRY RUN] Blocking IP", ip=ip)
            return True
        self.logger.info("Blocking IP", ip=ip)
        return True

    def _escalate(self, details: Dict[str, Any]) -> bool:
        """Tool: Escalate to SOC/human (stub)."""
        self.logger.error("ESCALATION REQUIRED", **details)
        return True

    def execute(self, input_data: Any) -> Dict[str, Any]:
        """
        Main response logic.

        Input expected:
        - Dict from ThreatDetector: {'anomaly_score': float, 'top_suspicious_nodes': list, ...}

        Process:
        1. Parse threat level
        2. Determine proposed action level
        3. Check escalation timer
        4. Execute allowed action (highest permitted)
        5. Log decision with justification
        6. Update history/memory

        Returns:
            Execution summary, action taken, justification
        """
        if not isinstance(input_data, dict) or "anomaly_score" not in input_data:
            raise ValueError("ResponseEngine expects dict with 'anomaly_score'")

        start_time = time.time()

        anomaly_score = input_data["anomaly_score"]
        suspicious_nodes = input_data.get("top_suspicious_nodes", [])
        justification = f"Anomaly score: {anomaly_score:.3f} | Nodes: {suspicious_nodes}"

        proposed_level = self._determine_action_level(anomaly_score)
        current_level = min(proposed_level, len(self.allowed_actions) - 1)

        action_taken = self.allowed_actions[current_level]
        executed = False
        action_result = None

        if action_taken == "alert_only":
            action_result = self.call_tool("send_alert", details={"score": anomaly_score, "nodes": suspicious_nodes})
            executed = True
        elif action_taken == "notify_admin" and self._can_escalate():
            action_result = self.call_tool("notify_admin", details={"score": anomaly_score})
            self.last_escalation_time = time.time()
            executed = True
        elif action_taken == "isolate_node" and self._can_escalate():
            for node in suspicious_nodes[:1]:  # Limit to first suspicious for safety
                action_result = self.call_tool("isolate_node", node_ip=str(node))
            self.last_escalation_time = time.time()
            executed = True
        elif action_taken == "block_ip" and self._can_escalate():
            # Assume first node IP
            if suspicious_nodes:
                action_result = self.call_tool("block_ip", ip=str(suspicious_nodes[0]))
            self.last_escalation_time = time.time()
            executed = True
        else:
            action_taken = "no_action"
            justification += " | Escalation not allowed yet or action not permitted"

        decision = {
            "timestamp": datetime.utcnow().isoformat(),
            "threat_score": anomaly_score,
            "proposed_level": proposed_level,
            "executed_level": current_level,
            "action_taken": action_taken,
            "executed": executed,
            "justification": justification,
            "dry_run": self.dry_run,
        }

        self.decision_history.append(decision)
        self.remember("last_decision", decision)
        self.remember("decision_history", self.decision_history[-20:])  # Keep recent

        duration = time.time() - start_time

        self.logger.info(
            "Response decision executed",
            action=action_taken,
            score=anomaly_score,
            duration_sec=duration,
            **decision
        )

        return {
            "status": "success" if executed else "skipped",
            "decision": decision,
            "duration_sec": duration,
        }

    def finalize(self) -> None:
        """Log summary on shutdown."""
        super().finalize()
        if self.decision_history:
            self.logger.info(
                "ResponseEngine finalizing",
                total_decisions=len(self.decision_history),
                last_action=self.decision_history[-1]["action_taken"]
            )
