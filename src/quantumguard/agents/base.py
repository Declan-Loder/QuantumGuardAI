"""
Base Agent Abstract Class
=========================

All QuantumGuard agents inherit from this base class.

It provides:
- Common interface (execute, initialize, step, finalize)
- Tool calling support (agents declare tools they can use)
- Basic memory/state management (short-term + long-term)
- Structured logging
- Configuration injection
- Error handling & observability hooks

Agents should override:
- execute() for the main logic loop
- _define_tools() to register callable tools
- Optional: initialize(), step(), finalize() for lifecycle control
"""

from __future__ import annotations

import abc
import logging
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

import structlog

from quantumguard.utils.config import Config  # We'll create this later
from quantumguard.utils.logging import get_logger

logger = get_logger(__name__)

@runtime_checkable
class ToolCallable(Protocol):
    """Protocol for functions/tools agents can call."""
    def __call__(self, **kwargs: Any) -> Any:
        ...

class BaseAgent(abc.ABC):
    """
    Abstract base class for all QuantumGuard agents.

    Args:
        name: Unique name/identifier for this agent instance
        config: Agent-specific configuration (from configs/*.yaml)
        memory: Optional external memory store (e.g., vector DB)
    """

    def __init__(
        self,
        name: str,
        config: Optional[Dict[str, Any]] = None,
        memory: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.name = name
        self.config = config or {}
        self.memory: Dict[str, Any] = memory or {}  # Short-term dict for MVP; upgrade to vector store
        self.tools: Dict[str, ToolCallable] = self._define_tools()
        self.logger = logger.bind(agent_name=self.name, agent_type=self.__class__.__name__)

        self._initialized = False
        self._state: Dict[str, Any] = {}  # Agent-specific persistent state

        self.logger.info("Agent initialized", config_keys=list(self.config.keys()))

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Human-readable description of what this agent does."""
        pass

    def _define_tools(self) -> Dict[str, ToolCallable]:
        """
        Override in subclasses to register tools this agent can call.

        Returns:
            Dict of tool_name -> callable
        """
        return {}

    def initialize(self) -> None:
        """
        Lifecycle hook: Called once before any execution.
        Subclasses can load models, connect to external services, etc.
        """
        if self._initialized:
            self.logger.warning("Already initialized")
            return

        self._initialized = True
        self.logger.info("Agent initialized successfully")

    def step(self, input_data: Any) -> Any:
        """
        Single step execution (useful for streaming or iterative agents).
        Default: delegates to full execute().
        """
        return self.execute(input_data)

    @abc.abstractmethod
    def execute(self, input_data: Any) -> Any:
        """
        Main entry point for the agent.

        Args:
            input_data: Input to process (e.g., network graph, log batch, alert)

        Returns:
            Output (e.g., anomaly score, action decision, updated policy)

        Raises:
            ValueError: On invalid input
            RuntimeError: On execution failure
        """
        pass

    def finalize(self) -> None:
        """Lifecycle hook: Cleanup, save state, close connections."""
        self.logger.info("Agent finalizing", state_keys=list(self._state.keys()))
        # Subclasses should override to persist memory/state if needed

    def call_tool(self, tool_name: str, **kwargs: Any) -> Any:
        """
        Invoke a registered tool by name.

        Args:
            tool_name: Name of the tool to call
            **kwargs: Arguments for the tool

        Returns:
            Tool result

        Raises:
            KeyError: If tool not registered
        """
        if tool_name not in self.tools:
            raise KeyError(f"Tool '{tool_name}' not registered for agent '{self.name}'")

        self.logger.debug("Calling tool", tool=tool_name, kwargs=kwargs)
        result = self.tools[tool_name](**kwargs)
        self.logger.debug("Tool result received", tool=tool_name, result_type=type(result).__name__)
        return result

    def remember(self, key: str, value: Any) -> None:
        """Store short-term memory."""
        self.memory[key] = value
        self.logger.debug("Memory stored", key=key)

    def recall(self, key: str, default: Any = None) -> Any:
        """Retrieve from short-term memory."""
        value = self.memory.get(key, default)
        if value is not None:
            self.logger.debug("Memory recalled", key=key)
        return value

    def update_state(self, key: str, value: Any) -> None:
        """Update persistent agent state."""
        self._state[key] = value
        self.logger.debug("State updated", key=key)

    def get_state(self, key: str, default: Any = None) -> Any:
        """Get from persistent state."""
        return self._state.get(key, default)
