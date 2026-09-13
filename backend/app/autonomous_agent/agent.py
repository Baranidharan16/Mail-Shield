"""
MAILSHIELD — Autonomous AI Agent Base Interface.

Provides the abstract blueprint for the future autonomous agent layer.
Does NOT perform any real-world actions (e.g. deleting emails, blocking IPs).
"""
from __future__ import annotations

import abc
from typing import Any, Dict, List, Optional


class AutonomousAgent(abc.ABC):
    """
    Abstract interface for future MailShield autonomous security agents.
    Designed to decouple agent reasoning from low-level forensic and ML pipelines.
    """

    @abc.abstractmethod
    async def analyze(self, investigation: Any) -> Dict[str, Any]:
        """
        Analyze an incoming email investigation using multi-modal forensic reasoning.
        Placeholder: No active execution in this release.
        """
        raise NotImplementedError("Autonomous agent is currently NOT CONFIGURED.")

    @abc.abstractmethod
    async def plan_actions(self, investigation: Any) -> List[Dict[str, Any]]:
        """
        Generate a non-destructive candidate action plan (e.g. policy recommendations, alerts)
        subject to administrator or analyst approval.
        Placeholder: No active execution in this release.
        """
        raise NotImplementedError("Autonomous action planner is currently NOT CONFIGURED.")

    @abc.abstractmethod
    async def execute_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute an approved security action.
        Safety Guarantee: No destructive operations (deleting emails, blocking firewalls)
        are permitted without policy gates.
        Placeholder: No active execution in this release.
        """
        raise NotImplementedError("Autonomous action execution is currently NOT CONFIGURED.")
