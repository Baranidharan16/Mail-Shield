"""
MAILSHIELD — Future Autonomous Email Monitoring Workflow.

TODO: Future autonomous email monitoring workflow.
Do NOT connect it to a real mailbox yet.
The existing manual email upload and analysis pipeline must continue working normally.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("mailshield.autonomous_agent.workflows.email_monitor")


class EmailMonitorWorkflow:
    """
    Placeholder workflow for future mailbox polling / webhook integrations.
    Inactive in current release.
    """

    def __init__(self, mailbox_config: Optional[Dict[str, Any]] = None):
        self.mailbox_config = mailbox_config or {}
        self.enabled = False

    async def poll_once(self) -> None:
        """TODO: Future autonomous mailbox polling mechanism."""
        logger.debug("EmailMonitorWorkflow: Inactive placeholder, no mailbox connected.")
        return None
