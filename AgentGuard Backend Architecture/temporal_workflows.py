"""Temporal workflow definitions for AgentGuard.

This module is loaded by the FastAPI process only when temporal mode is enabled
and by the dedicated Temporal worker process.
"""
from datetime import timedelta
from typing import Any, Dict

from temporalio import workflow
from temporalio.common import RetryPolicy


@workflow.defn(name="AgentGuardAnalysisWorkflow")
class AgentGuardAnalysisWorkflow:
    """Durably orchestrate one AgentGuard analysis activity."""

    @workflow.run
    async def run(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        # Keep workflow code deterministic. Network, database, LLM and analysis
        # work is performed by the registered activity in temporal_activities.py.
        return await workflow.execute_activity(
            "agentguard_analysis_activity",
            payload,
            start_to_close_timeout=timedelta(minutes=6),
            schedule_to_close_timeout=timedelta(minutes=7),
            retry_policy=RetryPolicy(maximum_attempts=1),
        )
