"""I/O-bearing activities for Temporal AgentGuard workflows."""
from __future__ import annotations

import asyncio
from typing import Any, Dict

from temporalio import activity


@activity.defn(name="agentguard_analysis_activity")
async def agentguard_analysis_activity(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Run the existing deterministic policy/research pipeline as an activity.

    The Temporal workflow does not send tool calls itself. All proposed tool
    actions continue through the existing AgentGuard gateway and review queue.
    Raw input is not included in workflow IDs or event logs.
    """
    import main as agentguard_main

    prompt = str(payload.get("prompt") or "")[:4_000]
    document_text = str(payload.get("document_text") or "")[:200_000]
    source_name = str(payload.get("source_name") or "temporal_analysis")[:255]
    if not prompt.strip():
        raise ValueError("A non-empty prompt is required for Temporal analysis.")

    response = await asyncio.to_thread(
        agentguard_main.agent.analyze_document,
        prompt=prompt,
        document_text=document_text,
        scenario_id=None,
        force_provenance=None,
    )
    response = await asyncio.to_thread(agentguard_main._queue_review_if_required, response)
    await asyncio.to_thread(
        agentguard_main._write_audit,
        response=response,
        prompt=prompt,
        file_name=source_name,
    )
    return response.model_dump(mode="json")
