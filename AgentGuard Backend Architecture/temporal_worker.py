"""AgentGuard Temporal worker entry point.

Start a Temporal development server first (for local development), then run:
    python temporal_worker.py
from the backend folder with the same .env used by FastAPI.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent
load_dotenv(BACKEND_DIR / ".env", override=False)
load_dotenv(BACKEND_DIR.parent / ".env", override=False)

from temporalio.client import Client
from temporalio.worker import Worker

from temporal_activities import agentguard_analysis_activity
from temporal_workflows import AgentGuardAnalysisWorkflow


def _connection_options() -> dict:
    api_key = os.getenv("TEMPORAL_API_KEY", "").strip()
    tls_enabled = os.getenv("TEMPORAL_TLS", "true" if api_key else "false").strip().lower() in {"1", "true", "yes", "on"}
    options = {
        "namespace": os.getenv("TEMPORAL_NAMESPACE", "default").strip() or "default",
    }
    if api_key:
        options["api_key"] = api_key
    if tls_enabled:
        options["tls"] = True
    return options


async def run_worker() -> None:
    address = os.getenv("TEMPORAL_ADDRESS", "127.0.0.1:7233").strip()
    task_queue = os.getenv("TEMPORAL_TASK_QUEUE", "agentguard-analysis").strip() or "agentguard-analysis"
    client = await Client.connect(address, **_connection_options())
    print(f"AgentGuard Temporal worker connected to {address}; task queue={task_queue}")
    worker = Worker(
        client,
        task_queue=task_queue,
        workflows=[AgentGuardAnalysisWorkflow],
        activities=[agentguard_analysis_activity],
    )
    await worker.run()


if __name__ == "__main__":
    asyncio.run(run_worker())
