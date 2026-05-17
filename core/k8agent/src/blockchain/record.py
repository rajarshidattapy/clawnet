"""Serialize incident data for blockchain storage."""

from __future__ import annotations

import logging
from datetime import datetime

from core.k8agent.src.blockchain.stellar_client import store_incident_on_chain

logger = logging.getLogger(__name__)


async def record_incident_on_blockchain(
    incident_id: str,
    anomaly_type: str,
    action_taken: str,
    confidence: float,
    was_auto_executed: bool,
    diagnosis: str,
) -> dict:
    """Record a resolved incident on the Stellar blockchain.

    Called from the explain node after an incident is fully resolved.
    Converts Python types to Soroban-compatible values.
    """
    # Convert confidence from float (0-1) to int (0-10000)
    confidence_score = int(confidence * 10000)

    # Use current UTC timestamp as epoch seconds
    timestamp = int(datetime.utcnow().timestamp())

    # Truncate diagnosis for on-chain storage (keep it concise)
    diagnosis_summary = diagnosis[:200] if diagnosis else "No diagnosis available"

    result = await store_incident_on_chain(
        incident_id=incident_id,
        anomaly_type=anomaly_type,
        action_taken=action_taken,
        timestamp=timestamp,
        confidence_score=confidence_score,
        was_auto_executed=was_auto_executed,
        diagnosis_summary=diagnosis_summary,
    )

    if result.get("status") == "success":
        logger.info(
            "Incident %s recorded on blockchain: %s",
            incident_id,
            result.get("transaction_hash"),
        )
    else:
        logger.warning(
            "Blockchain recording for %s: %s - %s",
            incident_id,
            result.get("status"),
            result.get("reason", "unknown"),
        )

    return result
