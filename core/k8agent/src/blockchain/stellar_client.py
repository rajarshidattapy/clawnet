"""Stellar blockchain client for storing incident audit records on testnet."""

from __future__ import annotations

import logging
from typing import Any

from core.k8agent.src.config import settings

logger = logging.getLogger(__name__)


async def store_incident_on_chain(
    incident_id: str,
    anomaly_type: str,
    action_taken: str,
    timestamp: int,
    confidence_score: int,
    was_auto_executed: bool,
    diagnosis_summary: str,
) -> dict[str, Any]:
    """Store an incident record on the Stellar testnet via Soroban contract.

    Returns a dict with transaction_hash and status, or error details.
    """
    if not settings.ENABLE_BLOCKCHAIN:
        return {"status": "skipped", "reason": "blockchain disabled"}

    if not settings.STELLAR_SECRET_KEY or not settings.STELLAR_CONTRACT_ID:
        logger.warning("Stellar credentials not configured, skipping blockchain storage")
        return {"status": "skipped", "reason": "credentials not configured"}

    try:
        from stellar_sdk import Keypair, Network, SorobanServer, TransactionBuilder
        from stellar_sdk import scval

        # Connect to Stellar testnet
        server = SorobanServer("https://soroban-testnet.stellar.org")
        network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE

        # Load source account
        keypair = Keypair.from_secret(settings.STELLAR_SECRET_KEY)
        source_account = server.load_account(keypair.public_key)

        # Build the contract invocation transaction
        builder = TransactionBuilder(
            source_account=source_account,
            network_passphrase=network_passphrase,
            base_fee=100,
        )

        # Invoke store_incident on the contract
        builder.append_invoke_contract_function_op(
            contract_id=settings.STELLAR_CONTRACT_ID,
            function_name="store_incident",
            parameters=[
                scval.to_string(incident_id),
                scval.to_string(anomaly_type),
                scval.to_string(action_taken),
                scval.to_uint64(timestamp),
                scval.to_uint32(confidence_score),
                scval.to_bool(was_auto_executed),
                scval.to_string(diagnosis_summary[:200]),  # Truncate for on-chain storage
            ],
        )

        builder.set_timeout(30)
        tx = builder.build()

        # Simulate first
        sim_response = server.simulate_transaction(tx)
        if sim_response.error:
            logger.error("Simulation failed: %s", sim_response.error)
            return {"status": "error", "reason": f"simulation failed: {sim_response.error}"}

        # Prepare and sign
        tx = server.prepare_transaction(tx, sim_response)
        tx.sign(keypair)

        # Submit
        response = server.send_transaction(tx)
        tx_hash = response.hash

        logger.info("Incident %s stored on Stellar testnet: %s", incident_id, tx_hash)
        return {
            "status": "success",
            "transaction_hash": tx_hash,
            "network": "testnet",
            "contract_id": settings.STELLAR_CONTRACT_ID,
            "explorer_url": f"https://stellar.expert/explorer/testnet/tx/{tx_hash}",
        }

    except ImportError:
        logger.warning("stellar-sdk not installed, skipping blockchain storage")
        return {"status": "skipped", "reason": "stellar-sdk not installed"}
    except Exception as e:
        logger.exception("Failed to store incident on blockchain")
        return {"status": "error", "reason": str(e)}


async def get_incident_from_chain(incident_id: str) -> dict[str, Any]:
    """Retrieve an incident record from the Stellar testnet."""
    if not settings.ENABLE_BLOCKCHAIN or not settings.STELLAR_CONTRACT_ID:
        return {"status": "skipped"}

    try:
        from stellar_sdk import Keypair, Network, SorobanServer, TransactionBuilder
        from stellar_sdk import scval

        server = SorobanServer("https://soroban-testnet.stellar.org")
        network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE
        keypair = Keypair.from_secret(settings.STELLAR_SECRET_KEY)
        source_account = server.load_account(keypair.public_key)

        builder = TransactionBuilder(
            source_account=source_account,
            network_passphrase=network_passphrase,
            base_fee=100,
        )

        builder.append_invoke_contract_function_op(
            contract_id=settings.STELLAR_CONTRACT_ID,
            function_name="get_incident",
            parameters=[scval.to_string(incident_id)],
        )

        builder.set_timeout(30)
        tx = builder.build()

        sim_response = server.simulate_transaction(tx)
        if sim_response.error:
            return {"status": "error", "reason": str(sim_response.error)}

        # Parse the result
        result = sim_response.results[0]
        return {"status": "success", "record": str(result)}

    except Exception as e:
        logger.exception("Failed to retrieve incident from blockchain")
        return {"status": "error", "reason": str(e)}


async def get_incident_count() -> int:
    """Get the total number of incidents stored on-chain."""
    if not settings.ENABLE_BLOCKCHAIN or not settings.STELLAR_CONTRACT_ID:
        return 0

    try:
        from stellar_sdk import Keypair, Network, SorobanServer, TransactionBuilder
        from stellar_sdk import scval

        server = SorobanServer("https://soroban-testnet.stellar.org")
        network_passphrase = Network.TESTNET_NETWORK_PASSPHRASE
        keypair = Keypair.from_secret(settings.STELLAR_SECRET_KEY)
        source_account = server.load_account(keypair.public_key)

        builder = TransactionBuilder(
            source_account=source_account,
            network_passphrase=network_passphrase,
            base_fee=100,
        )

        builder.append_invoke_contract_function_op(
            contract_id=settings.STELLAR_CONTRACT_ID,
            function_name="get_count",
            parameters=[],
        )

        builder.set_timeout(30)
        tx = builder.build()

        sim_response = server.simulate_transaction(tx)
        if sim_response.results:
            return int(str(sim_response.results[0]))
        return 0

    except Exception:
        return 0
