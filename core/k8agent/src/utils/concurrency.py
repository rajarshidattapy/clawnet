"""Per-pod async lock manager to prevent concurrent remediation on the same resource."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

logger = logging.getLogger(__name__)


class PodLockManager:
    """Manages a pool of ``asyncio.Lock`` instances keyed by pod identity.

    The key is ``namespace/name`` so that concurrent remediation actions
    against the same pod are serialised.  Locks are created lazily and
    garbage-collected when no longer held.
    """

    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = {}
        self._ref_counts: dict[str, int] = {}
        self._manager_lock = asyncio.Lock()

    @staticmethod
    def _key(namespace: str, name: str) -> str:
        return f"{namespace}/{name}"

    @asynccontextmanager
    async def acquire(self, namespace: str, name: str) -> AsyncIterator[None]:
        """Acquire the lock for the given pod.

        Usage::

            async with pod_locks.acquire("default", "my-pod"):
                # exclusive access to this pod
                ...
        """
        key = self._key(namespace, name)

        # Get or create the lock (protected by manager lock)
        async with self._manager_lock:
            if key not in self._locks:
                self._locks[key] = asyncio.Lock()
                self._ref_counts[key] = 0
            self._ref_counts[key] += 1

        lock = self._locks[key]
        logger.debug("Waiting for lock on %s", key)

        try:
            async with lock:
                logger.debug("Acquired lock on %s", key)
                yield
        finally:
            # Decrement ref count and clean up if nobody is waiting
            async with self._manager_lock:
                self._ref_counts[key] -= 1
                if self._ref_counts[key] == 0:
                    del self._locks[key]
                    del self._ref_counts[key]
                    logger.debug("Released and cleaned up lock for %s", key)


# Module-level singleton
pod_locks = PodLockManager()
