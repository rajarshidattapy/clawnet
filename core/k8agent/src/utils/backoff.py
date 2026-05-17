"""Exponential-backoff verification helper."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)


async def verify_with_backoff(
    check_fn: Callable[[], Awaitable[bool]],
    *,
    max_attempts: int = 5,
    initial_delay: float = 5.0,
) -> bool:
    """Repeatedly call *check_fn* with exponential backoff until it returns ``True``.

    Parameters
    ----------
    check_fn:
        An async callable that returns ``True`` when the condition is met.
    max_attempts:
        Maximum number of attempts before giving up.
    initial_delay:
        Seconds to wait before the first retry.  Each subsequent retry
        doubles the delay.

    Returns
    -------
    bool
        ``True`` if *check_fn* succeeded within the allowed attempts,
        ``False`` otherwise.
    """
    delay = initial_delay

    for attempt in range(1, max_attempts + 1):
        try:
            result = await check_fn()
            if result:
                logger.info("Verification passed on attempt %d/%d", attempt, max_attempts)
                return True
        except Exception as exc:
            logger.warning(
                "Verification attempt %d/%d raised %s: %s",
                attempt,
                max_attempts,
                type(exc).__name__,
                exc,
            )

        if attempt < max_attempts:
            logger.info(
                "Verification attempt %d/%d failed, retrying in %.1fs...",
                attempt,
                max_attempts,
                delay,
            )
            await asyncio.sleep(delay)
            delay *= 2

    logger.error("Verification failed after %d attempts", max_attempts)
    return False
