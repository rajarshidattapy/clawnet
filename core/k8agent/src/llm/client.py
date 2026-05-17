"""Async LiteLLM wrapper with retry logic and JSON extraction."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
import time as _time
from typing import Any, Optional

import litellm

from core.k8agent.src.config import settings
from core.k8agent.src.tracing.tracer import record_trace

logger = logging.getLogger(__name__)

# ── Per-thread trace context ───────────────────────────────────────────

_trace_ctx = threading.local()


def set_current_trace_id(trace_id: str, stage: str = "unknown") -> None:
    """Set the trace_id and stage for the current thread's LLM calls."""
    _trace_ctx.trace_id = trace_id
    _trace_ctx.stage = stage


def _get_trace_id() -> str:
    return getattr(_trace_ctx, "trace_id", "")


def _get_stage() -> str:
    return getattr(_trace_ctx, "stage", "unknown")

# ── Helpers ─────────────────────────────────────────────────────────────


def _extract_json(text: str) -> Any:
    """Attempt to parse JSON from an LLM response.

    Strategy:
      1. Direct ``json.loads`` on the full text.
      2. Extract the first fenced ```json ... ``` block.
      3. Find the first top-level ``[`` or ``{`` and parse from there.
    """
    # 1. Direct parse
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        pass

    # 2. Fenced code block
    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # 3. First bracket / brace
    for char, close in [("[", "]"), ("{", "}")]:
        start = text.find(char)
        if start == -1:
            continue
        # Find matching close walking backwards from end
        end = text.rfind(close)
        if end == -1 or end <= start:
            continue
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            continue

    raise ValueError(f"Could not extract JSON from LLM response: {text[:200]}...")


# ── Core call ───────────────────────────────────────────────────────────


async def llm_call(
    messages: list[dict[str, str]],
    *,
    model: Optional[str] = None,
    response_format: Optional[dict] = None,
    temperature: float = 0.2,
    max_retries: int = 3,
) -> str:
    """Call LiteLLM with automatic retry and exponential backoff.

    Returns the raw assistant message content as a string.
    """
    model = model or settings.LITELLM_MODEL_FAST

    kwargs: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }
    if settings.LLM_API_KEY:
        kwargs["api_key"] = settings.LLM_API_KEY
    if settings.LLM_BASE_URL:
        kwargs["api_base"] = settings.LLM_BASE_URL
    if response_format is not None:
        kwargs["response_format"] = response_format

    last_exc: Optional[Exception] = None
    for attempt in range(max_retries):
        try:
            response = await litellm.acompletion(**kwargs)
            content: str = response.choices[0].message.content  # type: ignore[union-attr]
            return content
        except Exception as exc:
            last_exc = exc
            delay = 2**attempt
            logger.warning(
                "LLM call attempt %d/%d failed (%s), retrying in %ds...",
                attempt + 1,
                max_retries,
                exc,
                delay,
            )
            await asyncio.sleep(delay)

    raise RuntimeError(
        f"LLM call failed after {max_retries} attempts"
    ) from last_exc


async def llm_call_reasoning(
    messages: list[dict[str, str]],
    *,
    model: Optional[str] = None,
    response_format: Optional[dict] = None,
    temperature: float = 0.2,
    max_retries: int = 3,
) -> str:
    """Call the reasoning model (slower, higher quality).

    Same interface as ``llm_call`` but defaults to the reasoning model.
    """
    model = model or settings.LITELLM_MODEL_REASONING
    return await llm_call(
        messages,
        model=model,
        response_format=response_format,
        temperature=temperature,
        max_retries=max_retries,
    )


async def llm_call_json(
    messages: list[dict[str, str]],
    *,
    model: Optional[str] = None,
    temperature: float = 0.2,
    max_retries: int = 3,
) -> Any:
    """Call LLM and parse the response as JSON.

    Uses ``_extract_json`` with multiple fallback strategies.
    """
    raw = await llm_call(
        messages,
        model=model,
        temperature=temperature,
        max_retries=max_retries,
    )
    return _extract_json(raw)


# ── Synchronous wrappers for use in LangGraph nodes ───────────────────


def llm_call_sync(
    messages: list[dict[str, str]],
    *,
    model: Optional[str] = None,
    temperature: float = 0.2,
) -> str:
    """Synchronous LLM call using litellm.completion (not async)."""
    model = model or settings.LITELLM_MODEL_FAST
    kwargs: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }
    if settings.LLM_API_KEY:
        kwargs["api_key"] = settings.LLM_API_KEY
    if settings.LLM_BASE_URL:
        kwargs["api_base"] = settings.LLM_BASE_URL

    input_text = json.dumps(messages, default=str)
    t0 = _time.monotonic()
    result = ""

    for attempt in range(3):
        try:
            response = litellm.completion(**kwargs)
            result = response.choices[0].message.content
            break
        except Exception as exc:
            logger.warning("Sync LLM attempt %d/3 failed: %s", attempt + 1, exc)
            _time.sleep(2 ** attempt)

    duration_ms = int((_time.monotonic() - t0) * 1000)
    trace_id = _get_trace_id()
    if trace_id:
        try:
            record_trace(
                trace_id=trace_id,
                stage=_get_stage(),
                model=model,
                input_text=input_text,
                output_text=result,
                duration_ms=duration_ms,
            )
        except Exception:
            logger.warning("Failed to record LLM trace", exc_info=True)

    return result


def llm_call_json_sync(
    messages: list[dict[str, str]],
    *,
    model: Optional[str] = None,
    temperature: float = 0.2,
) -> Any:
    """Synchronous LLM call that returns parsed JSON.

    Tracing is handled inside ``llm_call_sync``, so no extra trace here.
    """
    raw = llm_call_sync(messages, model=model, temperature=temperature)
    if not raw:
        return None
    try:
        return _extract_json(raw)
    except ValueError:
        return None
