"""Utilities for chunking large log outputs before sending to an LLM."""

from __future__ import annotations

_MAX_CHARS = 12_000  # conservative limit for a single LLM context chunk


def chunk_logs(logs: str, max_lines: int = 200) -> str:
    """Keep the last *max_lines* of *logs* and summarise what was truncated.

    If the log is within the limit it is returned unchanged.  Otherwise the
    output consists of a short header indicating how many lines were
    truncated followed by the tail of the log.
    """
    if not logs:
        return ""

    lines = logs.splitlines()

    if len(lines) <= max_lines:
        return logs

    truncated_count = len(lines) - max_lines
    kept = lines[-max_lines:]

    header = (
        f"[... {truncated_count} earlier log lines truncated — "
        f"showing last {max_lines} lines ...]\n"
    )
    return header + "\n".join(kept)


def chunk_log(log_text: str, max_chars: int = _MAX_CHARS) -> list[str]:
    """Split *log_text* into chunks of at most *max_chars* characters.

    Splits on newline boundaries so individual log lines are never broken.
    Returns a list of string chunks.
    """
    if not log_text:
        return []

    if len(log_text) <= max_chars:
        return [log_text]

    chunks: list[str] = []
    lines = log_text.splitlines(keepends=True)
    current: list[str] = []
    current_len = 0

    for line in lines:
        if current_len + len(line) > max_chars and current:
            chunks.append("".join(current))
            current = []
            current_len = 0
        current.append(line)
        current_len += len(line)

    if current:
        chunks.append("".join(current))

    return chunks
