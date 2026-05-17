"""Incident fingerprinting for the self-evolving runbook system.

A fingerprint is a compact, deterministic identifier derived from the
anomaly type, error pattern, and resource kind.  Two incidents that share
a fingerprint are assumed to have the same root cause and can reuse the
same cached runbook.
"""

from __future__ import annotations

import hashlib
import re


def compute_fingerprint(
    anomaly_type: str,
    error_pattern: str,
    resource_kind: str,
) -> str:
    """Return a 16-character hex fingerprint for an incident signature.

    The fingerprint is the first 16 hex characters of a SHA-256 hash over
    the canonicalised (lowered, stripped) triple of *anomaly_type*,
    *error_pattern*, and *resource_kind*.
    """
    canonical = "|".join(
        part.strip().lower() for part in (anomaly_type, error_pattern, resource_kind)
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return digest[:16]


def extract_error_pattern(diagnosis: str) -> str:
    """Extract a normalised error pattern from a free-text diagnosis.

    Strategy:
      1. Take the first sentence (up to the first period, newline, or
         end-of-string).
      2. Lower-case and strip whitespace.
      3. Collapse runs of whitespace to a single space.

    The result is suitable for use as the *error_pattern* argument to
    :func:`compute_fingerprint`.
    """
    if not diagnosis:
        return ""

    # First sentence: split on sentence-ending punctuation or newline
    match = re.match(r"([^.\n]+)", diagnosis.strip())
    first_sentence = match.group(1).strip() if match else diagnosis.strip()

    # Normalise
    normalised = re.sub(r"\s+", " ", first_sentence.lower().strip())
    return normalised
