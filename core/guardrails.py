"""Output guardrails: what the model says, and what it asks ClawNet to do.

  redact(text)           strips secrets and PII from model-written text
  StreamRedactor         the same, for text that arrives in chunks
  validate_action(...)   checks a proposed control action against a JSON Schema

Machine evidence (IPs, hashes, paths, PIDs) is the product here, so it is left alone:
only credentials and personal data are replaced, each with a `[REDACTED:<kind>]` marker.
The schema check is the first gate in front of the existing policy guardrails; it does
not replace them (protected processes, private IPs, System32 and so on are still refused
by ClawNet after a human approves).
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

# ── redaction ─────────────────────────────────────────────────────────────────

# (kind, pattern). Specific token formats first, so the generic rule never relabels them.
_SECRETS: tuple[tuple[str, re.Pattern], ...] = tuple((k, re.compile(p)) for k, p in (
    ("private-key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    ("api-key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    ("api-key", r"\bsk-or-[A-Za-z0-9_\-]{20,}"),
    ("api-key", r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}"),
    ("api-key", r"\bAIza[0-9A-Za-z_\-]{30,}"),
    ("aws-key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("github-token", r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"),
    ("slack-token", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    ("stripe-key", r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    ("bearer-token", r"(?i)\bbearer\s+[A-Za-z0-9._~+/\-]{20,}=*"),
    ("password-in-url", r"(?i)\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@"),
))
# name = value, where the name says it is a credential. Keeps the name, drops the value.
_ASSIGNED = re.compile(
    r"(?i)\b([A-Za-z0-9_.\-]*(?:api[_\-]?key|secret|passwd|password|token|credential)[A-Za-z0-9_.\-]*)"
    r"(\s*[:=]\s*)(\"[^\"\n]{6,}\"|'[^'\n]{6,}'|[^\s\"',;]{6,})")

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_CARD = re.compile(r"\b\d(?:[ \-]?\d){12,18}\b")
# Needs a + prefix, parentheses or -/. separators, so PIDs, ports, timestamps, hashes and
# plain space-grouped numbers do not match.
_PHONE = re.compile(
    r"(?<![\w.])(?:\+\d{1,3}[ .\-]?\(?\d{1,4}\)?(?:[ .\-]?\d{2,4}){2,4}"
    r"|\(\d{3}\)[ .\-]?\d{3}[ .\-]\d{4}"
    r"|\d{3}[.\-]\d{3}[.\-]\d{4})(?!\w)")


def _luhn(digits: str) -> bool:
    total, flip = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if flip:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total, flip = total + d, not flip
    return total % 10 == 0


def _mark(kind: str) -> str:
    return f"[REDACTED:{kind}]"


def redact(text: str) -> str:
    """`text` with secrets and PII replaced by [REDACTED:<kind>] markers."""
    return redact_report(text)[0]


def redact_report(text: str) -> tuple[str, list[str]]:
    """(redacted text, the kinds that were found), for audit logging."""
    if not text:
        return text or "", []
    found: list[str] = []

    def sub(kind: str, pattern: re.Pattern, s: str, repl=None) -> str:
        def one(m: re.Match) -> str:
            new = repl(m) if repl else _mark(kind)
            if new != m.group(0):
                found.append(kind)
            return new
        return pattern.sub(one, s)

    out = str(text)
    for kind, pat in _SECRETS:
        out = sub(kind, pat, out, (lambda m: m.group(0).split("://")[0] + "://" + _mark(kind) + "@")
                  if kind == "password-in-url" else None)
    out = sub("secret", _ASSIGNED, out,
              lambda m: m.group(0) if m.group(3).startswith("[REDACTED") else f"{m.group(1)}{m.group(2)}{_mark('secret')}")
    out = sub("email", _EMAIL, out)
    out = sub("ssn", _SSN, out)
    out = sub("credit-card", _CARD, out,
              lambda m: _mark("credit-card") if _luhn(re.sub(r"\D", "", m.group(0))) and
              13 <= len(re.sub(r"\D", "", m.group(0))) <= 19 else m.group(0))
    out = sub("phone", _PHONE, out)
    return out, found


class StreamRedactor:
    """Redacts text that arrives in chunks. A secret split across two chunks is still caught,
    because the trailing partial word is held back until the next chunk (or flush) completes it."""

    def __init__(self) -> None:
        self._held = ""

    def feed(self, chunk: str) -> str:
        buf = self._held + (chunk or "")
        cut = max(buf.rfind(" "), buf.rfind("\n"), buf.rfind("\t")) + 1
        self._held = buf[cut:]
        return redact(buf[:cut])

    def flush(self) -> str:
        out, self._held = redact(self._held), ""
        return out


# ── action schema ─────────────────────────────────────────────────────────────

_REASON = {"type": "string", "minLength": 20, "maxLength": 1000}
_PID = {"type": "integer", "minimum": 1, "maximum": 4194304}
_SCHEMAS: dict[str, dict] = {
    "kill_process":    {"pid": _PID, "reason": _REASON},
    "suspend_process": {"pid": _PID, "reason": _REASON},
    "block_ip":        {"ip": {"type": "string", "format": "ip-address"}, "reason": _REASON},
    "quarantine_file": {"path": {"type": "string", "minLength": 3, "maxLength": 520,
                                 "pattern": r"^[A-Za-z]:[\\/][^\x00<>|?*]+$",
                                 "not": {"pattern": r"(^|[\\/])\.\.([\\/]|$)"}}, "reason": _REASON},
    "close_port":      {"port": {"type": "integer", "minimum": 1, "maximum": 65535}, "reason": _REASON},
    "promote_sandbox_run": {"run_id": {"type": "string", "pattern": r"^[A-Za-z0-9_\-]{1,64}$"},
                            "reason": _REASON},
}
CONTROL_ACTIONS = tuple(_SCHEMAS)


def schema_for(action: str) -> dict | None:
    props = _SCHEMAS.get(action)
    if props is None:
        return None
    return {"type": "object", "properties": props, "required": list(props),
            "additionalProperties": False}


# Shape only. Whether an IP or process is off-limits (private ranges, PID 4, protected
# processes) is ClawNet's policy guardrail, which refuses and logs it after this gate.
def _is_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _validator(schema: dict):
    from jsonschema import Draft202012Validator, FormatChecker
    checker = FormatChecker()
    checker.checks("ip-address")(lambda v: not isinstance(v, str) or _is_ip(v))
    return Draft202012Validator(schema, format_checker=checker)


def validate_action(action: str, args: dict) -> list[str]:
    """Why `args` is not an acceptable `action` proposal ([] when it is).

    Rejects unknown actions, missing/extra/mistyped arguments (a bool is not a PID), PIDs
    outside the real range, malformed IPs (ranges, hostnames), relative, traversal or wildcard
    paths, and a `reason` too short to say what, why and what breaks.
    """
    schema = schema_for(action)
    if schema is None:
        return [f"unknown control action {action!r}"]
    if not isinstance(args, dict):
        return ["arguments must be a JSON object"]
    errors = []
    for e in sorted(_validator(schema).iter_errors(args), key=lambda e: list(e.absolute_path)):
        where = ".".join(str(p) for p in e.absolute_path) or "arguments"
        errors.append(f"{where}: {e.message[:160]}")
    return errors
