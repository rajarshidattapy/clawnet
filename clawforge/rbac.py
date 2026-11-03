"""Role-based access control for the ClawForge MCP server.

Roles map to the tool tiers the server already draws (see mcp_server.py):

    role        OBSERVE   EXECUTE (sandbox)   CONTROL (changes the host)
    viewer         yes          no                   no
    analyst        yes          yes                  no
    responder      yes          yes                  yes*        * still pauses for a human approval

Who gets which role:
  - the static service token (what the registered TrueForge connector sends) gets
    CLAWFORGE_SERVICE_ROLE, default `responder`: the agent needs the control tools, and
    every one of them still waits for a human;
  - an OAuth/JWT caller gets the highest role found in its CLAWFORGE_ROLE_CLAIM claim
    (default `roles`; `role`, `scope` and dotted paths like `realm_access.roles` work too),
    after CLAWFORGE_ROLE_MAP renames the identity provider's role names;
  - a JWT with no recognised role gets CLAWFORGE_DEFAULT_ROLE, default `viewer`.

    CLAWFORGE_ROLE_MAP=soc-lead=responder,soc-analyst=analyst,soc-intern=viewer
"""
from __future__ import annotations

import os
import re
from typing import Any, Optional

OBSERVE, EXECUTE, CONTROL = "observe", "execute", "control"

# Lowest to highest privilege; each role includes the tiers of the ones before it.
ROLES: dict[str, frozenset] = {
    "viewer":    frozenset({OBSERVE}),
    "analyst":   frozenset({OBSERVE, EXECUTE}),
    "responder": frozenset({OBSERVE, EXECUTE, CONTROL}),
}
_ORDER = list(ROLES)


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, "").strip() or default


def _valid(role: str, fallback: str) -> str:
    role = role.lower()
    return role if role in ROLES else fallback


def service_role() -> str:
    return _valid(_env("CLAWFORGE_SERVICE_ROLE", "responder"), "responder")


def default_role() -> str:
    return _valid(_env("CLAWFORGE_DEFAULT_ROLE", "viewer"), "viewer")


def _role_map() -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in _env("CLAWFORGE_ROLE_MAP").split(","):
        theirs, _, ours = pair.partition("=")
        if theirs.strip() and ours.strip().lower() in ROLES:
            out[theirs.strip().lower()] = ours.strip().lower()
    return out


def _claim_values(claims: dict, path: str) -> list[str]:
    node: Any = claims
    for part in path.split("."):
        node = node.get(part) if isinstance(node, dict) else None
    if isinstance(node, str):
        return [v for v in re.split(r"[\s,]+", node) if v]
    return [str(v) for v in node] if isinstance(node, (list, tuple)) else []


def role_from_claims(claims: dict) -> str:
    """The highest role the token's claims grant, else the default role."""
    paths = [_env("CLAWFORGE_ROLE_CLAIM", "roles")]
    if paths[0] == "roles":
        paths.append("role")
    mapping = _role_map()
    best = -1
    for path in paths:
        for value in _claim_values(claims, path):
            name = mapping.get(value.lower(), value.lower())
            if name in ROLES:
                best = max(best, _ORDER.index(name))
    return _ORDER[best] if best >= 0 else default_role()


def allowed(role: Optional[str], tier: str) -> bool:
    return tier in ROLES.get(role or "", frozenset())


def tier_of(annotations: Any) -> str:
    """The tier an MCP tool's annotations put it in (the same hints the approval gate reads)."""
    if getattr(annotations, "destructiveHint", None):
        return CONTROL
    if getattr(annotations, "readOnlyHint", None):
        return OBSERVE
    return EXECUTE
