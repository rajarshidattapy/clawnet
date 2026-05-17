"""MCP-style skill registry for K8sWhisperer.

Each skill is an async callable annotated with metadata (name, description,
input/output schemas).  The registry provides discovery and lookup so the
agent framework and MCP server can expose skills dynamically.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SkillMeta:
    """Immutable metadata attached to a registered skill."""

    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)


SkillFn = Callable[..., Coroutine[Any, Any, Any]]


class SkillRegistry:
    """Central registry that maps skill names to callables + metadata."""

    def __init__(self) -> None:
        self._skills: dict[str, tuple[SkillFn, SkillMeta]] = {}

    # ── Registration ──────────────────────────────────────────────────

    def register(
        self,
        skill_fn: SkillFn,
        name: str,
        description: str,
        *,
        input_schema: Optional[dict[str, Any]] = None,
        output_schema: Optional[dict[str, Any]] = None,
    ) -> SkillFn:
        """Register *skill_fn* under *name* with its metadata.

        Can also be used as a decorator via :meth:`skill`.
        """
        meta = SkillMeta(
            name=name,
            description=description,
            input_schema=input_schema or {},
            output_schema=output_schema or {},
        )
        self._skills[name] = (skill_fn, meta)
        logger.info("Registered skill: %s", name)
        return skill_fn

    def skill(
        self,
        name: str,
        description: str,
        *,
        input_schema: Optional[dict[str, Any]] = None,
        output_schema: Optional[dict[str, Any]] = None,
    ) -> Callable[[SkillFn], SkillFn]:
        """Decorator form of :meth:`register`.

        Usage::

            @skills_registry.skill("my_skill", "Does a thing")
            async def my_skill(arg: str) -> dict:
                ...
        """

        def _decorator(fn: SkillFn) -> SkillFn:
            self.register(
                fn,
                name=name,
                description=description,
                input_schema=input_schema,
                output_schema=output_schema,
            )
            return fn

        return _decorator

    # ── Lookup ────────────────────────────────────────────────────────

    def get_skill(self, name: str) -> Optional[tuple[SkillFn, SkillMeta]]:
        """Return ``(callable, metadata)`` for *name*, or ``None``."""
        return self._skills.get(name)

    def list_skills(self) -> list[dict[str, Any]]:
        """Return a list of dicts describing every registered skill.

        Each dict contains ``name``, ``description``, ``input_schema``, and
        ``output_schema``.
        """
        return [
            {
                "name": meta.name,
                "description": meta.description,
                "input_schema": meta.input_schema,
                "output_schema": meta.output_schema,
            }
            for _, meta in self._skills.values()
        ]

    def __len__(self) -> int:
        return len(self._skills)

    def __contains__(self, name: str) -> bool:
        return name in self._skills


# ── Module-level singleton ────────────────────────────────────────────────

skills_registry = SkillRegistry()
