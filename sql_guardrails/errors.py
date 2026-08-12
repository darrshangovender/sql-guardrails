"""Typed exception hierarchy for sql-guardrails.

Every rejection raises a subclass of :class:`GuardError`, so callers can either
catch the umbrella exception or pattern-match on a specific failure mode.
"""

from __future__ import annotations


class GuardError(Exception):
    """Base class for all guardrail rejections.

    Attributes:
        sql: The offending SQL string (raw, as supplied by the caller).
        reason: Human-readable rationale for the rejection.
    """

    def __init__(self, reason: str, sql: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.sql = sql

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.reason


class ParseError(GuardError):
    """The SQL could not be parsed at all (malformed, unsupported dialect, etc.)."""


class MultiStatementError(GuardError):
    """The input contained more than one top-level statement.

    Multi-statement payloads are a classic stacked-query attack vector
    (``SELECT 1; DROP TABLE users;``). We always reject them.
    """


class DisallowedStatementError(GuardError):
    """The statement type is not on the allow-list (e.g. INSERT, DROP, MERGE)."""


class DisallowedFunctionError(GuardError):
    """A function call was rejected by the allowlist (e.g. ``pg_sleep``)."""


class DisallowedTableError(GuardError):
    """A reference to a forbidden table or schema (e.g. ``pg_user``)."""


class CostLimitExceeded(GuardError):
    """The planner-estimated cost exceeded the configured threshold."""

    def __init__(self, reason: str, *, estimated_cost: float, limit: float, sql: str | None = None) -> None:
        super().__init__(reason, sql=sql)
        self.estimated_cost = estimated_cost
        self.limit = limit


class RowLimitExceeded(GuardError):
    """The planner-estimated row count exceeded the configured threshold."""

    def __init__(self, reason: str, *, estimated_rows: float, limit: float, sql: str | None = None) -> None:
        super().__init__(reason, sql=sql)
        self.estimated_rows = estimated_rows
        self.limit = limit


__all__ = [
    "GuardError",
    "ParseError",
    "MultiStatementError",
    "DisallowedStatementError",
    "DisallowedFunctionError",
    "DisallowedTableError",
    "CostLimitExceeded",
    "RowLimitExceeded",
]
