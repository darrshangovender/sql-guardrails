"""Declarative allow-list of SQL functions.

The default allow-list covers the analytic functions you actually want in a
read-only NL-to-SQL pipeline: aggregates, simple math, date/time, string
manipulation, casts. Anything else — especially Postgres-specific introspection
or filesystem functions — is rejected by default.

You can extend or shrink the list either by subclassing or by constructing an
:class:`AllowList` directly with your own set.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

#: Functions that are always safe in a read-only analytics context.
DEFAULT_SAFE_FUNCTIONS: frozenset[str] = frozenset(
    name.upper()
    for name in (
        # Aggregates
        "COUNT", "SUM", "AVG", "MIN", "MAX", "STDDEV", "STDDEV_POP", "STDDEV_SAMP",
        "VARIANCE", "VAR_POP", "VAR_SAMP", "PERCENTILE_CONT", "PERCENTILE_DISC",
        "ARRAY_AGG", "STRING_AGG", "BOOL_AND", "BOOL_OR", "EVERY",
        # Window helpers (a function call on most dialects)
        "ROW_NUMBER", "RANK", "DENSE_RANK", "PERCENT_RANK", "CUME_DIST",
        "LAG", "LEAD", "FIRST_VALUE", "LAST_VALUE", "NTH_VALUE", "NTILE",
        # Math
        "ABS", "CEIL", "CEILING", "FLOOR", "ROUND", "TRUNC", "MOD", "POWER",
        "SQRT", "EXP", "LN", "LOG", "LOG10", "SIGN", "GREATEST", "LEAST",
        # String
        "LENGTH", "CHAR_LENGTH", "CHARACTER_LENGTH", "LOWER", "UPPER",
        "TRIM", "LTRIM", "RTRIM", "SUBSTRING", "SUBSTR", "REPLACE",
        "CONCAT", "CONCAT_WS", "LEFT", "RIGHT", "POSITION", "SPLIT_PART",
        "REGEXP_REPLACE", "REGEXP_MATCHES", "REGEXP_EXTRACT", "INITCAP",
        # Date/time. ``TIMESTAMP_TRUNC`` is the canonical name sqlglot rewrites
        # ``DATE_TRUNC`` into for Postgres; both must be present.
        "NOW", "CURRENT_DATE", "CURRENT_TIME", "CURRENT_TIMESTAMP",
        "DATE_TRUNC", "TIMESTAMP_TRUNC", "DATE_PART", "EXTRACT", "AGE",
        "DATE_DIFF", "DATEDIFF", "TIMESTAMP_DIFF",
        "DATE_ADD", "DATEADD", "TIMESTAMP_ADD", "DATE_SUB", "TIMESTAMP_SUB",
        "TO_DATE", "TO_TIMESTAMP", "TO_CHAR",
        # Type / null handling
        "CAST", "COALESCE", "NULLIF", "IFNULL", "TRY_CAST",
        # Conditional
        "IF", "CASE", "DECODE", "IIF",
    )
)

#: Functions that are *always* blocked, regardless of how the allow-list is
#: customised. These are dangerous enough that we don't trust callers to
#: re-enable them by accident.
ALWAYS_BLOCKED_FUNCTIONS: frozenset[str] = frozenset(
    name.upper()
    for name in (
        # Server / session control
        "PG_SLEEP", "PG_TERMINATE_BACKEND", "PG_CANCEL_BACKEND",
        "PG_RELOAD_CONF", "PG_ROTATE_LOGFILE",
        # Filesystem / shell
        "PG_READ_FILE", "PG_READ_BINARY_FILE", "PG_LS_DIR",
        "PG_STAT_FILE", "COPY", "LO_IMPORT", "LO_EXPORT",
        "LOAD_FILE", "LOAD_EXTENSION",
        # Network / RPC
        "DBLINK", "DBLINK_CONNECT", "DBLINK_EXEC",
        # Generic shell escapes seen on various engines
        "SYS_EXEC", "XP_CMDSHELL", "SP_EXECUTESQL", "EXEC", "EXECUTE",
    )
)


@dataclass(frozen=True)
class AllowList:
    """Function allow-list used by :class:`~sql_guardrails.ast_guard.Guard`.

    Args:
        allowed: Functions permitted in addition to the conservative defaults.
            Pass an empty iterable to keep only the defaults. Names are
            case-insensitive.
        blocked: Functions to block in addition to :data:`ALWAYS_BLOCKED_FUNCTIONS`.
        replace_defaults: If ``True``, ``allowed`` *replaces* the default set
            rather than extending it. Use this when you want a very tight
            allow-list (e.g. only ``COUNT`` and ``SUM``).
    """

    allowed: frozenset[str] = field(default_factory=frozenset)
    blocked: frozenset[str] = field(default_factory=frozenset)
    replace_defaults: bool = False

    def __post_init__(self) -> None:
        # ``frozenset`` is immutable but we still want case-insensitive lookups,
        # so normalise into uppercase on construction.
        object.__setattr__(self, "allowed", frozenset(s.upper() for s in self.allowed))
        object.__setattr__(self, "blocked", frozenset(s.upper() for s in self.blocked))

    @property
    def effective_allowed(self) -> frozenset[str]:
        """The full set of permitted function names."""
        if self.replace_defaults:
            return self.allowed
        return DEFAULT_SAFE_FUNCTIONS | self.allowed

    @property
    def effective_blocked(self) -> frozenset[str]:
        """The full set of blocked function names (always wins over allowed)."""
        return ALWAYS_BLOCKED_FUNCTIONS | self.blocked

    def is_allowed(self, function_name: str) -> bool:
        """Return whether ``function_name`` is permitted.

        Blocked wins over allowed, by design.
        """
        name = function_name.upper()
        if name in self.effective_blocked:
            return False
        return name in self.effective_allowed

    def extend(self, more: Iterable[str]) -> "AllowList":
        """Return a new allow-list with extra functions permitted."""
        return AllowList(
            allowed=frozenset(self.allowed | {s.upper() for s in more}),
            blocked=self.blocked,
            replace_defaults=self.replace_defaults,
        )


__all__ = [
    "AllowList",
    "DEFAULT_SAFE_FUNCTIONS",
    "ALWAYS_BLOCKED_FUNCTIONS",
]
