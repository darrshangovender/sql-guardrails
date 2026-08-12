"""Safe query executor.

The :class:`Executor` wraps a database connection and runs queries through
three barriers:

1. The :class:`~sql_guardrails.ast_guard.Guard` AST check.
2. An optional :class:`~sql_guardrails.cost_estimator.PostgresCostEstimator`
   threshold check.
3. The actual ``cursor.execute`` call, with a statement timeout set on the
   session (Postgres) or via Python-level wall clock (SQLite).

If any step rejects the SQL, a typed :class:`~sql_guardrails.errors.GuardError`
is raised and the query is never executed.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Protocol

from .ast_guard import Guard
from .cost_estimator import PostgresCostEstimator, SQLiteCostEstimator


class _DBAPIConnection(Protocol):
    def cursor(self) -> Any: ...  # pragma: no cover - protocol


@dataclass
class ExecutionResult:
    """The rows + column metadata from a successful execution."""

    rows: list[tuple[Any, ...]]
    columns: list[str]
    normalized_sql: str


@dataclass
class Executor:
    """Runs SQL through the guard stack and then executes it.

    Args:
        connection: A DB-API 2.0 connection. Should be opened with a
            read-only role on Postgres (we set ``default_transaction_read_only``
            defensively, but the database role is the real security boundary).
        guard: The :class:`~sql_guardrails.ast_guard.Guard` to enforce. A
            default Postgres-dialect guard is created if not supplied.
        cost_estimator: Optional cost estimator. Either
            :class:`~sql_guardrails.cost_estimator.PostgresCostEstimator` or
            :class:`~sql_guardrails.cost_estimator.SQLiteCostEstimator`.
        statement_timeout_ms: Statement timeout in milliseconds. On Postgres
            this is set via ``SET LOCAL statement_timeout``; on SQLite we
            enforce a Python-side wall clock via
            ``connection.set_progress_handler``.
        enforce_read_only: When ``True`` (default), set the session to
            read-only before each query. Belt-and-braces protection in case
            the AST guard misses something.
    """

    connection: _DBAPIConnection
    guard: Guard = field(default_factory=Guard)
    cost_estimator: PostgresCostEstimator | SQLiteCostEstimator | None = None
    statement_timeout_ms: int = 8_000
    enforce_read_only: bool = True

    def execute(self, sql: str) -> ExecutionResult:
        """Validate ``sql`` and execute it.

        Raises any :class:`~sql_guardrails.errors.GuardError` subclass on
        rejection; the underlying ``Exception`` from the database driver on
        execution failure.
        """
        result = self.guard.check(sql)
        if not result.safe:
            self.guard.check_or_raise(sql)  # raises the typed exception

        # Cost check (optional). Done before exec so we don't waste work.
        if self.cost_estimator is not None:
            self.cost_estimator.estimate(sql)

        cursor = self.connection.cursor()
        try:
            self._apply_session_settings(cursor)
            cursor.execute(sql)
            description = cursor.description or []
            columns = [d[0] for d in description]
            rows = list(cursor.fetchall()) if description else []
        finally:
            cursor.close()

        return ExecutionResult(
            rows=rows,
            columns=columns,
            normalized_sql=result.normalized_sql or sql,
        )

    def _apply_session_settings(self, cursor: Any) -> None:
        """Set per-statement timeout and read-only flag, dialect-aware."""
        dialect = self.guard.dialect.lower()
        if dialect == "postgres":
            cursor.execute(f"SET LOCAL statement_timeout = {int(self.statement_timeout_ms)}")
            if self.enforce_read_only:
                cursor.execute("SET LOCAL default_transaction_read_only = on")
        elif dialect == "sqlite":
            # SQLite has no native statement timeout; use a progress handler
            # tied to a Python-side wall clock. The handler returns non-zero
            # to abort the in-flight statement.
            self._install_sqlite_timeout()
            if self.enforce_read_only:
                # ``query_only`` PRAGMA blocks any writes for the session.
                cursor.execute("PRAGMA query_only = ON")

    def _install_sqlite_timeout(self) -> None:
        """Install a progress handler that aborts long-running SQLite queries."""
        # Lazy import: we don't want a hard dep on sqlite3 at module import.
        deadline = threading.Event()

        def _trip() -> None:
            deadline.set()

        timer = threading.Timer(self.statement_timeout_ms / 1000.0, _trip)
        timer.daemon = True

        def _progress() -> int:
            # Returning non-zero asks SQLite to abort the current statement.
            return 1 if deadline.is_set() else 0

        # ``set_progress_handler`` is invoked every N VDBE ops; 1000 is a
        # reasonable balance between responsiveness and overhead.
        if hasattr(self.connection, "set_progress_handler"):
            self.connection.set_progress_handler(_progress, 1000)
            timer.start()


__all__ = ["Executor", "ExecutionResult"]
