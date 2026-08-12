"""Planner-cost estimation and threshold enforcement.

The :class:`CostEstimator` runs ``EXPLAIN`` against the target database and
extracts a (rows, cost) tuple from the planner output. If either exceeds the
configured limit, :class:`~sql_guardrails.errors.CostLimitExceeded` or
:class:`~sql_guardrails.errors.RowLimitExceeded` is raised.

Two backends are provided:

* :class:`PostgresCostEstimator` — uses ``EXPLAIN (FORMAT JSON)`` and reads the
  top plan node's ``Total Cost`` and ``Plan Rows``. Works against any
  DB-API 2.0 Postgres connection (``psycopg2``, ``psycopg``, etc.).
* :class:`SQLiteCostEstimator` — uses ``EXPLAIN QUERY PLAN`` and a coarse
  heuristic (each ``SCAN`` counts as the table's row count, each ``SEARCH`` as
  ``log(rows)``). Useful for tests and for tiny embedded use cases; it is *not*
  a substitute for the Postgres planner.

The cost estimator never executes the query itself — that's
:class:`~sql_guardrails.executor.Executor`'s job.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any, Protocol

from .errors import CostLimitExceeded, RowLimitExceeded


class _DBAPIConnection(Protocol):
    """Structural type for the subset of DB-API 2.0 we use."""

    def cursor(self) -> Any: ...  # pragma: no cover - protocol


@dataclass(frozen=True)
class CostEstimate:
    """The planner's view of how expensive a query will be.

    Attributes:
        estimated_rows: Expected number of rows returned. ``math.inf`` if the
            backend cannot produce an estimate.
        estimated_cost: Backend-specific cost units (Postgres "cost",
            SQLite-heuristic units, ...). ``math.inf`` for unknown.
        raw: The raw planner output, kept for logging / debugging.
    """

    estimated_rows: float
    estimated_cost: float
    raw: Any = None


@dataclass
class _BaseEstimator:
    """Shared threshold-enforcement logic."""

    max_cost: float = math.inf
    max_rows: float = math.inf

    def enforce(self, estimate: CostEstimate, sql: str) -> CostEstimate:
        """Raise if the estimate exceeds either configured limit; else return it."""
        if estimate.estimated_cost > self.max_cost:
            raise CostLimitExceeded(
                f"planner cost {estimate.estimated_cost:.0f} exceeds limit {self.max_cost:.0f}",
                estimated_cost=estimate.estimated_cost,
                limit=self.max_cost,
                sql=sql,
            )
        if estimate.estimated_rows > self.max_rows:
            raise RowLimitExceeded(
                f"planner rows {estimate.estimated_rows:.0f} exceeds limit {self.max_rows:.0f}",
                estimated_rows=estimate.estimated_rows,
                limit=self.max_rows,
                sql=sql,
            )
        return estimate


@dataclass
class PostgresCostEstimator(_BaseEstimator):
    """Cost estimator backed by Postgres ``EXPLAIN (FORMAT JSON)``.

    Args:
        connection: Any DB-API 2.0 connection to a Postgres database.
        max_cost: Maximum acceptable planner ``Total Cost``. Default unbounded.
        max_rows: Maximum acceptable ``Plan Rows``. Default unbounded.

    .. note::
        ``EXPLAIN`` (without ``ANALYZE``) does not execute the query, so this
        is safe to call on hostile input *after* the AST guard has accepted it.
    """

    connection: _DBAPIConnection | None = None

    def estimate(self, sql: str) -> CostEstimate:
        """Run ``EXPLAIN`` and parse the planner output."""
        if self.connection is None:  # pragma: no cover - misconfiguration
            raise RuntimeError("PostgresCostEstimator requires a connection")

        cursor = self.connection.cursor()
        try:
            cursor.execute(f"EXPLAIN (FORMAT JSON) {sql}")
            row = cursor.fetchone()
        finally:
            cursor.close()

        # psycopg returns the JSON already parsed; psycopg2 returns a string.
        plan_blob = row[0] if isinstance(row, (list, tuple)) else row
        if isinstance(plan_blob, str):
            plan_blob = json.loads(plan_blob)

        # EXPLAIN JSON shape: [{"Plan": {"Total Cost": ..., "Plan Rows": ...}}]
        top_plan: dict[str, Any] = plan_blob[0]["Plan"]
        estimate = CostEstimate(
            estimated_rows=float(top_plan.get("Plan Rows", math.inf)),
            estimated_cost=float(top_plan.get("Total Cost", math.inf)),
            raw=plan_blob,
        )
        return self.enforce(estimate, sql)


@dataclass
class SQLiteCostEstimator(_BaseEstimator):
    """Heuristic cost estimator for SQLite.

    SQLite's planner reports a textual ``EXPLAIN QUERY PLAN`` rather than
    numeric costs. We count ``SCAN`` and ``SEARCH`` entries against a supplied
    table-cardinality map (which you might fill in from ``COUNT(*)`` during
    setup) to get a rough order-of-magnitude estimate.

    Args:
        connection: A DB-API connection to the SQLite database.
        table_rowcounts: Mapping of table name → row count. Tables not in the
            map contribute 0 cost (the caller has decided they're small).
        max_cost: Maximum acceptable cost score. Default unbounded.
        max_rows: Maximum acceptable estimated rows. Default unbounded.
    """

    connection: _DBAPIConnection | None = None
    table_rowcounts: dict[str, int] | None = None

    def estimate(self, sql: str) -> CostEstimate:
        if self.connection is None:  # pragma: no cover - misconfiguration
            raise RuntimeError("SQLiteCostEstimator requires a connection")

        cursor = self.connection.cursor()
        try:
            cursor.execute(f"EXPLAIN QUERY PLAN {sql}")
            rows = cursor.fetchall()
        finally:
            cursor.close()

        rowcounts = self.table_rowcounts or {}
        total_cost = 0.0
        total_rows = 0.0
        for entry in rows:
            # Different SQLite versions tuple this differently; the human-
            # readable description is always the last column.
            description = str(entry[-1])
            for table_name, count in rowcounts.items():
                if table_name in description:
                    if description.upper().startswith("SCAN"):
                        total_cost += count
                        total_rows += count
                    elif description.upper().startswith("SEARCH"):
                        total_cost += math.log2(max(count, 2))
                        total_rows += 1
                    break

        estimate = CostEstimate(estimated_rows=total_rows, estimated_cost=total_cost, raw=rows)
        return self.enforce(estimate, sql)


# Backwards-compatible alias: most callers just want "a cost estimator".
CostEstimator = PostgresCostEstimator

__all__ = [
    "CostEstimate",
    "CostEstimator",
    "PostgresCostEstimator",
    "SQLiteCostEstimator",
]
