"""AST-based SQL safety guard.

The :class:`Guard` parses incoming SQL with `sqlglot`_ and walks the AST to
reject anything that isn't a strictly read-only ``SELECT``. Because we work on
the parsed tree, attacks hidden in comments, CTEs, subqueries, or stacked
statements all collapse to the same checks.

What gets rejected
------------------

* **Multi-statement payloads** — ``SELECT 1; DROP TABLE x;``
* **DML** — ``INSERT``, ``UPDATE``, ``DELETE``, ``MERGE`` (including when
  nested inside a CTE with ``RETURNING``).
* **DDL** — ``CREATE``, ``DROP``, ``ALTER``, ``TRUNCATE``, ``RENAME``,
  ``GRANT``, ``REVOKE``, ``COMMENT``.
* **Transaction / session control** — ``COMMIT``, ``ROLLBACK``, ``SET``,
  ``RESET``, ``SAVEPOINT``, ``LOCK``, ``VACUUM``, ``ANALYZE``.
* **System tables** — ``pg_*`` always; ``information_schema.*`` in strict mode.
* **Disallowed functions** — anything outside the
  :class:`~sql_guardrails.function_allowlist.AllowList`.

What it does **not** do
-----------------------

* It does not validate that referenced tables exist.
* It does not check row-level security; that is the database's job.
* It does not estimate cost — see
  :class:`~sql_guardrails.cost_estimator.CostEstimator`.

.. _sqlglot: https://github.com/tobymao/sqlglot
"""

from __future__ import annotations

from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError as SqlglotParseError

from .errors import (
    DisallowedFunctionError,
    DisallowedStatementError,
    DisallowedTableError,
    GuardError,
    MultiStatementError,
    ParseError,
)
from .function_allowlist import AllowList

# Expression classes that represent state-changing operations. If any of these
# turn up *anywhere* in the parsed tree, we reject. This is broader than just
# checking the root node — DML hidden inside CTEs is the whole reason this
# library exists.
_FORBIDDEN_NODE_TYPES: tuple[type[exp.Expression], ...] = (
    # DML
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Merge,
    # DDL
    exp.Create,
    exp.Drop,
    exp.Alter,
    exp.AlterColumn,
    exp.TruncateTable,
    exp.Comment,
    # Privilege / session
    exp.Grant,
    exp.Revoke,
    exp.Transaction,
    exp.Commit,
    exp.Rollback,
    exp.Set,
    exp.SetItem,
    exp.Use,
)

# Pretty names for error messages.
_NODE_TYPE_LABELS: dict[type[exp.Expression], str] = {
    exp.Insert: "INSERT",
    exp.Update: "UPDATE",
    exp.Delete: "DELETE",
    exp.Merge: "MERGE",
    exp.Create: "CREATE",
    exp.Drop: "DROP",
    exp.Alter: "ALTER",
    exp.AlterColumn: "ALTER COLUMN",
    exp.TruncateTable: "TRUNCATE",
    exp.Comment: "COMMENT",
    exp.Grant: "GRANT",
    exp.Revoke: "REVOKE",
    exp.Transaction: "BEGIN/COMMIT",
    exp.Commit: "COMMIT",
    exp.Rollback: "ROLLBACK",
    exp.Set: "SET",
    exp.SetItem: "SET",
    exp.Use: "USE",
}

# Schemas we always block reads against. ``pg_catalog`` and ``pg_*`` are
# Postgres-specific; ``mysql`` / ``sys`` cover MySQL's equivalents.
_ALWAYS_BLOCKED_SCHEMAS: frozenset[str] = frozenset(
    {"pg_catalog", "pg_toast", "mysql", "sys", "performance_schema"}
)

# Schemas only blocked when ``strict_system_tables`` is enabled.
_STRICT_BLOCKED_SCHEMAS: frozenset[str] = frozenset({"information_schema"})

# Table-name prefixes always blocked (Postgres puts a lot of introspection
# tables in the public namespace under ``pg_``).
_ALWAYS_BLOCKED_PREFIXES: tuple[str, ...] = ("pg_",)


@dataclass(frozen=True)
class GuardResult:
    """Outcome of a :meth:`Guard.check` call.

    Attributes:
        safe: Whether the SQL passed every check.
        sql: The original SQL string.
        reason: Human-readable description, populated only when ``safe`` is False.
        normalized_sql: The SQL re-emitted from the parsed AST. Useful for
            logging because comments and whitespace tricks are stripped.
    """

    safe: bool
    sql: str
    reason: str | None = None
    normalized_sql: str | None = None

    def raise_for_unsafe(self) -> None:
        """Raise :class:`GuardError` if the result is unsafe."""
        if not self.safe:
            raise GuardError(self.reason or "SQL rejected", sql=self.sql)


@dataclass
class Guard:
    """AST-based SQL safety guard.

    Args:
        dialect: sqlglot dialect string (``"postgres"``, ``"mysql"``,
            ``"sqlite"``, ...). Defaults to ``"postgres"`` because that's the
            most common analytics target and has the richest set of attack
            surfaces.
        allowlist: Function allow-list. Defaults to the conservative built-in.
        strict_system_tables: When ``True``, also reject reads against
            ``information_schema``. Leave ``False`` if your NL-to-SQL agent
            needs to introspect the schema.
    """

    dialect: str = "postgres"
    allowlist: AllowList = field(default_factory=AllowList)
    strict_system_tables: bool = False

    # ---- public API -------------------------------------------------------

    def check(self, sql: str) -> GuardResult:
        """Run all checks against ``sql``.

        Returns a :class:`GuardResult` describing the outcome. Never raises
        for *unsafe* SQL — call :meth:`GuardResult.raise_for_unsafe` if you
        want the exception. Does raise :class:`ParseError` when the SQL is
        syntactically broken, since "broken SQL" is a programmer error rather
        than an attack.
        """
        if not sql or not sql.strip():
            return GuardResult(safe=False, sql=sql, reason="empty SQL")

        try:
            statements = sqlglot.parse(sql, dialect=self.dialect)
        except SqlglotParseError as exc:
            raise ParseError(f"failed to parse SQL: {exc}", sql=sql) from exc

        # sqlglot returns ``[None]`` if the input was only comments/whitespace
        # but otherwise unparseable. Filter those out so the count is honest.
        statements = [s for s in statements if s is not None]

        if not statements:
            return GuardResult(safe=False, sql=sql, reason="no executable statement found")

        if len(statements) > 1:
            return GuardResult(
                safe=False,
                sql=sql,
                reason=f"multiple statements not allowed (found {len(statements)})",
            )

        root = statements[0]

        # Root must be a SELECT-like read.
        if not self._is_read_only_root(root):
            label = _NODE_TYPE_LABELS.get(type(root), type(root).__name__.upper())
            return GuardResult(
                safe=False,
                sql=sql,
                reason=f"only SELECT statements are allowed; got {label}",
            )

        # Walk the whole tree for forbidden node types (catches DML in CTEs).
        for node in root.walk():
            for bad in _FORBIDDEN_NODE_TYPES:
                if isinstance(node, bad):
                    label = _NODE_TYPE_LABELS.get(bad, bad.__name__.upper())
                    return GuardResult(
                        safe=False,
                        sql=sql,
                        reason=f"{label} is not allowed (found nested in query)",
                    )

        # Table-name checks.
        for table in root.find_all(exp.Table):
            blocked = self._blocked_table_reason(table)
            if blocked:
                return GuardResult(safe=False, sql=sql, reason=blocked)

        # Function-allowlist checks.
        for func in root.find_all(exp.Func):
            name = self._function_name(func)
            if name and not self.allowlist.is_allowed(name):
                return GuardResult(
                    safe=False,
                    sql=sql,
                    reason=f"function {name}() is not on the allow-list",
                )

        return GuardResult(safe=True, sql=sql, normalized_sql=root.sql(dialect=self.dialect))

    def check_or_raise(self, sql: str) -> GuardResult:
        """Like :meth:`check`, but raises the appropriate typed exception on failure."""
        result = self.check(sql)
        if result.safe:
            return result
        reason = result.reason or "SQL rejected"
        # Route to the most specific exception type we can.
        lowered = reason.lower()
        if "multiple statements" in lowered:
            raise MultiStatementError(reason, sql=sql)
        if "function" in lowered and "allow-list" in lowered:
            raise DisallowedFunctionError(reason, sql=sql)
        if "table" in lowered or "schema" in lowered:
            raise DisallowedTableError(reason, sql=sql)
        raise DisallowedStatementError(reason, sql=sql)

    # ---- internals --------------------------------------------------------

    @staticmethod
    def _is_read_only_root(node: exp.Expression) -> bool:
        """Whether ``node`` is a permitted top-level read expression."""
        # SELECT, set operations, and CTE-wrapped SELECTs are all fine at the
        # root — the deeper forbidden-node walk catches mutations nested inside.
        return isinstance(node, (exp.Select, exp.Union, exp.Intersect, exp.Except, exp.With, exp.Subquery))

    def _blocked_table_reason(self, table: exp.Table) -> str | None:
        """Return a rejection reason if the table reference is forbidden."""
        schema = (table.db or "").lower()
        name = (table.name or "").lower()

        if schema in _ALWAYS_BLOCKED_SCHEMAS:
            return f"reads against system schema '{schema}' are not allowed"
        if self.strict_system_tables and schema in _STRICT_BLOCKED_SCHEMAS:
            return f"reads against system schema '{schema}' are not allowed (strict mode)"
        for prefix in _ALWAYS_BLOCKED_PREFIXES:
            if name.startswith(prefix):
                return f"reads against system table '{table.name}' are not allowed"
        return None

    @staticmethod
    def _function_name(func: exp.Func) -> str | None:
        """Extract a usable function name from a sqlglot Func node.

        sqlglot models some functions as dedicated classes (``exp.Sum``) and
        unknown ones as :class:`exp.Anonymous`. ``sql_name()`` handles both,
        but we fall back to the class name for safety.
        """
        # exp.Anonymous carries the original name in ``this``.
        if isinstance(func, exp.Anonymous):
            this = func.this
            return this if isinstance(this, str) else None
        # Built-in classes expose a stable name via ``sql_name``.
        sql_name = getattr(func, "sql_name", None)
        if callable(sql_name):
            try:
                return sql_name()
            except Exception:  # pragma: no cover - defensive
                pass
        return type(func).__name__.upper()


__all__ = ["Guard", "GuardResult"]
