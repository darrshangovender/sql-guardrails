"""sql-guardrails — make LLM-generated SQL safe to execute.

Quick start::

    from sql_guardrails import Guard

    guard = Guard(dialect="postgres")
    result = guard.check("SELECT user_id, COUNT(*) FROM events GROUP BY user_id")
    assert result.safe

    guard.check("DROP TABLE users").safe        # -> False
    guard.check("SELECT pg_sleep(1000)").safe   # -> False
    guard.check("SELECT 1; DROP TABLE x").safe  # -> False

See :mod:`sql_guardrails.ast_guard` for the AST checks,
:mod:`sql_guardrails.cost_estimator` for the planner-cost checks, and
:mod:`sql_guardrails.executor` for the safe-execution wrapper.
"""

from .ast_guard import Guard, GuardResult
from .cost_estimator import (
    CostEstimate,
    CostEstimator,
    PostgresCostEstimator,
    SQLiteCostEstimator,
)
from .errors import (
    CostLimitExceeded,
    DisallowedFunctionError,
    DisallowedStatementError,
    DisallowedTableError,
    GuardError,
    MultiStatementError,
    ParseError,
    RowLimitExceeded,
)
from .executor import ExecutionResult, Executor
from .function_allowlist import (
    ALWAYS_BLOCKED_FUNCTIONS,
    DEFAULT_SAFE_FUNCTIONS,
    AllowList,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # Core
    "Guard",
    "GuardResult",
    "AllowList",
    # Cost
    "CostEstimate",
    "CostEstimator",
    "PostgresCostEstimator",
    "SQLiteCostEstimator",
    # Executor
    "Executor",
    "ExecutionResult",
    # Errors
    "GuardError",
    "ParseError",
    "MultiStatementError",
    "DisallowedStatementError",
    "DisallowedFunctionError",
    "DisallowedTableError",
    "CostLimitExceeded",
    "RowLimitExceeded",
    # Constants
    "DEFAULT_SAFE_FUNCTIONS",
    "ALWAYS_BLOCKED_FUNCTIONS",
]
