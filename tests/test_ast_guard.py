"""Adversarial tests for :class:`sql_guardrails.Guard`.

Every safe case must pass; every unsafe case must be rejected with a useful
reason. New attack vectors should be added here first, then to the YAML
corpus in :file:`benchmarks/adversarial_corpus.yml`.
"""

from __future__ import annotations

import pytest

from sql_guardrails import (
    AllowList,
    DisallowedFunctionError,
    DisallowedStatementError,
    DisallowedTableError,
    Guard,
    MultiStatementError,
    ParseError,
)

# ---------------------------------------------------------------------------
# Safe SELECT cases — everything below must pass cleanly.
# ---------------------------------------------------------------------------

SAFE_QUERIES: list[str] = [
    "SELECT 1",
    "SELECT * FROM users",
    "SELECT id, name FROM users WHERE id = 42",
    "SELECT user_id, COUNT(*) FROM events GROUP BY user_id",
    "SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id",
    "SELECT u.id, o.total FROM users u LEFT JOIN orders o ON u.id = o.user_id",
    "SELECT id FROM users WHERE id IN (SELECT user_id FROM orders)",
    "WITH recent AS (SELECT * FROM events WHERE created_at > NOW() - INTERVAL '7 days') "
    "SELECT user_id, COUNT(*) FROM recent GROUP BY user_id",
    "SELECT user_id, RANK() OVER (PARTITION BY day ORDER BY revenue DESC) FROM daily_stats",
    "SELECT DATE_TRUNC('month', created_at) AS m, SUM(amount) FROM orders GROUP BY m",
    "(SELECT id FROM users) UNION (SELECT id FROM admins)",
    "(SELECT id FROM users) INTERSECT (SELECT id FROM verified)",
    "(SELECT id FROM users) EXCEPT (SELECT id FROM banned)",
    "SELECT COALESCE(name, 'anon') FROM users",
    "SELECT CAST(amount AS DECIMAL(10,2)) FROM orders",
    "SELECT * FROM information_schema.tables",  # ok unless strict mode
    "SELECT id FROM users ORDER BY created_at DESC LIMIT 100 OFFSET 200",
    "SELECT id, name FROM users WHERE name ILIKE '%admin%'",
    "SELECT EXTRACT(YEAR FROM created_at) AS y, COUNT(*) FROM users GROUP BY y",
    "SELECT a.id FROM users a, orders b WHERE a.id = b.user_id",
]


@pytest.mark.parametrize("sql", SAFE_QUERIES)
def test_safe_queries_pass(sql: str) -> None:
    guard = Guard(dialect="postgres")
    result = guard.check(sql)
    assert result.safe, f"expected safe, got: {result.reason}"
    assert result.normalized_sql, "normalized_sql should be populated for safe queries"


# ---------------------------------------------------------------------------
# Adversarial cases — every one must be rejected, with reason text containing
# a substring that explains *why*.
# ---------------------------------------------------------------------------

# (sql, substring_that_must_appear_in_reason)
ATTACKS: list[tuple[str, str]] = [
    # DML at the root.
    ("DROP TABLE users", "DROP"),
    ("TRUNCATE TABLE orders", "TRUNCATE"),
    ("DELETE FROM users", "DELETE"),
    ("UPDATE users SET name = 'x'", "UPDATE"),
    ("INSERT INTO users VALUES (1, 'x')", "INSERT"),
    ("CREATE TABLE foo (id int)", "CREATE"),
    ("ALTER TABLE users ADD COLUMN x int", "ALTER"),
    ("GRANT SELECT ON users TO public", "GRANT"),
    ("REVOKE SELECT ON users FROM public", "REVOKE"),
    ("MERGE INTO t USING s ON true WHEN MATCHED THEN DELETE", "MERGE"),

    # Multi-statement (stacked-query) attacks.
    ("SELECT 1; DROP TABLE orders", "multiple statements"),
    ("SELECT * FROM users; DELETE FROM users;", "multiple statements"),
    ("SELECT 1;;SELECT 2", "multiple statements"),

    # Mutation hidden inside a CTE.
    ("WITH x AS (DELETE FROM users RETURNING id) SELECT * FROM x", "DELETE"),
    ("WITH x AS (UPDATE users SET name = 'x' RETURNING id) SELECT * FROM x", "UPDATE"),
    ("WITH x AS (INSERT INTO log VALUES (1) RETURNING id) SELECT * FROM x", "INSERT"),

    # Mutation hidden in a subquery (some parsers tolerate this; we don't).
    # Postgres doesn't allow this, but sqlglot will still parse it and we
    # want to make sure we'd reject if we ever saw it.
    ("WITH y AS (WITH z AS (DELETE FROM t RETURNING *) SELECT * FROM z) SELECT * FROM y", "DELETE"),

    # Function denylist — Postgres-specific system functions.
    ("SELECT pg_sleep(60)", "pg_sleep"),
    ("SELECT pg_read_file('/etc/passwd')", "pg_read_file"),
    ("SELECT pg_ls_dir('/')", "pg_ls_dir"),
    ("SELECT pg_terminate_backend(123)", "pg_terminate_backend"),
    ("SELECT dblink('host=evil', 'SELECT * FROM secrets')", "dblink"),

    # System table reads.
    ("SELECT * FROM pg_user", "pg_user"),
    ("SELECT * FROM pg_catalog.pg_class", "pg_catalog"),
    ("SELECT * FROM pg_shadow", "pg_shadow"),

    # Session control.
    ("SET search_path = malicious", "SET"),
    ("USE other_db", "USE"),
]


@pytest.mark.parametrize("sql, reason_substring", ATTACKS)
def test_attacks_are_rejected(sql: str, reason_substring: str) -> None:
    guard = Guard(dialect="postgres")
    result = guard.check(sql)
    assert not result.safe, f"expected unsafe, but guard accepted: {sql!r}"
    assert reason_substring.lower() in (result.reason or "").lower(), (
        f"reason {result.reason!r} should mention {reason_substring!r}"
    )


# ---------------------------------------------------------------------------
# Targeted regression tests — each pins one specific tricky behaviour.
# ---------------------------------------------------------------------------


def test_empty_string_rejected() -> None:
    assert Guard().check("").safe is False
    assert Guard().check("   \n\t  ").safe is False


def test_comment_only_input_rejected() -> None:
    # sqlglot strips comments; the result is "no statements".
    result = Guard().check("-- just a comment")
    assert result.safe is False
    assert "no executable statement" in (result.reason or "").lower() or "empty" in (result.reason or "").lower()


def test_line_comment_hiding_delete_is_safe() -> None:
    # ``SELECT 1 -- DELETE FROM users`` is *genuinely* a SELECT — the DELETE
    # is in a comment. We must accept it (no false positive).
    result = Guard().check("SELECT 1 -- DELETE FROM users")
    assert result.safe, f"comment-stripping should leave SELECT intact: {result.reason}"


def test_block_comment_hiding_drop_is_safe() -> None:
    result = Guard().check("/* DROP TABLE x */ SELECT 1")
    assert result.safe, f"block comments are stripped: {result.reason}"


def test_strict_system_tables_blocks_information_schema() -> None:
    relaxed = Guard(dialect="postgres", strict_system_tables=False)
    strict = Guard(dialect="postgres", strict_system_tables=True)

    sql = "SELECT * FROM information_schema.tables"
    assert relaxed.check(sql).safe is True
    assert strict.check(sql).safe is False


def test_pg_prefix_always_blocked_even_without_strict_mode() -> None:
    # The ``pg_*`` prefix is so heavily used for introspection that we always
    # block it, regardless of the strict-mode flag.
    relaxed = Guard(dialect="postgres", strict_system_tables=False)
    assert relaxed.check("SELECT * FROM pg_user").safe is False
    assert relaxed.check("SELECT * FROM pg_stat_activity").safe is False


def test_unparseable_sql_raises_parse_error() -> None:
    # Syntactically broken SQL is treated as a programmer error, not an attack.
    with pytest.raises(ParseError):
        Guard().check("SELECT FROM WHERE GROUP")


def test_check_or_raise_routes_to_typed_exception() -> None:
    guard = Guard()
    with pytest.raises(DisallowedStatementError):
        guard.check_or_raise("DROP TABLE x")
    with pytest.raises(MultiStatementError):
        guard.check_or_raise("SELECT 1; SELECT 2")
    with pytest.raises(DisallowedFunctionError):
        guard.check_or_raise("SELECT pg_sleep(1)")
    with pytest.raises(DisallowedTableError):
        guard.check_or_raise("SELECT * FROM pg_user")


def test_normalized_sql_is_populated_for_safe_queries() -> None:
    # sqlglot preserves comments in re-emission, but the security checks run
    # on the parsed AST — comments cannot smuggle in keywords. The contract
    # we expose is just "you get back a normalized form you can log".
    result = Guard().check("/* trick */ SELECT 1 /* hi */ -- comment")
    assert result.safe
    assert result.normalized_sql is not None
    assert "SELECT" in result.normalized_sql.upper()


def test_allowlist_can_be_tightened_to_replace_defaults() -> None:
    # Construct a tiny allow-list with only COUNT and SUM — nothing else.
    minimal = AllowList(allowed=frozenset({"COUNT", "SUM"}), replace_defaults=True)
    guard = Guard(dialect="postgres", allowlist=minimal)

    assert guard.check("SELECT COUNT(*) FROM users").safe is True
    # AVG is in the default allow-list but not in our tightened one.
    assert guard.check("SELECT AVG(amount) FROM orders").safe is False


def test_allowlist_can_be_extended() -> None:
    extended = AllowList().extend(["MY_CUSTOM_FN"])
    guard = Guard(dialect="postgres", allowlist=extended)
    # The custom function is now permitted...
    assert guard.check("SELECT my_custom_fn(x) FROM t").safe is True
    # ...but the defaults still work.
    assert guard.check("SELECT COUNT(*) FROM t").safe is True


def test_blocked_functions_cannot_be_re_enabled() -> None:
    # Even if a caller adds pg_sleep to their allow-list, the always-blocked
    # set wins. This is intentional: dangerous functions should not be
    # re-enabled through configuration.
    extended = AllowList().extend(["PG_SLEEP"])
    guard = Guard(dialect="postgres", allowlist=extended)
    assert guard.check("SELECT pg_sleep(1)").safe is False


def test_quoted_identifier_does_not_bypass_table_check() -> None:
    # An attacker quoting the table name shouldn't be able to slip past us.
    result = Guard().check('SELECT * FROM "pg_user"')
    assert result.safe is False


def test_multi_statement_with_trailing_semicolon_is_ok() -> None:
    # A single trailing semicolon is not "two statements".
    assert Guard().check("SELECT 1;").safe is True


def test_default_dialect_is_postgres() -> None:
    g = Guard()
    assert g.dialect == "postgres"


def test_sqlite_dialect_works() -> None:
    g = Guard(dialect="sqlite")
    assert g.check("SELECT * FROM users").safe is True
    assert g.check("DROP TABLE users").safe is False


def test_mysql_dialect_works() -> None:
    g = Guard(dialect="mysql")
    assert g.check("SELECT * FROM users").safe is True
    assert g.check("DROP TABLE users").safe is False


def test_join_count_does_not_block_legitimate_analytics() -> None:
    # Five-way join across a star schema is normal analytics; we should not
    # block this. (We deliberately did not implement a hard join cap because
    # cost estimation is the right tool for that.)
    sql = (
        "SELECT f.id "
        "FROM fact f "
        "JOIN d1 ON f.d1 = d1.id "
        "JOIN d2 ON f.d2 = d2.id "
        "JOIN d3 ON f.d3 = d3.id "
        "JOIN d4 ON f.d4 = d4.id "
        "JOIN d5 ON f.d5 = d5.id"
    )
    assert Guard().check(sql).safe is True
