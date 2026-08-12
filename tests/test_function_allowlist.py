"""Tests for the function allow-list."""

from __future__ import annotations

import pytest

from sql_guardrails import ALWAYS_BLOCKED_FUNCTIONS, DEFAULT_SAFE_FUNCTIONS, AllowList


@pytest.mark.parametrize(
    "name",
    ["COUNT", "count", "Count", "SUM", "AVG", "MIN", "MAX", "DATE_TRUNC", "COALESCE"],
)
def test_default_safe_functions_are_allowed(name: str) -> None:
    al = AllowList()
    assert al.is_allowed(name)


@pytest.mark.parametrize(
    "name",
    [
        "pg_sleep", "PG_SLEEP", "pg_read_file", "pg_terminate_backend",
        "xp_cmdshell", "load_file", "dblink", "sp_executesql",
    ],
)
def test_always_blocked_functions_are_rejected(name: str) -> None:
    al = AllowList()
    assert not al.is_allowed(name)


def test_unknown_function_is_rejected() -> None:
    al = AllowList()
    assert not al.is_allowed("some_random_udf")


def test_extend_adds_to_allowlist() -> None:
    al = AllowList().extend(["my_udf", "company_metric"])
    assert al.is_allowed("MY_UDF")
    assert al.is_allowed("company_metric")
    # Defaults still work.
    assert al.is_allowed("COUNT")


def test_replace_defaults_shrinks_allowlist() -> None:
    minimal = AllowList(allowed=frozenset({"COUNT"}), replace_defaults=True)
    assert minimal.is_allowed("COUNT")
    assert not minimal.is_allowed("SUM")
    assert not minimal.is_allowed("AVG")


def test_blocked_wins_over_allowed() -> None:
    # Even if a caller adds pg_sleep to allowed, the always-blocked set wins.
    al = AllowList(allowed=frozenset({"PG_SLEEP"}))
    assert not al.is_allowed("pg_sleep")


def test_blocked_set_is_extensible() -> None:
    al = AllowList(blocked=frozenset({"COMPANY_FORBIDDEN_FN"}))
    assert not al.is_allowed("company_forbidden_fn")
    # Defaults still allowed.
    assert al.is_allowed("COUNT")


def test_immutable_after_construction() -> None:
    # AllowList is a frozen dataclass; mutation should fail.
    al = AllowList()
    with pytest.raises(Exception):
        al.allowed = frozenset({"FOO"})  # type: ignore[misc]


def test_default_safe_functions_and_blocked_do_not_overlap() -> None:
    # Sanity: the conservative defaults must not include anything in the
    # always-blocked set, otherwise the library would have an inconsistent
    # baseline behaviour.
    overlap = DEFAULT_SAFE_FUNCTIONS & ALWAYS_BLOCKED_FUNCTIONS
    assert overlap == frozenset(), f"unsafe defaults: {overlap}"
