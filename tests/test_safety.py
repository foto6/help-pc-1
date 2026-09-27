import pytest

from pc_executor.safety import SafetyViolation, ensure_argv_allowed, ensure_path_allowed


def test_protected_path_is_case_insensitive_and_descendant_aware():
    with pytest.raises(SafetyViolation):
        ensure_path_allowed(r"e:\MANHWA\chapter\x.txt")


def test_neighbor_path_is_not_accidentally_blocked():
    ensure_path_allowed(r"E:\manhwa-tools\x.txt")


def test_argv_requires_explicit_safe_executable():
    assert ensure_argv_allowed(["git", "status"])[0] == "git"
    with pytest.raises(SafetyViolation):
        ensure_argv_allowed(["format.com", "C:"])
