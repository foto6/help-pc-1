from __future__ import annotations

import subprocess
from pathlib import Path

PARITY_BASE = "18a6496b24520bade8246dae0759306a00a5a372"
REMOTE_SOURCE = "9254fe113f474a1108cacff97f5bccfd5107f06c"
FULL_STACK_BASE = "3a07382fa98f3e02a3d1ffbb4cc3c61b806e2e63"
COMMON_BASE = "2cc1e40f792a3d74560b726a0d246c90b7f077e9"
OLD_TRANSPORT = "8df29aad32a6cb142dff6721f92fca74a080e441"
OLD_RELAY = "992c66335c9e6c40d150bc10c086e97ea7600d48"

INTEGRATION_ONLY = {
    "docs/CANONICAL_FULL_STACK_INTEGRATION.md",
    "tests/test_native_full_stack_integration.py",
    "tools/audit_full_stack_integration.py",
}
INTENTIONAL_REMOTE_DIVERGENCES = {
    ".github/workflows/tests.yml",
    "src/pc_remote_transport/executor_adapter.py",
}
GAP_DELTA_EXPECTED = {
    ".github/workflows/tests.yml",
    "docs/NATIVE_DESKTOP_TOOL_PARITY_V1.md",
    "pyproject.toml",
    "schemas/pc_executor.native_tool_capabilities.v1.schema.json",
    "schemas/pc_executor.native_tool_request.v1.schema.json",
    "schemas/pc_executor.native_tool_result.v1.schema.json",
    "src/pc_executor/executor.py",
    "src/pc_executor/native_settings.py",
    "src/pc_executor/operations.py",
    "src/pc_executor/pdf_ops.py",
    "src/pc_remote_transport/agent.py",
    "src/pc_remote_transport/executor_adapter.py",
    "tests/fixtures/native_tool_parity_v1/desktop_commander_mapping.json",
    "tests/test_native_full_parity_gaps.py",
    "tests/test_native_tool_parity.py",
    "tools/audit_full_stack_integration.py",
}


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        check=check,
        text=True,
        capture_output=True,
    )


def rev(spec: str) -> str:
    return git("rev-parse", spec).stdout.strip()


def names(base: str, head: str) -> set[str]:
    return {
        line.strip()
        for line in git("diff", "--name-only", base, head).stdout.splitlines()
        if line.strip()
    }


def assert_not_ancestor(commit: str, head: str) -> None:
    result = git("merge-base", "--is-ancestor", commit, head, check=False)
    assert result.returncode == 1, (
        f"obsolete history unexpectedly became an ancestor: {commit}; "
        f"returncode={result.returncode} stderr={result.stderr!r}"
    )


def audit_canonical_base() -> None:
    base = FULL_STACK_BASE
    assert git("merge-base", PARITY_BASE, REMOTE_SOURCE).stdout.strip() == COMMON_BASE
    assert git("merge-base", "--is-ancestor", PARITY_BASE, base, check=False).returncode == 0
    assert git("merge-base", "--is-ancestor", REMOTE_SOURCE, base, check=False).returncode == 1
    assert_not_ancestor(OLD_TRANSPORT, base)
    assert_not_ancestor(OLD_RELAY, base)

    remote_delta = names(COMMON_BASE, REMOTE_SOURCE)
    changed = names(PARITY_BASE, base)
    expected = remote_delta | INTEGRATION_ONLY
    assert changed == expected, (
        f"canonical base diff drifted; missing={sorted(expected - changed)} "
        f"extra={sorted(changed - expected)}"
    )

    executor_changes = git(
        "diff",
        "--name-only",
        PARITY_BASE,
        base,
        "--",
        "src/pc_executor",
    ).stdout.splitlines()
    assert not executor_changes, f"canonical base parity Executor drifted: {executor_changes}"

    for path in sorted(remote_delta - INTENTIONAL_REMOTE_DIVERGENCES):
        assert rev(f"{base}:{path}") == rev(f"{REMOTE_SOURCE}:{path}"), (
            f"remote source delta not carried byte-for-byte at canonical base: {path}"
        )
    for path in sorted(INTENTIONAL_REMOTE_DIVERGENCES):
        assert path in remote_delta
        assert rev(f"{base}:{path}") != rev(f"{REMOTE_SOURCE}:{path}"), (
            f"expected canonical integration divergence missing: {path}"
        )


def main() -> None:
    head = rev("HEAD")
    audit_canonical_base()
    assert git(
        "merge-base", "--is-ancestor", FULL_STACK_BASE, head, check=False
    ).returncode == 0

    gap_delta = names(FULL_STACK_BASE, head)
    assert gap_delta == GAP_DELTA_EXPECTED, (
        f"unexpected parity-gap diff; missing={sorted(GAP_DELTA_EXPECTED - gap_delta)} "
        f"extra={sorted(gap_delta - GAP_DELTA_EXPECTED)}"
    )
    assert not any("search_session" in path.lower() for path in gap_delta)
    assert not any("service" in path.lower() for path in gap_delta)
    assert_not_ancestor(OLD_TRANSPORT, head)
    assert_not_ancestor(OLD_RELAY, head)

    adapter = Path("src/pc_remote_transport/executor_adapter.py").read_text(
        encoding="utf-8"
    )
    assert "_PARITY_EXECUTOR_ACTION_BY_TOOL" in adapter
    assert '"operations_digest"' in adapter
    assert "github_relay" not in adapter.lower()

    workflow = Path(".github/workflows/tests.yml").read_text(encoding="utf-8")
    assert "agent/pc-native-full-stack" in workflow
    assert "agent/pc-native-full-parity-gaps" in workflow
    assert "tests/test_native_full_stack_integration.py" in workflow
    assert "tools/audit_full_stack_integration.py" in workflow

    diff_check = git("diff", "--check", FULL_STACK_BASE, head, check=False)
    assert diff_check.returncode == 0, diff_check.stdout + diff_check.stderr
    print(
        "canonical full-stack integration audit: PASS "
        f"head={head} base={FULL_STACK_BASE} parity={PARITY_BASE} "
        f"remote={REMOTE_SOURCE}"
    )


if __name__ == "__main__":
    main()
