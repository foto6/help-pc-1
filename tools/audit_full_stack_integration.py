from __future__ import annotations

import subprocess
from pathlib import Path

PARITY_BASE = "18a6496b24520bade8246dae0759306a00a5a372"
REMOTE_SOURCE = "9254fe113f474a1108cacff97f5bccfd5107f06c"
COMMON_BASE = "2cc1e40f792a3d74560b726a0d246c90b7f077e9"
OLD_TRANSPORT = "8df29aad32a6cb142dff6721f92fca74a080e441"
OLD_RELAY = "992c66335c9e6c40d150bc10c086e97ea7600d48"
SERVICE_BASE = "e47908e2c734984a872f3cc087731f4690d1c82c"
SERVICE_SOURCE = "a4596e6f9cef8eed8161425217939282a3b52509"

INTEGRATION_ONLY = {
    "docs/CANONICAL_FULL_STACK_INTEGRATION.md",
    "tests/test_native_full_stack_integration.py",
    "tools/audit_full_stack_integration.py",
}
INTENTIONAL_REMOTE_DIVERGENCES = {
    ".github/workflows/tests.yml",
    "pyproject.toml",
    "src/pc_remote_transport/executor_adapter.py",
}
SERVICE_OVERLAY = {
    "docs/NATIVE_DEVICE_SERVICE.md",
    "src/pc_remote_transport/service.py",
    "src/pc_remote_transport/service_cli.py",
    "src/pc_remote_transport/windows_service.py",
    "tests/test_native_device_service.py",
    "tools/install_pc_native_device_service.ps1",
}
SERVICE_EXACT = {
    "src/pc_remote_transport/service_cli.py",
    "src/pc_remote_transport/windows_service.py",
    "tools/install_pc_native_device_service.ps1",
}
SERVICE_INTEGRATION_DIVERGENCES = SERVICE_OVERLAY - SERVICE_EXACT


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


def main() -> None:
    head = rev("HEAD")
    assert git("merge-base", PARITY_BASE, REMOTE_SOURCE).stdout.strip() == COMMON_BASE
    assert git("merge-base", SERVICE_BASE, SERVICE_SOURCE).stdout.strip() == SERVICE_BASE
    assert git("merge-base", "--is-ancestor", PARITY_BASE, head, check=False).returncode == 0
    assert git("merge-base", "--is-ancestor", REMOTE_SOURCE, head, check=False).returncode == 1
    assert git("merge-base", "--is-ancestor", SERVICE_SOURCE, head, check=False).returncode == 1
    assert_not_ancestor(OLD_TRANSPORT, head)
    assert_not_ancestor(OLD_RELAY, head)

    remote_delta = names(COMMON_BASE, REMOTE_SOURCE)
    service_delta = names(SERVICE_BASE, SERVICE_SOURCE)
    assert service_delta == SERVICE_OVERLAY | {".github/workflows/tests.yml", "pyproject.toml"}
    changed = names(PARITY_BASE, head)
    expected = remote_delta | INTEGRATION_ONLY | SERVICE_OVERLAY
    assert changed == expected, (
        f"unexpected full-stack diff; missing={sorted(expected - changed)} "
        f"extra={sorted(changed - expected)}"
    )

    executor_changes = git(
        "diff",
        "--name-only",
        PARITY_BASE,
        head,
        "--",
        "src/pc_executor",
    ).stdout.splitlines()
    assert not executor_changes, f"parity Executor drifted: {executor_changes}"

    for path in sorted(remote_delta - INTENTIONAL_REMOTE_DIVERGENCES):
        assert rev(f"{head}:{path}") == rev(f"{REMOTE_SOURCE}:{path}"), (
            f"remote source delta not carried byte-for-byte: {path}"
        )

    for path in sorted(INTENTIONAL_REMOTE_DIVERGENCES):
        assert path in remote_delta
        assert rev(f"{head}:{path}") != rev(f"{REMOTE_SOURCE}:{path}"), (
            f"expected documented integration divergence missing: {path}"
        )

    for path in sorted(SERVICE_EXACT):
        assert rev(f"{head}:{path}") == rev(f"{SERVICE_SOURCE}:{path}"), (
            f"service component not carried byte-for-byte: {path}"
        )
    for path in sorted(SERVICE_INTEGRATION_DIVERGENCES):
        assert rev(f"{head}:{path}") != rev(f"{SERVICE_SOURCE}:{path}"), (
            f"expected full-stack service integration divergence missing: {path}"
        )

    adapter = Path("src/pc_remote_transport/executor_adapter.py").read_text(
        encoding="utf-8"
    )
    assert "_PARITY_EXECUTOR_ACTION_BY_TOOL" in adapter
    assert '"operations_digest"' in adapter
    assert "github_relay" not in adapter.lower()

    workflow = Path(".github/workflows/tests.yml").read_text(encoding="utf-8")
    assert "agent/pc-native-full-stack" in workflow
    assert "agent/pc-native-full-stack-service" in workflow
    assert "tests/test_native_full_stack_integration.py" in workflow
    assert "tests/test_native_device_service.py" in workflow
    assert "tools/audit_full_stack_integration.py" in workflow

    changed_text = "\n".join(sorted(changed)).lower()
    assert "tools/github_relay.py" not in changed_text
    assert not any(path.startswith("relay/") for path in changed)

    diff_check = git("diff", "--check", PARITY_BASE, head, check=False)
    assert diff_check.returncode == 0, diff_check.stdout + diff_check.stderr
    print(
        "canonical full-stack integration audit: PASS "
        f"head={head} parity={PARITY_BASE} remote={REMOTE_SOURCE}"
    )


if __name__ == "__main__":
    main()
