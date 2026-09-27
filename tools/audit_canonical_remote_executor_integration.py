from __future__ import annotations

import subprocess
from pathlib import Path

BASE = "e47908e2c734984a872f3cc087731f4690d1c82c"
SOURCE = "30d7cb0f0571c3bd1565fd6b96c069ef64f3d9dd"
OLD_TRANSPORT = "8df29aad32a6cb142dff6721f92fca74a080e441"
OLD_RELAY = "992c66335c9e6c40d150bc10c086e97ea7600d48"

EXPECTED_CHANGED = {
    ".github/workflows/tests.yml",
    "docs/CANONICAL_REMOTE_EXECUTOR_INTEGRATION.md",
    "docs/NATIVE_REMOTE_EXECUTOR_ADAPTER.md",
    "src/pc_remote_transport/__init__.py",
    "src/pc_remote_transport/agent.py",
    "src/pc_remote_transport/executor_adapter.py",
    "tests/test_native_remote_executor_adapter.py",
    "tests/test_native_remote_executor_adapter_recovery.py",
    "tools/audit_canonical_remote_executor_integration.py",
}
SOURCE_BLOB_PATHS = {
    "src/pc_remote_transport/__init__.py",
    "src/pc_remote_transport/agent.py",
    "src/pc_remote_transport/executor_adapter.py",
    "tests/test_native_remote_executor_adapter.py",
    "tests/test_native_remote_executor_adapter_recovery.py",
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


def main() -> None:
    head = rev("HEAD")
    parents = git("show", "-s", "--format=%P", head).stdout.strip().split()
    assert parents == [BASE], f"HEAD must have canonical base as sole parent: {parents}"

    assert rev(f"{head}^") == BASE
    assert git("merge-base", head, BASE).stdout.strip() == BASE

    for forbidden in (OLD_RELAY, OLD_TRANSPORT):
        result = git("merge-base", "--is-ancestor", forbidden, head, check=False)
        assert result.returncode == 1, (
            f"obsolete branch commit unexpectedly became an ancestor: {forbidden}; "
            f"returncode={result.returncode} stderr={result.stderr!r}"
        )

    changed = {
        line.strip()
        for line in git("diff", "--name-only", BASE, head).stdout.splitlines()
        if line.strip()
    }
    assert changed == EXPECTED_CHANGED, (
        f"unexpected canonical diff; missing={sorted(EXPECTED_CHANGED - changed)} "
        f"extra={sorted(changed - EXPECTED_CHANGED)}"
    )
    assert not any(path.startswith("src/pc_executor/") for path in changed)
    assert "tools/github_relay.py" not in changed
    assert not any(path.startswith("relay/") for path in changed)

    for path in sorted(SOURCE_BLOB_PATHS):
        assert rev(f"{head}:{path}") == rev(f"{SOURCE}:{path}"), (
            f"ported adapter blob differs from source candidate: {path}"
        )

    base_executor = git("ls-tree", "-r", "--name-only", BASE, "src/pc_executor").stdout.splitlines()
    for path in base_executor:
        if path:
            assert rev(f"{head}:{path}") == rev(f"{BASE}:{path}"), (
                f"authoritative Executor byte drift: {path}"
            )

    source_text = (
        Path("src/pc_remote_transport/executor_adapter.py").read_text(encoding="utf-8")
        + Path("src/pc_remote_transport/agent.py").read_text(encoding="utf-8")
    )
    assert "github_relay" not in source_text.lower()

    diff_check = git("diff", "--check", BASE, head, check=False)
    assert diff_check.returncode == 0, diff_check.stdout + diff_check.stderr

    print(f"canonical remote Executor integration audit: PASS head={head}")


if __name__ == "__main__":
    main()
