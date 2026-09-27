import subprocess
from pathlib import Path

FULL_STACK_BASE = "3a07382fa98f3e02a3d1ffbb4cc3c61b806e2e63"
SEARCH_PARENT = "18a6496b24520bade8246dae0759306a00a5a372"
SEARCH_SOURCE = "603d7a5791d6e0fc145e65e6b14ad031a5b2cf75"
REMOTE_SOURCE = "9254fe113f474a1108cacff97f5bccfd5107f06c"
OLD_TRANSPORT = "8df29aad32a6cb142dff6721f92fca74a080e441"
OLD_RELAY = "992c66335c9e6c40d150bc10c086e97ea7600d48"

INTEGRATION_ONLY = {
    "docs/CANONICAL_FULL_STACK_INTEGRATION.md",
    "docs/NATIVE_REMOTE_EXECUTOR_ADAPTER.md",
    "src/pc_remote_transport/executor_adapter.py",
    "tests/test_native_full_stack_integration.py",
    "tests/test_native_remote_executor_adapter.py",
    "tools/audit_full_stack_integration.py",
}
SEARCH_DIVERGENCES = {".github/workflows/tests.yml"}


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        check=check,
        text=True,
        capture_output=True,
    )


def rev(spec: str) -> str:
    return git("rev-parse", spec).stdout.strip()


def names(base: str, head: str, *paths: str) -> set[str]:
    args = ["diff", "--name-only", base, head]
    if paths:
        args.extend(["--", *paths])
    return {
        line.strip()
        for line in git(*args).stdout.splitlines()
        if line.strip()
    }


def assert_not_ancestor(commit: str, head: str) -> None:
    result = git("merge-base", "--is-ancestor", commit, head, check=False)
    assert result.returncode == 1, (
        f"unexpected ancestor {commit}; returncode={result.returncode} "
        f"stderr={result.stderr!r}"
    )


def main() -> None:
    head = rev("HEAD")
    assert git(
        "merge-base", "--is-ancestor", FULL_STACK_BASE, head, check=False
    ).returncode == 0
    assert rev(f"{head}^") == FULL_STACK_BASE, (
        "integration commit must be a single commit directly on the pinned full-stack base"
    )
    assert rev(f"{SEARCH_SOURCE}^") == SEARCH_PARENT
    assert_not_ancestor(SEARCH_SOURCE, head)
    assert_not_ancestor(REMOTE_SOURCE, head)
    assert_not_ancestor(OLD_TRANSPORT, head)
    assert_not_ancestor(OLD_RELAY, head)

    search_delta = names(SEARCH_PARENT, SEARCH_SOURCE)
    changed = names(FULL_STACK_BASE, head)
    expected = search_delta | INTEGRATION_ONLY
    assert changed == expected, (
        f"unexpected full-stack-search diff; missing={sorted(expected - changed)} "
        f"extra={sorted(changed - expected)}"
    )

    for path in sorted(search_delta - SEARCH_DIVERGENCES):
        assert rev(f"{head}:{path}") == rev(f"{SEARCH_SOURCE}:{path}"), (
            f"search source delta not carried byte-for-byte: {path}"
        )

    remote_src_changes = names(
        FULL_STACK_BASE,
        head,
        "src/pc_remote_transport",
    )
    assert remote_src_changes == {
        "src/pc_remote_transport/executor_adapter.py"
    }, f"unexpected remote transport source drift: {sorted(remote_src_changes)}"

    adapter = Path("src/pc_remote_transport/executor_adapter.py").read_text(
        encoding="utf-8"
    )
    for tool in ("search.start", "search.read", "search.list", "search.stop"):
        assert f'NativeTool("{tool}"' in adapter
    assert "capabilities_digest=context.session_capabilities_digest" in adapter
    assert "STALE_SEARCH_HANDLE" in adapter
    assert "_filter_search_list" in adapter
    assert "github_relay" not in adapter.lower()

    workflow = Path(".github/workflows/tests.yml").read_text(encoding="utf-8")
    assert "agent/pc-native-full-stack-search" in workflow
    assert "tests/test_search_sessions.py" in workflow
    assert "tests/windows/test_search_sessions_windows.py" in workflow
    assert "tests/test_native_remote_executor_adapter.py" in workflow
    assert "tests/test_native_full_stack_integration.py" in workflow
    assert "tools/audit_full_stack_integration.py" in workflow

    changed_text = "\n".join(sorted(changed)).lower()
    assert "tools/github_relay.py" not in changed_text
    assert not any(path.startswith("relay/") for path in changed)

    diff_check = git("diff", "--check", FULL_STACK_BASE, head, check=False)
    assert diff_check.returncode == 0, diff_check.stdout + diff_check.stderr
    print(
        "canonical full-stack search integration audit: PASS "
        f"head={head} base={FULL_STACK_BASE} search={SEARCH_SOURCE}"
    )


if __name__ == "__main__":
    main()
