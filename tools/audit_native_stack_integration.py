from __future__ import annotations

import subprocess
from pathlib import Path

BASE = "18a6496b24520bade8246dae0759306a00a5a372"
TRANSPORT = "e47908e2c734984a872f3cc087731f4690d1c82c"
ADAPTER = "30d7cb0f0571c3bd1565fd6b96c069ef64f3d9dd"
OLD_RELAY = "992c66335c9e6c40d150bc10c086e97ea7600d48"

EXPECTED_CHANGED = {
    ".github/workflows/tests.yml",
    "docs/CANONICAL_NATIVE_STACK_INTEGRATION.md",
    "docs/NATIVE_REMOTE_EXECUTOR_ADAPTER.md",
    "docs/NATIVE_REMOTE_MIGRATION.md",
    "docs/NATIVE_REMOTE_THREAT_MODEL.md",
    "docs/NATIVE_REMOTE_TRANSPORT.md",
    "pyproject.toml",
    "src/pc_remote_transport/__init__.py",
    "src/pc_remote_transport/agent.py",
    "src/pc_remote_transport/config.py",
    "src/pc_remote_transport/executor_adapter.py",
    "src/pc_remote_transport/ledger.py",
    "src/pc_remote_transport/protocol.py",
    "src/pc_remote_transport/websocket.py",
    "tests/test_native_remote_executor_adapter.py",
    "tests/test_native_remote_executor_adapter_recovery.py",
    "tests/test_native_remote_transport.py",
    "tests/test_native_stack_integration.py",
    "tests/test_remote_protocol.py",
    "tools/audit_native_stack_integration.py",
    "tools/native_remote_harness.py",
}

TRANSPORT_EXACT = {
    "docs/NATIVE_REMOTE_MIGRATION.md",
    "docs/NATIVE_REMOTE_THREAT_MODEL.md",
    "docs/NATIVE_REMOTE_TRANSPORT.md",
    "src/pc_remote_transport/config.py",
    "src/pc_remote_transport/ledger.py",
    "src/pc_remote_transport/protocol.py",
    "src/pc_remote_transport/websocket.py",
    "tests/test_native_remote_transport.py",
    "tests/test_remote_protocol.py",
    "tools/native_remote_harness.py",
}
ADAPTER_HOOK_EXACT = {
    "src/pc_remote_transport/__init__.py",
    "src/pc_remote_transport/agent.py",
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


def tracked(ref: str, prefix: str) -> list[str]:
    return [
        line for line in git("ls-tree", "-r", "--name-only", ref, prefix).stdout.splitlines()
        if line
    ]


def main() -> None:
    head = rev("HEAD")
    parents = git("show", "-s", "--format=%P", head).stdout.strip().split()
    assert parents == [BASE], f"canonical stack must have {BASE} as sole parent: {parents}"
    assert git("merge-base", head, BASE).stdout.strip() == BASE

    for forbidden in (TRANSPORT, ADAPTER, OLD_RELAY):
        result = git("merge-base", "--is-ancestor", forbidden, head, check=False)
        assert result.returncode == 1, f"stale candidate became ancestor: {forbidden}"
    changed = {
        line.strip()
        for line in git("diff", "--name-only", BASE, head).stdout.splitlines()
        if line.strip()
    }
    assert changed == EXPECTED_CHANGED, (
        f"unexpected diff; missing={sorted(EXPECTED_CHANGED - changed)} "
        f"extra={sorted(changed - EXPECTED_CHANGED)}"
    )
    assert "tools/github_relay.py" not in changed
    assert not any(path.startswith("relay/") for path in changed)
    assert not any(path.startswith("src/pc_executor/") for path in changed)

    for path in sorted(TRANSPORT_EXACT):
        assert rev(f"{head}:{path}") == rev(f"{TRANSPORT}:{path}"), (
            f"transport provenance mismatch: {path}"
        )
    for path in sorted(ADAPTER_HOOK_EXACT):
        assert rev(f"{head}:{path}") == rev(f"{ADAPTER}:{path}"), (
            f"adapter transport-hook provenance mismatch: {path}"
        )

    for prefix in ("src/pc_executor", "schemas"):
        for path in tracked(BASE, prefix):
            assert rev(f"{head}:{path}") == rev(f"{BASE}:{path}"), (
                f"authoritative parity/Executor byte drift: {path}"
            )
    adapter_text = Path("src/pc_remote_transport/executor_adapter.py").read_text(
        encoding="utf-8"
    )
    agent_text = Path("src/pc_remote_transport/agent.py").read_text(encoding="utf-8")
    assert "github_relay" not in (adapter_text + agent_text).lower()

    from pc_executor.operations import OPS_ACTIONS, OPS_SIDE_EFFECT_ACTIONS
    from pc_remote_transport.executor_adapter import TOOL_REGISTRY_LIST

    assert {tool.executor_action for tool in TOOL_REGISTRY_LIST} <= set(OPS_ACTIONS)
    assert all(
        (tool.effect == "side_effect") == (tool.executor_action in OPS_SIDE_EFFECT_ACTIONS)
        for tool in TOOL_REGISTRY_LIST
    )

    checked = git("diff", "--check", BASE, head, check=False)
    assert checked.returncode == 0, checked.stdout + checked.stderr
    print(f"canonical native stack audit: PASS head={head}")


if __name__ == "__main__":
    main()
