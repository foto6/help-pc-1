from __future__ import annotations

import subprocess
from pathlib import Path

BASE = "fec2bc951cef3e4c9f5d31f00503277e7ed5b90b"
SERVICE = "a4596e6f9cef8eed8161425217939282a3b52509"
SEARCH = "603d7a5791d6e0fc145e65e6b14ad031a5b2cf75"
OLD_RELAY = "992c66335c9e6c40d150bc10c086e97ea7600d48"

EXPECTED_CHANGED = {
    ".github/workflows/tests.yml",
    "docs/CANONICAL_NATIVE_FULL_DC_PARITY.md",
    "docs/NATIVE_DESKTOP_TOOL_PARITY_V1.md",
    "docs/NATIVE_DEVICE_SERVICE.md",
    "pyproject.toml",
    "schemas/pc_executor.native_tool_capabilities.v1.schema.json",
    "schemas/pc_executor.native_tool_request.v1.schema.json",
    "schemas/pc_executor.native_tool_result.v1.schema.json",
    "src/pc_executor/admin_config.py",
    "src/pc_executor/audit.py",
    "src/pc_executor/executor.py",
    "src/pc_executor/operations.py",
    "src/pc_executor/search_sessions.py",
    "src/pc_remote_transport/agent.py",
    "src/pc_remote_transport/executor_adapter.py",
    "src/pc_remote_transport/service.py",
    "src/pc_remote_transport/service_cli.py",
    "src/pc_remote_transport/windows_service.py",
    "tests/fixtures/native_tool_parity_v1/desktop_commander_mapping.json",
    "tests/test_full_dc_core_parity.py",
    "tests/test_native_device_service.py",
    "tests/test_native_remote_executor_adapter.py",
    "tests/test_native_tool_parity.py",
    "tests/test_search_sessions.py",
    "tests/windows/test_search_sessions_windows.py",
    "tools/audit_native_full_dc_parity.py",
    "tools/install_pc_native_device_service.ps1",
}

SERVICE_EXACT = {
    "src/pc_remote_transport/service_cli.py",
    "src/pc_remote_transport/windows_service.py",
    "tests/test_native_device_service.py",
    "tools/install_pc_native_device_service.ps1",
}

SEARCH_EXACT = {
    "src/pc_executor/search_sessions.py",
    "tests/test_search_sessions.py",
    "tests/windows/test_search_sessions_windows.py",
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
    assert parents == [BASE], (
        f"full DC parity head must have canonical PC Core as sole parent: {parents}"
    )
    assert git("merge-base", head, BASE).stdout.strip() == BASE

    for forbidden in (SERVICE, SEARCH, OLD_RELAY):
        result = git("merge-base", "--is-ancestor", forbidden, head, check=False)
        assert result.returncode == 1, (
            f"candidate/history was merged wholesale: {forbidden}"
        )

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

    for path in sorted(SERVICE_EXACT):
        assert rev(f"{head}:{path}") == rev(f"{SERVICE}:{path}"), (
            f"service provenance mismatch: {path}"
        )
    for path in sorted(SEARCH_EXACT):
        assert rev(f"{head}:{path}") == rev(f"{SEARCH}:{path}"), (
            f"search provenance mismatch: {path}"
        )

    from pc_executor.operations import OPS_ACTIONS, OPS_SIDE_EFFECT_ACTIONS
    from pc_remote_transport.executor_adapter import TOOL_REGISTRY_LIST

    required_actions = {
        "fs.read_many",
        "config.set",
        "device.shutdown",
        "audit.history",
        "metrics.get",
        "identity.get",
        "search.start",
        "search.read",
        "search.list",
        "search.stop",
    }
    assert required_actions <= set(OPS_ACTIONS)
    assert {tool.executor_action for tool in TOOL_REGISTRY_LIST} <= set(OPS_ACTIONS)
    assert all(
        (tool.effect == "side_effect")
        == (tool.executor_action in OPS_SIDE_EFFECT_ACTIONS)
        for tool in TOOL_REGISTRY_LIST
    )

    mapping = Path(
        "tests/fixtures/native_tool_parity_v1/desktop_commander_mapping.json"
    ).read_text(encoding="utf-8")
    assert '"unsupported_hard_gap"' in mapping
    assert '"write_pdf"' in mapping
    assert '"fs.read_many"' in mapping
    assert '"audit.history"' in mapping
    assert '"metrics.get"' in mapping

    combined = (
        Path("src/pc_remote_transport/agent.py").read_text(encoding="utf-8")
        + Path("src/pc_remote_transport/executor_adapter.py").read_text(encoding="utf-8")
        + Path("src/pc_remote_transport/service.py").read_text(encoding="utf-8")
    )
    assert "github_relay" not in combined.lower()

    checked = git("diff", "--check", BASE, head, check=False)
    assert checked.returncode == 0, checked.stdout + checked.stderr
    print(f"canonical native full DC parity audit: PASS head={head}")


if __name__ == "__main__":
    main()
