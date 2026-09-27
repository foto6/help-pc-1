from __future__ import annotations

import json
import subprocess
from pathlib import Path

from pc_executor.operations import (
    NATIVE_TOOL_PARITY_VERSION,
    OPS_ACTIONS,
    OPS_SIDE_EFFECT_ACTIONS,
)
from pc_remote_transport.executor_adapter import (
    EXPECTED_COMPAT_TOOL_REGISTRY_V1_DIGEST,
    PARITY_TOOL_REGISTRY_LIST,
    TOOL_REGISTRY_DIGEST,
)

BASE = "078de1871d4303db74ffff9d6b74efe1f342c482"
SEARCH = "c3b86fefb66348e6a78f5f555a59f81154bd357e"
SERVICE = "e8804f116c84b74ae8e04f1c07abc3a01baf79a1"
STRICT_B = "fec2bc951cef3e4c9f5d31f00503277e7ed5b90b"
OLD_TRANSPORT = "8df29aad32a6cb142dff6721f92fca74a080e441"
OLD_RELAY = "992c66335c9e6c40d150bc10c086e97ea7600d48"

TRANSPORT_CORE = {
    "src/pc_remote_transport/agent.py",
    "src/pc_remote_transport/config.py",
    "src/pc_remote_transport/ledger.py",
    "src/pc_remote_transport/protocol.py",
    "src/pc_remote_transport/websocket.py",
}
EXECUTOR_SCHEMA_ALLOWED = {
    "src/pc_executor/operations.py",
    "src/pc_executor/search_sessions.py",
    "schemas/pc_executor.native_tool_capabilities.v1.schema.json",
    "schemas/pc_executor.native_tool_request.v1.schema.json",
    "schemas/pc_executor.native_tool_result.v1.schema.json",
}
SEARCH_EXACT = {
    "src/pc_executor/search_sessions.py",
    "tests/test_search_sessions.py",
    "tests/windows/test_search_sessions_windows.py",
}
SERVICE_EXACT = {
    "src/pc_remote_transport/service.py",
    "src/pc_remote_transport/service_cli.py",
    "src/pc_remote_transport/windows_service.py",
    "tests/test_native_device_service.py",
    "tools/install_pc_native_device_service.ps1",
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


def names(base: str, head: str, *paths: str) -> set[str]:
    args = ["diff", "--name-only", base, head]
    if paths:
        args.extend(["--", *paths])
    return {line for line in git(*args).stdout.splitlines() if line}
def assert_not_ancestor(commit: str, head: str) -> None:
    result = git("merge-base", "--is-ancestor", commit, head, check=False)
    assert result.returncode == 1, f"forbidden ancestor: {commit}"


def assert_same_blob(left: str, right: str, path: str) -> None:
    assert rev(f"{left}:{path}") == rev(f"{right}:{path}"), path


def main() -> None:
    head = rev("HEAD")
    assert git("merge-base", "--is-ancestor", BASE, head, check=False).returncode == 0
    for source in (SEARCH, SERVICE, STRICT_B):
        assert_not_ancestor(source, head)
    assert_not_ancestor(OLD_TRANSPORT, head)
    assert_not_ancestor(OLD_RELAY, head)

    for path in sorted(TRANSPORT_CORE):
        assert_same_blob(BASE, head, path)

    changed_executor_schema = names(
        BASE,
        head,
        "src/pc_executor",
        "schemas",
    )
    assert changed_executor_schema == EXECUTOR_SCHEMA_ALLOWED, (
        "unexpected Executor/schema drift: "
        f"{sorted(changed_executor_schema ^ EXECUTOR_SCHEMA_ALLOWED)}"
    )

    base_tracked = {
        line
        for line in git(
            "ls-tree",
            "-r",
            "--name-only",
            BASE,
            "src/pc_executor",
            "schemas",
        ).stdout.splitlines()
        if line
    }
    for path in sorted(base_tracked - EXECUTOR_SCHEMA_ALLOWED):
        assert_same_blob(BASE, head, path)

    for path in sorted(SEARCH_EXACT):
        assert_same_blob(SEARCH, head, path)
    for path in sorted(SERVICE_EXACT):
        assert_same_blob(SERVICE, head, path)

    assert TOOL_REGISTRY_DIGEST == EXPECTED_COMPAT_TOOL_REGISTRY_V1_DIGEST
    direct_actions = {tool.executor_action for tool in PARITY_TOOL_REGISTRY_LIST}
    assert direct_actions <= set(OPS_ACTIONS)
    for tool in PARITY_TOOL_REGISTRY_LIST:
        assert (tool.effect == "side_effect") == (
            tool.executor_action in OPS_SIDE_EFFECT_ACTIONS
        )

    root = Path(__file__).resolve().parents[1]
    mapping = json.loads(
        (
            root
            / "tests"
            / "fixtures"
            / "native_tool_parity_v1"
            / "desktop_commander_mapping.json"
        ).read_text(encoding="utf-8")
    )
    entries = mapping["mappings"]
    assert len(entries) == 30
    exclusions = {
        item["reference"]
        for item in entries
        if item["status"] == "intentional_exclusion"
    }
    assert exclusions == {
        "get_prompts",
        "give_feedback_to_desktop_commander",
    }
    mandatory = [item for item in entries if item["reference"] not in exclusions]
    assert len(mandatory) == 28
    for item in mandatory:
        candidates = set(item["candidate"])
        assert candidates
        assert candidates <= direct_actions, (
            item["reference"],
            sorted(candidates - direct_actions),
        )
    adapter = (
        root / "src" / "pc_remote_transport" / "executor_adapter.py"
    ).read_text(encoding="utf-8")
    assert 'PARITY_TOOL_REGISTRY_V1 = "pc.native.parity_tool_registry.v1"' in adapter
    assert '"uia.find": "No current parity or legacy Executor action' in adapter
    assert '"device.set_config": "config.set"' in adapter
    assert '"process.interact": "shell.session.write_stdin"' in adapter
    assert "github_relay" not in adapter.lower()

    mapping_text = json.dumps(mapping, sort_keys=True)
    assert "E:\\manhwa" not in mapping_text

    changed = names(BASE, head)
    assert "tools/github_relay.py" not in changed
    assert not any(path.startswith("relay/") for path in changed)

    assert (root / "tests" / "test_native_full_stack_integration.py").exists()
    assert (root / "tests" / "test_native_stack_integration.py").exists()
    assert (root / "tests" / "test_native_core_registry_policy.py").exists()
    assert (root / "docs" / "CANONICAL_PC_CORE_FINAL_CANDIDATE.md").exists()

    workflow = (root / ".github" / "workflows" / "tests.yml").read_text(
        encoding="utf-8"
    )
    assert "agent/pc-native-core-final-candidate" in workflow
    assert "test_native_stack_integration.py" in workflow
    assert "test_native_core_registry_policy.py" in workflow
    assert "test_native_device_service.py" in workflow
    assert "test_search_sessions.py" in workflow

    diff_check = git("diff", "--check", BASE, head, check=False)
    assert diff_check.returncode == 0, diff_check.stdout + diff_check.stderr

    print(
        "native PC core final candidate audit: PASS "
        f"head={head} base={BASE} search={SEARCH} service={SERVICE} "
        f"strict_b={STRICT_B} parity={NATIVE_TOOL_PARITY_VERSION}"
    )


if __name__ == "__main__":
    main()
