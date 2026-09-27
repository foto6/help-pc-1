from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

PARITY_BASE = "18a6496b24520bade8246dae0759306a00a5a372"
COMMON_BASE = "2cc1e40f792a3d74560b726a0d246c90b7f077e9"
REMOTE_SOURCE = "9254fe113f474a1108cacff97f5bccfd5107f06c"
FULL_STACK_BASE = "3a07382fa98f3e02a3d1ffbb4cc3c61b806e2e63"

PARITY_GAP_INTEGRATION = "078de1871d4303db74ffff9d6b74efe1f342c482"
SEARCH_INTEGRATION = "dad382d0c34a0f77ae7dc841fad82265044e01ff"
SEARCH_SOURCE = "603d7a5791d6e0fc145e65e6b14ad031a5b2cf75"
SERVICE_INTEGRATION = "e625913c463948ce581fa7536e342baed5198f20"
SERVICE_SOURCE = "a4596e6f9cef8eed8161425217939282a3b52509"
SERVICE_SOURCE_PARENT = "e47908e2c734984a872f3cc087731f4690d1c82c"
IMMUTABLE_SERVICE_BASE = "e8804f116c84b74ae8e04f1c07abc3a01baf79a1"
IMMUTABLE_SERVICE_SOURCE = "a906312f49c97ab0ee6ceb6cda00925d5b9ebfca"

OLD_TRANSPORT = "8df29aad32a6cb142dff6721f92fca74a080e441"
OLD_RELAY = "992c66335c9e6c40d150bc10c086e97ea7600d48"

FULL_STACK_INTEGRATION_ONLY = {
    "docs/CANONICAL_FULL_STACK_INTEGRATION.md",
    "tests/test_native_full_stack_integration.py",
    "tools/audit_full_stack_integration.py",
}
FULL_STACK_REMOTE_DIVERGENCES = {
    ".github/workflows/tests.yml",
    "src/pc_remote_transport/executor_adapter.py",
}

PARITY_GAP_OVERLAY = {
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
PARITY_GAP_UNTOUCHED = {
    "docs/NATIVE_DESKTOP_TOOL_PARITY_V1.md",
    "src/pc_executor/executor.py",
    "src/pc_executor/native_settings.py",
    "src/pc_executor/pdf_ops.py",
    "src/pc_remote_transport/agent.py",
    "tests/test_native_full_parity_gaps.py",
    "tests/test_native_tool_parity.py",
}

SEARCH_SOURCE_OVERLAY = {
    ".github/workflows/tests.yml",
    "docs/NATIVE_DESKTOP_TOOL_PARITY_V1.md",
    "schemas/pc_executor.native_tool_capabilities.v1.schema.json",
    "schemas/pc_executor.native_tool_request.v1.schema.json",
    "schemas/pc_executor.native_tool_result.v1.schema.json",
    "src/pc_executor/operations.py",
    "src/pc_executor/search_sessions.py",
    "tests/fixtures/native_tool_parity_v1/desktop_commander_mapping.json",
    "tests/test_native_tool_parity.py",
    "tests/test_search_sessions.py",
    "tests/windows/test_search_sessions_windows.py",
}
SEARCH_INTEGRATION_OVERLAY = {
    "docs/CANONICAL_FULL_STACK_INTEGRATION.md",
    "docs/NATIVE_REMOTE_EXECUTOR_ADAPTER.md",
    "schemas/pc_executor.native_tool_capabilities.v1.schema.json",
    "schemas/pc_executor.native_tool_request.v1.schema.json",
    "schemas/pc_executor.native_tool_result.v1.schema.json",
    "src/pc_executor/operations.py",
    "src/pc_executor/search_sessions.py",
    "src/pc_remote_transport/executor_adapter.py",
    "tests/fixtures/native_tool_parity_v1/desktop_commander_mapping.json",
    "tests/test_native_full_stack_integration.py",
    "tests/test_native_remote_executor_adapter.py",
    "tests/test_search_sessions.py",
    "tests/windows/test_search_sessions_windows.py",
}
SEARCH_EXACT = {
    "src/pc_executor/search_sessions.py",
    "tests/test_search_sessions.py",
    "tests/windows/test_search_sessions_windows.py",
}

SERVICE_SOURCE_OVERLAY = {
    ".github/workflows/tests.yml",
    "docs/NATIVE_DEVICE_SERVICE.md",
    "pyproject.toml",
    "src/pc_remote_transport/service.py",
    "src/pc_remote_transport/service_cli.py",
    "src/pc_remote_transport/windows_service.py",
    "tests/test_native_device_service.py",
    "tools/install_pc_native_device_service.ps1",
}
SERVICE_INTEGRATION_OVERLAY = {
    "docs/NATIVE_DEVICE_SERVICE.md",
    "pyproject.toml",
    "src/pc_remote_transport/service.py",
    "src/pc_remote_transport/service_cli.py",
    "src/pc_remote_transport/windows_service.py",
    "tests/test_native_device_service.py",
    "tools/install_pc_native_device_service.ps1",
}
SERVICE_EXACT_AT_INTEGRATION = {
    "src/pc_remote_transport/service_cli.py",
    "src/pc_remote_transport/windows_service.py",
    "tools/install_pc_native_device_service.ps1",
}

IMMUTABLE_SERVICE_OVERLAY = {
    ".github/workflows/tests.yml",
    "docs/NATIVE_DEVICE_SERVICE.md",
    "tests/test_native_service_artifact.py",
    "tools/audit_full_stack_integration.py",
    "tools/install_pc_native_device_service.ps1",
    "tools/verify_pc_native_service_artifact.py",
}
IMMUTABLE_SERVICE_EXACT = {
    "docs/NATIVE_DEVICE_SERVICE.md",
    "tests/test_native_service_artifact.py",
    "tools/install_pc_native_device_service.ps1",
    "tools/verify_pc_native_service_artifact.py",
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


def parent(commit: str) -> list[str]:
    return git("show", "-s", "--format=%P", commit).stdout.strip().split()


def assert_not_ancestor(commit: str, head: str) -> None:
    result = git("merge-base", "--is-ancestor", commit, head, check=False)
    assert result.returncode == 1, (
        f"stale source unexpectedly became ancestor: {commit}; "
        f"returncode={result.returncode} stderr={result.stderr!r}"
    )


def assert_blob_equal(left: str, right: str, paths: set[str]) -> None:
    for path in sorted(paths):
        assert rev(f"{left}:{path}") == rev(f"{right}:{path}"), (
            f"blob provenance mismatch for {path}: {left} != {right}"
        )


def assert_exact_overlay(base: str, head: str, expected: set[str], label: str) -> None:
    actual = names(base, head)
    assert actual == expected, (
        f"{label} overlay mismatch; missing={sorted(expected - actual)} "
        f"extra={sorted(actual - expected)}"
    )


def audit_full_stack_base() -> None:
    assert git("merge-base", PARITY_BASE, REMOTE_SOURCE).stdout.strip() == COMMON_BASE
    assert parent(FULL_STACK_BASE) == ["2a6558588cca24b2b0d1ad1bda3c14dafa6f185d"]
    assert_not_ancestor(REMOTE_SOURCE, FULL_STACK_BASE)
    assert_not_ancestor(OLD_TRANSPORT, FULL_STACK_BASE)
    assert_not_ancestor(OLD_RELAY, FULL_STACK_BASE)

    remote_delta = names(COMMON_BASE, REMOTE_SOURCE)
    expected = remote_delta | FULL_STACK_INTEGRATION_ONLY
    assert_exact_overlay(PARITY_BASE, FULL_STACK_BASE, expected, "canonical full-stack base")

    executor_changes = git(
        "diff", "--name-only", PARITY_BASE, FULL_STACK_BASE, "--", "src/pc_executor"
    ).stdout.splitlines()
    assert not executor_changes, f"canonical full-stack base changed parity Executor: {executor_changes}"

    exact = remote_delta - FULL_STACK_REMOTE_DIVERGENCES
    assert_blob_equal(FULL_STACK_BASE, REMOTE_SOURCE, exact)
    for path in FULL_STACK_REMOTE_DIVERGENCES:
        assert path in remote_delta
        assert rev(f"{FULL_STACK_BASE}:{path}") != rev(f"{REMOTE_SOURCE}:{path}")


def audit_overlay_chain(head: str) -> None:
    assert parent(PARITY_GAP_INTEGRATION) == [FULL_STACK_BASE]
    assert parent(SEARCH_INTEGRATION) == [PARITY_GAP_INTEGRATION]
    assert parent(SERVICE_INTEGRATION) == [SEARCH_INTEGRATION]
    assert parent(head) == [SERVICE_INTEGRATION]

    assert_exact_overlay(
        FULL_STACK_BASE, PARITY_GAP_INTEGRATION, PARITY_GAP_OVERLAY, "parity-gap"
    )
    assert_blob_equal(head, PARITY_GAP_INTEGRATION, PARITY_GAP_UNTOUCHED)

    assert parent(SEARCH_SOURCE) == [PARITY_BASE]
    assert_exact_overlay(
        PARITY_BASE, SEARCH_SOURCE, SEARCH_SOURCE_OVERLAY, "search source"
    )
    assert_exact_overlay(
        PARITY_GAP_INTEGRATION,
        SEARCH_INTEGRATION,
        SEARCH_INTEGRATION_OVERLAY,
        "search integration",
    )
    assert_blob_equal(SEARCH_INTEGRATION, SEARCH_SOURCE, SEARCH_EXACT)
    assert_not_ancestor(SEARCH_SOURCE, head)

    assert parent(SERVICE_SOURCE) == [SERVICE_SOURCE_PARENT]
    assert_exact_overlay(
        SERVICE_SOURCE_PARENT, SERVICE_SOURCE, SERVICE_SOURCE_OVERLAY, "service source"
    )
    assert_exact_overlay(
        SEARCH_INTEGRATION,
        SERVICE_INTEGRATION,
        SERVICE_INTEGRATION_OVERLAY,
        "service integration",
    )
    assert_blob_equal(SERVICE_INTEGRATION, SERVICE_SOURCE, SERVICE_EXACT_AT_INTEGRATION)
    assert_not_ancestor(SERVICE_SOURCE, head)

    assert parent(IMMUTABLE_SERVICE_SOURCE) == [IMMUTABLE_SERVICE_BASE]
    assert_exact_overlay(
        IMMUTABLE_SERVICE_BASE,
        IMMUTABLE_SERVICE_SOURCE,
        IMMUTABLE_SERVICE_OVERLAY,
        "immutable service source",
    )
    assert_exact_overlay(
        SERVICE_INTEGRATION, head, IMMUTABLE_SERVICE_OVERLAY, "finalization"
    )
    assert_blob_equal(head, IMMUTABLE_SERVICE_SOURCE, IMMUTABLE_SERVICE_EXACT)
    assert_not_ancestor(IMMUTABLE_SERVICE_SOURCE, head)
def audit_registry_and_mapping() -> None:
    from pc_executor.executor import Executor
    from pc_executor.operations import (
        NATIVE_CAPABILITIES_VERSION,
        NATIVE_REQUEST_VERSION,
        NATIVE_RESULT_VERSION,
        NATIVE_TOOL_PARITY_VERSION,
        OPS_ACTIONS,
        OPS_SIDE_EFFECT_ACTIONS,
        LocalOperations,
    )
    from pc_executor.outcome_journal import OutcomeJournal
    from pc_executor.shell import SafeShellAdapter
    from pc_remote_transport.executor_adapter import ExecutorRemoteDispatcher

    fixture = json.loads(
        Path("tests/fixtures/native_tool_parity_v1/desktop_commander_mapping.json").read_text(
            encoding="utf-8"
        )
    )
    mappings = fixture["mappings"]
    assert len(mappings) == 30
    exclusions = {
        item["reference"]
        for item in mappings
        if item["status"] == "intentional_exclusion"
    }
    assert exclusions == {"get_prompts", "give_feedback_to_desktop_commander"}

    mandatory = [item for item in mappings if item["reference"] not in exclusions]
    assert len(mandatory) == 28
    assert all(item["candidate"] for item in mandatory)
    mapped_actions = {action for item in mandatory for action in item["candidate"]}
    assert mapped_actions <= set(OPS_ACTIONS), sorted(mapped_actions - set(OPS_ACTIONS))

    shell = SafeShellAdapter(allow_executables={"python", "python.exe", "python3"})
    with tempfile.TemporaryDirectory(prefix="pc-core-audit-") as raw:
        root = Path(raw)
        operations = LocalOperations(shell=shell, state_root=root / "ops")
        executor = Executor(
            shell=shell,
            operations=operations,
            outcome_journal=OutcomeJournal(root / "outcomes.jsonl"),
            dry_run=False,
        )
        caps = operations.capabilities_snapshot()
        assert caps["native_tool_parity_version"] == NATIVE_TOOL_PARITY_VERSION
        assert caps["schema_versions"]["request"] == NATIVE_REQUEST_VERSION
        assert caps["schema_versions"]["result"] == NATIVE_RESULT_VERSION
        assert caps["schema_versions"]["capabilities"] == NATIVE_CAPABILITIES_VERSION
        assert set(caps["actions"]) == set(OPS_ACTIONS)
        assert all(
            entry["side_effecting"] == (action in OPS_SIDE_EFFECT_ACTIONS)
            for action, entry in caps["actions"].items()
        )

        manifest = ExecutorRemoteDispatcher(executor).capability_manifest()
        assert manifest["executor"]["operations_digest"] == caps["attestation"]["digest"]
        assert set(OPS_ACTIONS) <= set(manifest["executor"]["actions"])

    assert fixture["contract_version"] == NATIVE_TOOL_PARITY_VERSION


def audit_security_and_ci(head: str) -> None:
    assert_not_ancestor(OLD_TRANSPORT, head)
    assert_not_ancestor(OLD_RELAY, head)

    changed_text = "\n".join(sorted(names(PARITY_BASE, head))).lower()
    assert "tools/github_relay.py" not in changed_text
    assert not any(path.startswith("relay/") for path in names(PARITY_BASE, head))

    workflow = Path(".github/workflows/tests.yml").read_text(encoding="utf-8")
    required_workflow = {
        "agent/pc-native-core-finalized",
        "tests/test_native_full_parity_gaps.py",
        "tests/test_search_sessions.py",
        "tests/test_native_device_service.py",
        "tests/test_native_service_artifact.py",
        "tests/test_native_remote_transport.py",
        "tests/test_native_remote_executor_adapter.py",
        "tests/test_native_full_stack_integration.py",
        "tests/test_action_outcome.py",
        "tests/test_outcome_journal.py",
        "tools/native_remote_harness.py",
        "tools/audit_full_stack_integration.py",
    }
    assert all(value in workflow for value in required_workflow)

    bootstrap = Path("tools/install_pc_native_device_service.ps1").read_text(
        encoding="utf-8"
    )
    assert "$RepoRoot" not in bootstrap
    assert "verify_pc_native_service_artifact.py" in bootstrap
    assert "$StagedArtifact" in bootstrap

    verifier = Path("tools/verify_pc_native_service_artifact.py").read_text(
        encoding="utf-8"
    )
    assert "pc.native.device_service.artifact_manifest.v1" in verifier
    assert "EXPECTED_REPOSITORY = \"foto6/help-pc-1\"" in verifier

    checked = git("diff", "--check", SERVICE_INTEGRATION, head, check=False)
    assert checked.returncode == 0, checked.stdout + checked.stderr


def main() -> None:
    head = rev("HEAD")
    audit_full_stack_base()
    audit_overlay_chain(head)
    audit_registry_and_mapping()
    audit_security_and_ci(head)
    print(
        "canonical PC core finalization audit: PASS "
        f"head={head} source={SERVICE_INTEGRATION} "
        f"immutable_service={IMMUTABLE_SERVICE_SOURCE}"
    )


if __name__ == "__main__":
    main()
