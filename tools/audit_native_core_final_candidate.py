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
    PARITY_TOOL_REGISTRY_DIGEST,
    PARITY_TOOL_REGISTRY_LIST,
    PARITY_TOOL_REGISTRY_V1,
    TOOL_REGISTRY_DIGEST,
)

BASE = "078de1871d4303db74ffff9d6b74efe1f342c482"
FULL_STACK_BASE = "3a07382fa98f3e02a3d1ffbb4cc3c61b806e2e63"
SEARCH = "c3b86fefb66348e6a78f5f555a59f81154bd357e"
SERVICE = "e8804f116c84b74ae8e04f1c07abc3a01baf79a1"
IMMUTABLE_SERVICE = "a906312f49c97ab0ee6ceb6cda00925d5b9ebfca"
LSA_HOTFIX = "72b8c83d99eca8226afdd8a149cd49ea463f5013"
SECRET_STDIN_HOTFIX = "fa27d68d2f24ca9f21768b8792bf012b500aeedd"
LAST_GREEN_PC = "97697b340f30f0190776eba4bd6da71c1a0d28d1"
SERVICE_HOST_HOTFIX = "93150246322636ae3ea55f59be2104a440fe2c7d"
LAST_GREEN_SERVICE_HOST = "a42533ce655064e789fbbe17a6dc45cf0c7f6f7f"
SERVICE_HOST_PATH_HOTFIX = "852f461c73b84aa2b642f0e89ba13e626498e5c0"
STRICT_B = "fec2bc951cef3e4c9f5d31f00503277e7ed5b90b"
OLD_TRANSPORT = "8df29aad32a6cb142dff6721f92fca74a080e441"
OLD_RELAY = "992c66335c9e6c40d150bc10c086e97ea7600d48"

SEARCH_SOURCE_DELTA = {
    ".github/workflows/tests.yml",
    "docs/CANONICAL_FULL_STACK_INTEGRATION.md",
    "docs/NATIVE_DESKTOP_TOOL_PARITY_V1.md",
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
    "tests/test_native_tool_parity.py",
    "tests/test_search_sessions.py",
    "tests/windows/test_search_sessions_windows.py",
    "tools/audit_full_stack_integration.py",
}
SERVICE_SOURCE_DELTA = {
    ".github/workflows/tests.yml",
    "docs/NATIVE_DEVICE_SERVICE.md",
    "pyproject.toml",
    "src/pc_remote_transport/service.py",
    "src/pc_remote_transport/service_cli.py",
    "src/pc_remote_transport/windows_service.py",
    "tests/test_native_device_service.py",
    "tools/audit_full_stack_integration.py",
    "tools/install_pc_native_device_service.ps1",
}
IMMUTABLE_SERVICE_DELTA = {
    ".github/workflows/tests.yml",
    "docs/NATIVE_DEVICE_SERVICE.md",
    "tests/test_native_service_artifact.py",
    "tools/audit_full_stack_integration.py",
    "tools/install_pc_native_device_service.ps1",
    "tools/verify_pc_native_service_artifact.py",
}

FINAL_CHANGED = {
    ".github/workflows/tests.yml",
    "docs/CANONICAL_FULL_STACK_INTEGRATION.md",
    "docs/CANONICAL_PC_CORE_FINAL_CANDIDATE.md",
    "docs/NATIVE_DEVICE_SERVICE.md",
    "docs/NATIVE_REMOTE_EXECUTOR_ADAPTER.md",
    "pyproject.toml",
    "schemas/pc_executor.native_tool_capabilities.v1.schema.json",
    "schemas/pc_executor.native_tool_request.v1.schema.json",
    "schemas/pc_executor.native_tool_result.v1.schema.json",
    "src/pc_executor/operations.py",
    "src/pc_executor/search_sessions.py",
    "src/pc_remote_transport/__init__.py",
    "src/pc_remote_transport/executor_adapter.py",
    "src/pc_remote_transport/service.py",
    "src/pc_remote_transport/service_cli.py",
    "src/pc_remote_transport/windows_service.py",
    "tests/fixtures/native_tool_parity_v1/desktop_commander_mapping.json",
    "tests/test_native_core_registry_policy.py",
    "tests/test_native_device_service.py",
    "tests/test_native_full_stack_integration.py",
    "tests/test_native_remote_executor_adapter.py",
    "tests/test_native_remote_executor_adapter_recovery.py",
    "tests/test_native_service_artifact.py",
    "tests/test_native_stack_integration.py",
    "tests/test_search_sessions.py",
    "tests/windows/test_search_sessions_windows.py",
    "tools/audit_full_stack_integration.py",
    "tools/audit_native_core_final_candidate.py",
    "tools/install_pc_native_device_service.ps1",
    "tools/verify_pc_native_service_artifact.py",
}
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
SEARCH_TRACKED = {
    "schemas/pc_executor.native_tool_capabilities.v1.schema.json",
    "schemas/pc_executor.native_tool_request.v1.schema.json",
    "schemas/pc_executor.native_tool_result.v1.schema.json",
    "src/pc_executor/operations.py",
    "src/pc_executor/search_sessions.py",
    "tests/test_search_sessions.py",
    "tests/windows/test_search_sessions_windows.py",
}
SEARCH_COMPOSITION_DIVERGENCES = {
    "schemas/pc_executor.native_tool_capabilities.v1.schema.json",
    "schemas/pc_executor.native_tool_request.v1.schema.json",
    "schemas/pc_executor.native_tool_result.v1.schema.json",
    "src/pc_executor/operations.py",
    "src/pc_executor/search_sessions.py",
    "tests/test_search_sessions.py",
}
SERVICE_IMMUTABLE_EXACT = {
    "docs/NATIVE_DEVICE_SERVICE.md",
    "src/pc_remote_transport/service.py",
    "tests/test_native_service_artifact.py",
    "tools/install_pc_native_device_service.ps1",
    "tools/verify_pc_native_service_artifact.py",
}
SERVICE_HOST_HOTFIX_EXACT = {
    "src/pc_remote_transport/windows_service.py",
    "tests/test_native_device_service.py",
}
SECRET_STDIN_HOTFIX_EXACT = {
    "src/pc_remote_transport/service_cli.py",
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
    assert result.returncode == 1, f"forbidden source history became ancestor: {commit}"


def assert_same_blob(left: str, right: str, path: str) -> None:
    assert rev(f"{left}:{path}") == rev(f"{right}:{path}"), path


def assert_source_deltas() -> None:
    assert git("merge-base", BASE, SEARCH).stdout.strip() == FULL_STACK_BASE
    assert git("merge-base", BASE, SERVICE).stdout.strip() == FULL_STACK_BASE
    assert git("merge-base", SERVICE, IMMUTABLE_SERVICE).stdout.strip() == SERVICE
    assert names(FULL_STACK_BASE, SEARCH) == SEARCH_SOURCE_DELTA
    assert names(FULL_STACK_BASE, SERVICE) == SERVICE_SOURCE_DELTA
    assert names(SERVICE, IMMUTABLE_SERVICE) == IMMUTABLE_SERVICE_DELTA


def assert_layered_provenance(head: str) -> None:
    assert git("merge-base", "--is-ancestor", BASE, head, check=False).returncode == 0
    for source in (SEARCH, SERVICE, IMMUTABLE_SERVICE, STRICT_B):
        assert_not_ancestor(source, head)
    assert_not_ancestor(OLD_TRANSPORT, head)
    assert_not_ancestor(OLD_RELAY, head)

    changed = names(BASE, head)
    assert changed == FINAL_CHANGED, (
        f"final changed-file set drifted; missing={sorted(FINAL_CHANGED - changed)} "
        f"extra={sorted(changed - FINAL_CHANGED)}"
    )

    for path in sorted(TRANSPORT_CORE):
        assert_same_blob(BASE, head, path)

    changed_executor_schema = names(BASE, head, "src/pc_executor", "schemas")
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

    search_diff = names(SEARCH, head, *sorted(SEARCH_TRACKED))
    assert search_diff == SEARCH_COMPOSITION_DIVERGENCES, (
        f"search composition drifted: {sorted(search_diff ^ SEARCH_COMPOSITION_DIVERGENCES)}"
    )
    for path in sorted(SEARCH_TRACKED - SEARCH_COMPOSITION_DIVERGENCES):
        assert_same_blob(SEARCH, head, path)

    for path in sorted(SERVICE_IMMUTABLE_EXACT):
        assert_same_blob(IMMUTABLE_SERVICE, head, path)

    assert git("merge-base", "--is-ancestor", LSA_HOTFIX, head, check=False).returncode == 0
    assert git("merge-base", "--is-ancestor", SECRET_STDIN_HOTFIX, head, check=False).returncode == 0
    for path in sorted(SECRET_STDIN_HOTFIX_EXACT):
        assert_same_blob(SECRET_STDIN_HOTFIX, head, path)

    assert git("merge-base", "--is-ancestor", SERVICE_HOST_HOTFIX, head, check=False).returncode == 0
    assert git("merge-base", "--is-ancestor", LAST_GREEN_PC, SERVICE_HOST_HOTFIX, check=False).returncode == 0
    assert names(LAST_GREEN_PC, SERVICE_HOST_HOTFIX) == SERVICE_HOST_HOTFIX_EXACT
    assert git("merge-base", "--is-ancestor", SERVICE_HOST_HOTFIX, SERVICE_HOST_PATH_HOTFIX, check=False).returncode == 0
    assert git("merge-base", "--is-ancestor", SERVICE_HOST_PATH_HOTFIX, head, check=False).returncode == 0
    assert git("merge-base", "--is-ancestor", LAST_GREEN_SERVICE_HOST, SERVICE_HOST_PATH_HOTFIX, check=False).returncode == 0
    assert names(LAST_GREEN_SERVICE_HOST, SERVICE_HOST_PATH_HOTFIX) == SERVICE_HOST_HOTFIX_EXACT
    for path in sorted(SERVICE_HOST_HOTFIX_EXACT):
        assert_same_blob(SERVICE_HOST_PATH_HOTFIX, head, path)

def assert_registry_and_mapping(root: Path) -> None:
    assert TOOL_REGISTRY_DIGEST == EXPECTED_COMPAT_TOOL_REGISTRY_V1_DIGEST
    assert TOOL_REGISTRY_DIGEST == (
        "58b2bde8c6a49825747dcd7010f105dad0b6d548c7e8341cdafb32d2319f6dcd"
    )
    assert PARITY_TOOL_REGISTRY_V1 == "pc.native.parity_tool_registry.v1"
    assert PARITY_TOOL_REGISTRY_DIGEST != TOOL_REGISTRY_DIGEST

    direct_actions = {tool.executor_action for tool in PARITY_TOOL_REGISTRY_LIST}
    assert direct_actions <= set(OPS_ACTIONS)
    for tool in PARITY_TOOL_REGISTRY_LIST:
        assert (tool.effect == "side_effect") == (
            tool.executor_action in OPS_SIDE_EFFECT_ACTIONS
        )

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
        assert candidates, item["reference"]
        assert candidates <= direct_actions, (
            item["reference"],
            sorted(candidates - direct_actions),
        )

    adapter = (
        root / "src" / "pc_remote_transport" / "executor_adapter.py"
    ).read_text(encoding="utf-8")
    assert 'PARITY_TOOL_REGISTRY_V1 = "pc.native.parity_tool_registry.v1"' in adapter
    assert '"device.set_config": "config.set"' in adapter
    assert '"process.interact": "shell.session.write_stdin"' in adapter
    assert '"uia.find": "No current parity or legacy Executor action' in adapter
    assert '"CAPABILITY_UNAVAILABLE"' in adapter
    assert "UnknownDispatchOutcome" in adapter
    assert "OUTCOME_JOURNAL_REQUIRED" in adapter
    assert "github_relay" not in adapter.lower()


def assert_search_retention(root: Path) -> None:
    text = (root / "src" / "pc_executor" / "search_sessions.py").read_text(
        encoding="utf-8"
    )
    assert "terminal_observed_monotonic" in text
    assert "MIN_UNOBSERVED_TERMINAL_RETENTION_SECONDS" in text
    assert "_mark_terminal_observed_locked" in text
    tests = (root / "tests" / "test_search_sessions.py").read_text(encoding="utf-8")
    assert "test_terminal_state_is_observable_before_tiny_retention_gc" in tests
    assert "test_unobserved_terminal_state_has_bounded_hard_gc" in tests


def assert_service_artifact_security(root: Path) -> None:
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    for required in (
        '"websockets>=13,<16"',
        '"pypdf>=5,<7"',
        '"reportlab>=4,<5"',
        'pc-native-device-service = "pc_remote_transport.service_cli:main"',
    ):
        assert required in pyproject

    bootstrap = (
        root / "tools" / "install_pc_native_device_service.ps1"
    ).read_text(encoding="utf-8")
    lower = bootstrap.lower()
    assert "$reporoot" not in lower
    assert "expectedartifactsha256" in lower
    assert "expectedproducersha" in lower
    assert "expectedcapabilitydigest" in lower
    assert "$stagedartifact" in lower
    assert "verify_pc_native_service_artifact.py" in lower

    verifier = (
        root / "tools" / "verify_pc_native_service_artifact.py"
    ).read_text(encoding="utf-8")
    assert 'FORMAT_VERSION = "pc.native.device_service.artifact_manifest.v1"' in verifier
    assert 'EXPECTED_REPOSITORY = "foto6/help-pc-1"' in verifier
    assert "artifact identity changed during hashing" in verifier
    assert "protected path" in verifier

    docs = (root / "docs" / "NATIVE_DEVICE_SERVICE.md").read_text(encoding="utf-8")
    assert "pc.native.device_service.artifact_manifest.v1" in docs
    assert "There is intentionally no developer local-source fallback" in docs


def assert_ci_and_docs(root: Path) -> None:
    workflow = (root / ".github" / "workflows" / "tests.yml").read_text(
        encoding="utf-8"
    )
    for required in (
        "agent/pc-native-core-final-candidate",
        "audit_native_core_final_candidate.py",
        "test_native_full_parity_gaps.py",
        "test_search_sessions.py",
        "test_native_device_service.py",
        "test_native_service_artifact.py",
        "test_native_core_registry_policy.py",
        "test_native_stack_integration.py",
        "test_native_full_stack_integration.py",
    ):
        assert required in workflow

    final_doc = (
        root / "docs" / "CANONICAL_PC_CORE_FINAL_CANDIDATE.md"
    ).read_text(encoding="utf-8")
    assert IMMUTABLE_SERVICE in final_doc
    assert "W3-B3" in final_doc
    assert "closed" in final_doc.lower()


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    head = rev("HEAD")
    assert_source_deltas()
    assert_layered_provenance(head)
    assert_registry_and_mapping(root)
    assert_search_retention(root)
    assert_service_artifact_security(root)
    assert_ci_and_docs(root)

    changed = names(BASE, head)
    assert "tools/github_relay.py" not in changed
    assert not any(path.startswith("relay/") for path in changed)

    diff_check = git("diff", "--check", BASE, head, check=False)
    assert diff_check.returncode == 0, diff_check.stdout + diff_check.stderr

    print(
        "native PC core final candidate audit: PASS "
        f"head={head} base={BASE} search={SEARCH} service={SERVICE} "
        f"immutable_service={IMMUTABLE_SERVICE} strict_b={STRICT_B} "
        f"parity={NATIVE_TOOL_PARITY_VERSION}"
    )


if __name__ == "__main__":
    main()
