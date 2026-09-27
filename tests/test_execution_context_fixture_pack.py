from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from pc_executor.context_binding import (
    CONTRACT_VERSION,
    VALIDATION_CONTRACT_VERSION,
    parse_execution_context_binding,
)


ROOT = Path(__file__).parent / "fixtures" / "execution_context_binding_v1"
SOURCE_HEAD = "5259724f7fea2a2fd539d21055ed616017437aa6"
BASE_HEAD = "d0ccb0f390474fc3fc091e51c25f7ef8771b0f09"
CONSUMER_HEAD = "f082a7e837392240788d7474123c90095891e153"


def git_blob(ref: str, path: str) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", f"{ref}:{path}"],
        text=True,
    ).strip()


@pytest.mark.parametrize(
    ("name", "kind", "action"),
    [
        ("uia.binding.json", "uia", "uia.invoke"),
        ("foreground.binding.json", "foreground", "keyboard.press"),
        ("shell.binding.json", "shell", "shell.run"),
    ],
)
def test_binding_fixtures_parse_strictly(name, kind, action):
    payload = json.loads((ROOT / name).read_text(encoding="utf-8"))
    parsed = parse_execution_context_binding(payload)
    assert parsed.contract_version == CONTRACT_VERSION
    assert parsed.context_kind == kind
    assert parsed.action == action
    assert parsed.to_dict() == payload


def test_context_mismatch_validation_fixture_is_conservative():
    payload = json.loads(
        (ROOT / "context_mismatch.validation.json").read_text(encoding="utf-8")
    )
    assert set(payload) == {
        "contract_version",
        "status",
        "reason",
        "binding_digest",
        "reexecution_safe",
        "adapter_dispatch_started",
        "mismatches",
    }
    assert payload["contract_version"] == VALIDATION_CONTRACT_VERSION
    assert payload["status"] == "blocked"
    assert payload["reason"] == "context_mismatch"
    assert payload["reexecution_safe"] is True
    assert payload["adapter_dispatch_started"] is False
    assert payload["mismatches"] == ["process.start_epoch_ms"]


def test_fixture_manifest_bytes_hashes_and_source_provenance_are_exact():
    manifest_path = ROOT / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert (
        (ROOT / "manifest.sha256").read_text(encoding="ascii").strip()
        == f"{digest}  manifest.json"
    )
    assert digest == "4d24dee1172354a68a93129ea6adce15603bd8f76ff30fadb587c5aa509938a0"
    assert manifest["contract_version"] == (
        "pc_executor.execution_context_binding.fixture_manifest.v1"
    )
    assert manifest["binding_contract_version"] == CONTRACT_VERSION
    assert manifest["validation_contract_version"] == VALIDATION_CONTRACT_VERSION
    assert manifest["producer_repository"] == "foto6/help-pc-1"
    assert manifest["producer_branch"] == "agent/pc-executor"
    assert manifest["producer_base_head"] == BASE_HEAD
    assert manifest["producer_source_head"] == SOURCE_HEAD
    assert manifest["consumer_repository"] == "foto6/help-pc-2"
    assert manifest["consumer_branch"] == "agent/pc-control-plane"
    assert manifest["consumer_compatibility_head"] == CONSUMER_HEAD

    for name, metadata in manifest["files"].items():
        raw = (ROOT / name).read_bytes()
        assert len(raw) == metadata["bytes"]
        assert hashlib.sha256(raw).hexdigest() == metadata["sha256"]

    source = manifest["source_provenance"]
    assert source["commit_sha"] == SOURCE_HEAD
    assert source["hash_algorithm"] == "git-blob-sha1"
    for path, expected_blob in source["files"].items():
        assert git_blob(SOURCE_HEAD, path) == expected_blob


def test_frozen_contract_blobs_and_fixture_hashes_are_unchanged():
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    frozen = manifest["frozen_contract_provenance"]
    module_blobs = {
        "src/pc_executor/capabilities.py": frozen["capabilities_py_git_blob_sha1"],
        "src/pc_executor/preflight.py": frozen["preflight_py_git_blob_sha1"],
        "src/pc_executor/outcome.py": frozen["outcome_py_git_blob_sha1"],
        "src/pc_executor/outcome_journal.py": frozen[
            "outcome_journal_py_git_blob_sha1"
        ],
    }
    for path, expected_blob in module_blobs.items():
        assert git_blob(BASE_HEAD, path) == expected_blob
        assert git_blob(SOURCE_HEAD, path) == expected_blob
        assert git_blob("HEAD", path) == expected_blob

    fixture_root = Path(__file__).parent / "fixtures"
    for name, expected in frozen["action_outcome_fixture_sha256"].items():
        assert hashlib.sha256((fixture_root / name).read_bytes()).hexdigest() == expected

    assert (
        hashlib.sha256(
            (fixture_root / "preflight_v1" / "manifest.json").read_bytes()
        ).hexdigest()
        == frozen["preflight_manifest_sha256"]
    )
    assert (
        hashlib.sha256(
            (fixture_root / "outcome_journal_v1" / "manifest.json").read_bytes()
        ).hexdigest()
        == frozen["outcome_journal_manifest_sha256"]
    )
