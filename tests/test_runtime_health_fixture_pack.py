from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pc_executor.runtime_health import CONTRACT_VERSION, validate_runtime_health
from pc_remote_transport.executor_adapter import (
    EXPECTED_COMPAT_TOOL_REGISTRY_V1_DIGEST,
    TOOL_REGISTRY_DIGEST,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "runtime_health_v1"


def _git_blob_sha(path: Path) -> str:
    raw = path.read_bytes()
    return hashlib.sha1(
        f"blob {len(raw)}\0".encode("ascii") + raw
    ).hexdigest()


def test_runtime_health_fixture_matches_producer_validator_and_schema_shape():
    fixture = json.loads(
        (FIXTURE_DIR / "runtime_health.example.json").read_text(encoding="utf-8")
    )
    schema = json.loads(
        (ROOT / "schemas" / "pc_executor.runtime_health.v1.schema.json")
        .read_text(encoding="utf-8")
    )

    validate_runtime_health(fixture)
    assert fixture["contract_version"] == CONTRACT_VERSION
    assert schema["$id"] == CONTRACT_VERSION
    assert set(schema["required"]) == {
        "contract_version",
        "observed_at",
        "complete",
        "probe_budget_ms",
        "elapsed_ms",
        "generation",
        "adapters",
        "outcome_journal",
        "summary",
    }
    assert set(schema["properties"]["adapters"]["required"]) == {
        "uia",
        "screenshot",
        "windows",
        "shell",
        "clipboard",
        "input",
        "outcome_journal",
        "search",
        "process",
    }


def test_r23_consumer_manifest_pins_exact_source_blobs_and_paths():
    manifest = json.loads(
        (FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["schema"] == "pc_executor.runtime_health.consumer_manifest.v1"
    assert manifest["source_base_sha"] == (
        "7eed906976d092e3216f50b0f52e6cb422392979"
    )
    assert manifest["delivery"] == {
        "native_tool": "device.health",
        "executor_action": "health.get",
        "response_field": "runtime_health",
        "registry_changes_required": False,
        "compatibility_registry_digest_must_remain": (
            "58b2bde8c6a49825747dcd7010f105dad0b6d548c7e8341cdafb32d2319f6dcd"
        ),
    }
    assert TOOL_REGISTRY_DIGEST == EXPECTED_COMPAT_TOOL_REGISTRY_V1_DIGEST
    assert TOOL_REGISTRY_DIGEST == (
        manifest["delivery"]["compatibility_registry_digest_must_remain"]
    )
    for item in manifest["source_blobs"]:
        path = ROOT / item["path"]
        assert path.is_file(), item
        assert _git_blob_sha(path) == item["git_blob_sha"], item["path"]

    required = set(manifest["required_consumer_paths"])
    assert {
        "adapters.uia.state",
        "adapters.uia.circuit.state",
        "adapters.windows.state",
        "outcome_journal.integrity",
        "generation.operations_generation_id",
    } <= required


def test_fixture_never_claims_live_cutover_or_sensitive_payloads():
    fixture_text = (FIXTURE_DIR / "runtime_health.example.json").read_text(
        encoding="utf-8"
    )
    manifest_text = (FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8")

    assert "E:\\manhwa" not in fixture_text
    assert "password" not in fixture_text.casefold()
    assert "credential" not in fixture_text.casefold()
    assert "Do not infer live cutover readiness" in manifest_text
