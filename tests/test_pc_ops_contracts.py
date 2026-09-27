from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from pc_executor.operations import (
    OPS_ACTIONS,
    OPS_CONTEXT_VERSION,
    OPS_PREFLIGHT_VERSION,
    OPS_SIDE_EFFECT_ACTIONS,
    validate_ops_params,
)
from pc_executor.ops_outcome import (
    EVIDENCE_VERSION,
    OpsActionOutcomeEvidence,
)


REPO = Path(__file__).resolve().parents[1]
ROOT = Path(__file__).parent / "fixtures" / "pc_ops_v1"
MANIFEST_SHA256 = "ab3be669303ec72b63f331fcde6a9a0ff66dee409d667289c67034c5e18bc1c7"


def test_manifest_bytes_and_file_hashes_are_exact() -> None:
    manifest_path = ROOT / "manifest.json"
    raw = manifest_path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == MANIFEST_SHA256
    assert (
        (ROOT / "manifest.sha256").read_text(encoding="ascii").strip()
        == f"{MANIFEST_SHA256}  manifest.json"
    )
    manifest = json.loads(raw.decode("utf-8"))

    assert manifest["contract_version"] == "pc_executor.ops_fixture_manifest.v1"
    assert manifest["consumer_repository"] == "foto6/help-pc-2"
    assert manifest["consumer_branch"] == "agent/pc-ops-gateway"
    assert manifest["action_count"] == len(OPS_ACTIONS) == 31
    assert manifest["non_meta_operation_count"] == 29

    for name, metadata in manifest["files"].items():
        path = REPO / name if name.startswith("schemas/") else ROOT / name
        payload = path.read_bytes()
        assert len(payload) == metadata["bytes"]
        assert hashlib.sha256(payload).hexdigest() == metadata["sha256"]


def test_legacy_v1_contract_blobs_remain_frozen() -> None:
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    for path, expected in manifest["frozen_legacy_v1_git_blobs"].items():
        actual = subprocess.check_output(
            ["git", "rev-parse", f"HEAD:{path}"],
            cwd=REPO,
            text=True,
        ).strip()
        assert actual == expected


def test_request_and_result_schema_action_coverage_is_exact() -> None:
    request_schema = json.loads(
        (REPO / "schemas" / "pc_executor.ops.request.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    request_actions = {
        variant["properties"]["action"]["const"]
        for variant in request_schema["oneOf"]
    }
    assert request_actions == set(OPS_ACTIONS)

    result_schema = json.loads(
        (REPO / "schemas" / "pc_executor.ops.result.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    result_actions = {
        variant["properties"]["action"]["const"]
        for variant in result_schema["oneOf"]
    }
    assert result_actions == set(OPS_ACTIONS)


def test_fixture_requests_validate_against_runtime_strict_params() -> None:
    fixture = json.loads((ROOT / "requests.json").read_text(encoding="utf-8"))
    names = set()
    for request in fixture["requests"]:
        validate_ops_params(request["action"], request["params"])
        names.add(request["action"])
    assert names == {
        action for action in OPS_ACTIONS if not action.startswith("ops.")
    }


def test_action_inventory_matches_runtime_side_effect_classification() -> None:
    fixture = json.loads(
        (ROOT / "action_inventory.json").read_text(encoding="utf-8")
    )
    entries = {entry["name"]: entry for entry in fixture["actions"]}
    assert set(entries) == set(OPS_ACTIONS)
    for action, entry in entries.items():
        assert entry["side_effecting"] is (action in OPS_SIDE_EFFECT_ACTIONS)
        assert entry["durable_outcome"] is (action in OPS_SIDE_EFFECT_ACTIONS)


def test_shell_migration_matrix_covers_every_non_meta_structured_action() -> None:
    fixture = json.loads(
        (ROOT / "shell_migration_matrix.json").read_text(encoding="utf-8")
    )
    structured = {row["structured_action"] for row in fixture["rows"]}
    assert {
        action for action in OPS_ACTIONS if not action.startswith("ops.")
    }.issubset(structured)
    git_rows = [
        row
        for row in fixture["rows"]
        if row["structured_action"] == "shell.run"
    ]
    assert len(git_rows) == 1
    assert "Git" in git_rows[0]["notes"]


def test_preflight_context_fixture_digest_is_valid() -> None:
    fixture = json.loads(
        (ROOT / "preflight_examples.json").read_text(encoding="utf-8")
    )
    ready = fixture["examples"][0]["result"]
    assert ready["contract_version"] == OPS_PREFLIGHT_VERSION
    binding = ready["context_binding"]
    assert binding["contract_version"] == OPS_CONTEXT_VERSION
    body = dict(binding)
    claimed = body.pop("context_digest")
    actual = hashlib.sha256(
        json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    assert claimed == actual


def test_outcome_examples_parse_with_exact_v1_semantics() -> None:
    fixture = json.loads(
        (ROOT / "outcome_examples.json").read_text(encoding="utf-8")
    )
    states = []
    for raw in fixture["examples"]:
        parsed = OpsActionOutcomeEvidence.from_dict(raw)
        assert parsed.contract_version == EVIDENCE_VERSION
        states.append(parsed.effect_state)
    assert states == ["completed", "unknown", "not_started"]
