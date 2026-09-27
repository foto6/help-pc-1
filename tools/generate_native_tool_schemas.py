from __future__ import annotations

import json
from pathlib import Path

from pc_executor.operations import (
    NATIVE_CAPABILITIES_VERSION,
    NATIVE_REQUEST_VERSION,
    NATIVE_RESULT_VERSION,
    NATIVE_TOOL_PARITY_VERSION,
    OPS_ACTIONS,
    OPS_CAPABILITIES_VERSION,
    OPS_CONTRACT_VERSION,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "schemas"
DRAFT = "https://json-schema.org/draft/2020-12/schema"


def _action_property() -> dict:
    return {"type": "string", "enum": sorted(OPS_ACTIONS)}


def request_schema() -> dict:
    return {
        "$schema": DRAFT,
        "$id": NATIVE_REQUEST_VERSION,
        "title": "PC Executor Native Tool Request v1",
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "action": _action_property(),
            "params": {"type": "object"},
            "request_id": {"type": "string", "minLength": 1},
            "dry_run": {"type": ["boolean", "null"]},
            "timeout_ms": {
                "type": ["integer", "null"],
                "minimum": 1,
            },
            "execution_context_binding": {
                "type": ["object", "null"],
            },
        },
        "required": ["action"],
    }


def result_schema() -> dict:
    return {
        "$schema": DRAFT,
        "$id": NATIVE_RESULT_VERSION,
        "title": "PC Executor Native Tool Result v1",
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "request_id": {"type": "string"},
            "action": _action_property(),
            "ok": {"type": "boolean"},
            "status": {"type": "string"},
            "started_at": {"type": "string"},
            "finished_at": {"type": "string"},
            "data": {"type": "object"},
            "error": {"type": ["string", "null"]},
            "error_kind": {"type": ["string", "null"]},
            "dry_run": {"type": "boolean"},
            "outcome_evidence": {
                "type": "object",
                "additionalProperties": True,
            },
        },
        "required": [
            "request_id",
            "action",
            "ok",
            "status",
            "started_at",
            "finished_at",
            "data",
            "error",
            "error_kind",
            "dry_run",
        ],
    }


def capabilities_schema() -> dict:
    return {
        "$schema": DRAFT,
        "$id": NATIVE_CAPABILITIES_VERSION,
        "title": "PC Executor Native Tool Capabilities v1",
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "contract_version": {"const": OPS_CAPABILITIES_VERSION},
            "operations_contract_version": {"const": OPS_CONTRACT_VERSION},
            "native_tool_parity_version": {
                "const": NATIVE_TOOL_PARITY_VERSION,
            },
            "schema_versions": {
                "type": "object",
                "additionalProperties": {"type": "string"},
            },
            "actions": {
                "type": "object",
                "propertyNames": _action_property(),
                "additionalProperties": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "side_effecting": {"type": "boolean"},
                        "supported": {"const": True},
                        "tool_contract_version": {
                            "const": NATIVE_TOOL_PARITY_VERSION,
                        },
                    },
                    "required": [
                        "side_effecting",
                        "supported",
                        "tool_contract_version",
                    ],
                },
            },
            "safety": {"type": "object"},
            "attestation": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "algorithm": {"const": "sha256"},
                    "digest": {
                        "type": "string",
                        "pattern": "^[0-9a-f]{64}$",
                    },
                },
                "required": ["algorithm", "digest"],
            },
        },
        "required": [
            "contract_version",
            "operations_contract_version",
            "native_tool_parity_version",
            "schema_versions",
            "actions",
            "safety",
            "attestation",
        ],
    }


def write_schema(filename: str, payload: dict) -> None:
    path = SCHEMA_ROOT / filename
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> None:
    SCHEMA_ROOT.mkdir(parents=True, exist_ok=True)
    write_schema(
        "pc_executor.native_tool_request.v1.schema.json",
        request_schema(),
    )
    write_schema(
        "pc_executor.native_tool_result.v1.schema.json",
        result_schema(),
    )
    write_schema(
        "pc_executor.native_tool_capabilities.v1.schema.json",
        capabilities_schema(),
    )


if __name__ == "__main__":
    main()
