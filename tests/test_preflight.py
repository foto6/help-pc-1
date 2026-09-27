from __future__ import annotations

import copy
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

import pytest

from pc_executor.capabilities import (
    CONTRACT_VERSION as CAPABILITIES_VERSION,
    SUPPORTED_ACTIONS,
    validate_capabilities,
)
from pc_executor.errors import AmbiguousTargetError, StaleTargetError
from pc_executor.executor import Executor
from pc_executor.models import (
    ElementInfo,
    Rect,
    UIObservationSnapshot,
    UINodeSnapshot,
)
from pc_executor.preflight import (
    CONTRACT_VERSION as PREFLIGHT_VERSION,
    PreflightRequest,
    PreflightResult,
    PreflightValidationError,
)
from pc_executor.safety import ensure_argv_allowed, ensure_path_allowed


VISION_FIXTURE = (
    Path(__file__).parent / "fixtures" / "grounded_target_v1.json"
)


def preflight_payload(
    action: str,
    params: dict | None = None,
    *,
    request_id: str = "pf-1",
    timeout_ms: int | None = 1000,
    dry_run: bool | None = None,
) -> dict:
    return {
        "contract_version": PREFLIGHT_VERSION,
        "request": {
            "request_id": request_id,
            "action": action,
            "params": dict(params or {}),
            "dry_run": dry_run,
            "timeout_ms": timeout_ms,
        },
    }


def actionable(
    *,
    automation_id: str = "save",
    enabled: bool = True,
    offscreen: bool = False,
    password: bool = False,
    invoke: bool = True,
    value: bool = True,
) -> ElementInfo:
    return ElementInfo(
        name="Save",
        automation_id=automation_id,
        control_type="ButtonControl",
        is_enabled=enabled,
        is_password=password,
        native_handle=10,
        bounds=Rect(1, 2, 3, 4),
        display_id="test-display",
        window_handle=11,
        process_id=12,
        class_name="Button",
        is_offscreen=offscreen,
        supports_invoke=invoke,
        supports_value=value,
    )


def snapshot() -> UIObservationSnapshot:
    return UIObservationSnapshot.create(
        app={"process_id": 12},
        window={"title": "App", "handle": 11, "process_id": 12},
        displays=(),
        nodes=(
            UINodeSnapshot(
                node_id="node-save",
                role="ButtonControl",
                name="Save",
                automation_id="save",
                class_name="Button",
                is_enabled=True,
                is_offscreen=False,
                bounds=Rect(1, 2, 3, 4),
                display_id="test-display",
                window_handle=11,
                process_id=12,
                supports_invoke=True,
                supports_value=True,
            ),
        ),
        captured_at="2026-09-27T10:00:00.000Z",
    )


class GuardedScreenshot:
    def __init__(self):
        self.calls = 0

    def capture_png(self):
        self.calls += 1
        raise AssertionError("preflight must not capture screenshots")


class GuardedWindows:
    def __init__(self):
        self.calls = 0

    def list_windows(self):
        self.calls += 1
        raise AssertionError("preflight must not enumerate windows")


class GuardedInput:
    def __init__(self):
        self.calls = []

    def click(self, *args, **kwargs):
        self.calls.append("click")
        raise AssertionError("preflight must not click")

    def press(self, *args, **kwargs):
        self.calls.append("press")
        raise AssertionError("preflight must not press keys")

    def type_text(self, *args, **kwargs):
        self.calls.append("type_text")
        raise AssertionError("preflight must not type")

    def clipboard_get(self):
        self.calls.append("clipboard_get")
        raise AssertionError("preflight must not read clipboard")

    def clipboard_set(self, *args, **kwargs):
        self.calls.append("clipboard_set")
        raise AssertionError("preflight must not write clipboard")

class GuardedShell:
    def __init__(self, allow_executables=None, output_limit_bytes=4096):
        self.allow_executables = set(allow_executables or {"git", "python", "python.exe"})
        self.output_limit_bytes = output_limit_bytes
        self.validate_calls = []
        self.run_calls = []

    def validate(self, argv, *, cwd=None):
        args = ensure_argv_allowed(argv, self.allow_executables)
        ensure_path_allowed(cwd)
        self.validate_calls.append((list(args), cwd))
        return args

    def run(self, *args, **kwargs):
        self.run_calls.append((args, kwargs))
        raise AssertionError("preflight must not start a process")


class GuardedUIA:
    def __init__(self, *, element=None, inspect_error=None, snapshot_error=None):
        self.element = element or actionable()
        self.inspect_error = inspect_error
        self.snapshot_error = snapshot_error
        self.read_calls = []
        self.side_effect_calls = []

    def inspect(self, query):
        self.read_calls.append(("inspect", query.automation_id))
        if self.inspect_error is not None:
            raise self.inspect_error
        return self.element

    def snapshot(self, *, window_title=None):
        self.read_calls.append(("snapshot", window_title))
        if self.snapshot_error is not None:
            raise self.snapshot_error
        return snapshot()

    def invoke(self, *args, **kwargs):
        self.side_effect_calls.append("invoke")
        raise AssertionError("preflight must never invoke")

    def focus(self, *args, **kwargs):
        self.side_effect_calls.append("focus")
        raise AssertionError("preflight must never focus")

    def set_value(self, *args, **kwargs):
        self.side_effect_calls.append("set_value")
        raise AssertionError("preflight must never set UIA values")


def guarded_executor(
    *,
    uia=None,
    coordinate=False,
    dry_run=True,
    shell=None,
):
    screenshot_adapter = GuardedScreenshot()
    windows_adapter = GuardedWindows()
    input_adapter = GuardedInput()
    shell_adapter = shell or GuardedShell()
    uia_adapter = uia or GuardedUIA()
    executor = Executor(
        screenshot=screenshot_adapter,
        windows=windows_adapter,
        accessibility=uia_adapter,
        input_adapter=input_adapter,
        shell=shell_adapter,
        dry_run=dry_run,
        allow_coordinate_fallback=coordinate,
        operation_timeout_seconds=3.5,
    )
    return (
        executor,
        screenshot_adapter,
        windows_adapter,
        uia_adapter,
        input_adapter,
        shell_adapter,
    )


def assert_no_side_effects(parts):
    _, screenshot_adapter, windows_adapter, uia, raw_input, shell = parts
    assert screenshot_adapter.calls == 0
    assert windows_adapter.calls == 0
    assert uia.side_effect_calls == []
    assert raw_input.calls == []
    assert shell.run_calls == []


def test_capabilities_snapshot_is_strict_deterministic_and_attested():
    first = guarded_executor()
    second = guarded_executor()

    one = first[0].capabilities_snapshot()
    two = first[0].capabilities_snapshot()
    restarted = second[0].capabilities_snapshot()

    validate_capabilities(one)
    assert one == two == restarted
    assert one["contract_version"] == CAPABILITIES_VERSION
    assert one["attestation"]["digest"] == two["attestation"]["digest"]
    assert tuple(sorted(one["actions"])) == SUPPORTED_ACTIONS
    assert one["safety"]["credential_entry_allowed"] is False
    assert one["safety"]["captcha_entry_allowed"] is False
    assert one["safety"]["coordinate_fallback_enabled"] is False
    assert one["safety"]["dry_run_default"] is True
    assert one["safety"]["protected_windows_roots"] == [r"E:\manhwa"]
    assert one["safety"]["shell_output_limit_bytes"] == 4096
    assert set(one["runtime"]) == {
        "executor_version",
        "python_implementation",
        "python_major_minor",
        "platform_system",
        "platform_machine",
        "os_family",
    }
    assert_no_side_effects(first)
    assert_no_side_effects(second)


def test_capability_attestation_changes_with_safety_configuration():
    default = guarded_executor(coordinate=False)[0].capabilities_snapshot()
    coordinates = guarded_executor(coordinate=True)[0].capabilities_snapshot()
    live_default = guarded_executor(dry_run=False)[0].capabilities_snapshot()

    assert default["attestation"]["digest"] != coordinates["attestation"]["digest"]
    assert default["attestation"]["digest"] != live_default["attestation"]["digest"]


def test_native_capability_portability_reports_platform_limits_explicitly():
    caps = Executor().capabilities_snapshot()
    validate_capabilities(caps)
    if os.name == "nt":
        assert caps["runtime"]["platform_system"] == "Windows"
        for name in ("uia", "screenshot", "input", "clipboard", "windows"):
            assert caps["adapters"][name]["provider"] == "native"
    else:
        for name in ("uia", "screenshot", "input", "clipboard", "windows"):
            assert caps["adapters"][name]["available"] is False
            assert caps["adapters"][name]["unsupported_reason"] == "platform_not_windows"
    assert caps["adapters"]["shell"]["available"] is True


def test_capabilities_contain_no_machine_identity_fields():
    caps = guarded_executor()[0].capabilities_snapshot()
    serialized = json.dumps(caps, sort_keys=True)
    lowered = serialized.lower()
    for forbidden in ("hostname", "username", "user_name", "home_directory", "mac_address"):
        assert forbidden not in lowered
    node = platform.node()
    if node:
        assert node not in serialized

@pytest.mark.parametrize(
    ("action", "params"),
    [
        ("capabilities.get", {}),
        ("outcome.lookup", {"request_id": "other", "action": "keyboard.press"}),
        ("screenshot.capture", {}),
        ("windows.list", {}),
        ("uia.snapshot", {"window_title": "App"}),
        ("uia.inspect", {"query": {"automation_id": "save"}}),
        ("uia.invoke", {"query": {"automation_id": "save"}}),
        ("uia.focus", {"query": {"automation_id": "save"}}),
        (
            "uia.set_value",
            {"query": {"automation_id": "save"}, "value": "non-secret"},
        ),
        ("mouse.click", {"x": 10, "y": 20, "button": "left"}),
        ("keyboard.press", {"key": "enter"}),
        ("keyboard.type_text", {"text": "ordinary text"}),
        ("clipboard.get", {}),
        ("clipboard.set", {"text": "ordinary text"}),
        ("shell.run", {"argv": ["git", "status"], "cwd": None}),
    ],
)
def test_preflight_ready_paths_never_call_side_effect_adapters(action, params):
    parts = guarded_executor(coordinate=True)
    result = parts[0].preflight(preflight_payload(action, params))

    assert result.status == "ready"
    assert result.executable is True
    assert result.reasons[0]["code"] == "ready"
    assert len(result.capabilities_digest) == 64
    assert result.deadline_budget_ms == 1000
    assert_no_side_effects(parts)


def test_vision_target_preflight_resolves_through_read_only_uia_only():
    target = json.loads(VISION_FIXTURE.read_text(encoding="utf-8"))
    parts = guarded_executor()
    result = parts[0].preflight(
        preflight_payload("vision.target.invoke", {"target": target})
    )

    assert result.status == "ready"
    assert result.target == {
        "resolved": True,
        "automation_id_present": True,
        "enabled": True,
        "offscreen": False,
        "password": False,
        "supports_invoke": True,
        "supports_value": True,
    }
    assert parts[3].read_calls == [("inspect", "save")]
    assert_no_side_effects(parts)


def test_action_preflight_can_preflight_its_own_versioned_transport():
    nested = preflight_payload("keyboard.press", {"key": "enter"})
    parts = guarded_executor()
    result = parts[0].preflight(
        preflight_payload("action.preflight", nested)
    )
    assert result.status == "ready"
    assert_no_side_effects(parts)


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (StaleTargetError("gone"), "stale_observation"),
        (AmbiguousTargetError("many"), "ambiguous_target"),
    ],
)
def test_uia_read_only_resolution_maps_stale_and_ambiguous(error, status):
    parts = guarded_executor(uia=GuardedUIA(inspect_error=error))
    result = parts[0].preflight(
        preflight_payload("uia.invoke", {"query": {"automation_id": "save"}})
    )
    assert result.status == status
    assert result.executable is False
    assert_no_side_effects(parts)


def test_uia_snapshot_window_staleness_is_read_only():
    parts = guarded_executor(
        uia=GuardedUIA(snapshot_error=StaleTargetError("window gone"))
    )
    result = parts[0].preflight(
        preflight_payload("uia.snapshot", {"window_title": "Gone"})
    )
    assert result.status == "stale_observation"
    assert parts[3].read_calls == [("snapshot", "Gone")]
    assert_no_side_effects(parts)


@pytest.mark.parametrize(
    ("element", "action", "params", "code"),
    [
        (
            actionable(enabled=False),
            "uia.invoke",
            {"query": {"automation_id": "save"}},
            "uia_target_not_actionable",
        ),
        (
            actionable(offscreen=True),
            "uia.focus",
            {"query": {"automation_id": "save"}},
            "uia_target_not_actionable",
        ),
        (
            actionable(invoke=False),
            "uia.invoke",
            {"query": {"automation_id": "save"}},
            "uia_invoke_unsupported",
        ),
        (
            actionable(value=False),
            "uia.set_value",
            {"query": {"automation_id": "save"}, "value": "x"},
            "uia_value_unsupported",
        ),
        (
            actionable(password=True),
            "uia.set_value",
            {"query": {"automation_id": "save"}, "value": "x"},
            "sensitive_entry_blocked",
        ),
    ],
)
def test_uia_actionability_is_checked_without_action(element, action, params, code):
    parts = guarded_executor(uia=GuardedUIA(element=element))
    result = parts[0].preflight(preflight_payload(action, params))
    assert result.status == "blocked"
    assert result.reasons[0]["code"] == code
    assert_no_side_effects(parts)

@pytest.mark.parametrize(
    ("action", "params"),
    [
        ("keyboard.type_text", {"text": "secret", "sensitive": True}),
        ("clipboard.set", {"text": "secret", "sensitive": True}),
        (
            "uia.set_value",
            {
                "query": {"automation_id": "save"},
                "value": "secret",
                "sensitive": True,
            },
        ),
    ],
)
def test_sensitive_entry_is_blocked_before_any_side_effect(action, params):
    parts = guarded_executor()
    result = parts[0].preflight(preflight_payload(action, params))
    assert result.status == "blocked"
    assert result.reasons[0]["code"] == "sensitive_entry_blocked"
    assert "secret" not in json.dumps(result.to_dict())
    assert_no_side_effects(parts)


def test_coordinate_authority_gate_blocks_without_clicking():
    parts = guarded_executor(coordinate=False)
    result = parts[0].preflight(
        preflight_payload("mouse.click", {"x": 100, "y": 200})
    )
    assert result.status == "blocked"
    assert result.reasons[0]["code"] == "coordinate_fallback_disabled"
    assert_no_side_effects(parts)


@pytest.mark.parametrize(
    "params",
    [
        {"argv": ["format.com", "C:"]},
        {"argv": ["git", "status"], "cwd": r"E:\manhwa"},
        {"argv": ["git", r"E:\manhwa\chapter"]},
    ],
)
def test_shell_preflight_preserves_allowlist_and_protected_path_policy(params):
    parts = guarded_executor()
    result = parts[0].preflight(preflight_payload("shell.run", params))
    assert result.status == "blocked"
    assert result.reasons[0]["code"] == "shell_policy_blocked"
    assert parts[5].run_calls == []
    assert_no_side_effects(parts)


def test_shell_ready_preflight_only_runs_validate_not_process():
    parts = guarded_executor()
    result = parts[0].preflight(
        preflight_payload("shell.run", {"argv": ["git", "status"]})
    )
    assert result.status == "ready"
    assert parts[5].validate_calls == [(["git", "status"], None)]
    assert parts[5].run_calls == []
    assert_no_side_effects(parts)


def test_unknown_action_is_explicitly_unsupported():
    parts = guarded_executor()
    result = parts[0].preflight(preflight_payload("future.action", {}))
    assert result.status == "unsupported"
    assert result.reasons[0]["code"] == "unsupported_action"
    assert_no_side_effects(parts)


def test_missing_uia_adapter_is_explicitly_unsupported_without_method_calls():
    parts = guarded_executor()
    parts[0].accessibility = object()
    result = parts[0].preflight(
        preflight_payload("uia.invoke", {"query": {"automation_id": "save"}})
    )
    assert result.status == "unsupported"
    assert result.reasons[0]["code"] == "adapter_unavailable"
    assert_no_side_effects(parts)


@pytest.mark.parametrize(
    "payload",
    [
        None,
        {},
        {"contract_version": "pc_executor.action_preflight.v2", "request": {}},
        {
            "contract_version": PREFLIGHT_VERSION,
            "request": {
                "request_id": "r",
                "action": "keyboard.press",
                "params": [],
            },
        },
        {
            "contract_version": PREFLIGHT_VERSION,
            "request": {
                "request_id": "r",
                "action": "keyboard.press",
                "params": {"key": "enter"},
                "timeout_ms": 0,
            },
        },
        {
            "contract_version": PREFLIGHT_VERSION,
            "request": {
                "request_id": "r",
                "action": "keyboard.press",
                "params": {"key": "enter"},
                "extra": True,
            },
        },
    ],
)
def test_malformed_contracts_return_invalid_request_without_side_effects(payload):
    parts = guarded_executor()
    result = parts[0].preflight(payload)
    assert result.status == "invalid_request"
    assert result.executable is False
    assert_no_side_effects(parts)

@pytest.mark.parametrize(
    ("action", "params"),
    [
        ("keyboard.press", {"key": ""}),
        ("keyboard.press", {"key": "x", "unexpected": True}),
        ("mouse.click", {"x": True, "y": 2}),
        ("mouse.click", {"x": 1, "y": 2, "button": "weapon"}),
        ("shell.run", {"argv": [{"not": "a string"}]}),
        ("clipboard.set", {"text": {"nested": "hostile"}}),
        ("uia.invoke", {"query": {"automation_id": "save", "raw_handle": 123}}),
    ],
)
def test_hostile_action_shapes_are_invalid_and_side_effect_free(action, params):
    parts = guarded_executor(coordinate=True)
    result = parts[0].preflight(preflight_payload(action, params))
    assert result.status == "invalid_request"
    assert_no_side_effects(parts)


def test_deadline_budget_is_bound_to_validated_request_without_execution():
    parts = guarded_executor()
    result = parts[0].preflight(
        preflight_payload("keyboard.press", {"key": "enter"}, timeout_ms=7)
    )
    assert result.status == "ready"
    assert result.deadline_budget_ms == 7
    assert_no_side_effects(parts)


def test_preflight_request_and_result_contracts_are_strict():
    request_payload = preflight_payload("keyboard.press", {"key": "enter"})
    parsed = PreflightRequest.from_dict(request_payload)
    assert parsed.to_dict() == request_payload

    result = guarded_executor()[0].preflight(request_payload)
    round_trip = PreflightResult.from_dict(result.to_dict())
    assert round_trip.to_dict() == result.to_dict()

    bad_request = copy.deepcopy(request_payload)
    bad_request["extra"] = True
    with pytest.raises(PreflightValidationError):
        PreflightRequest.from_dict(bad_request)

    bad_result = result.to_dict()
    bad_result["executable"] = False
    with pytest.raises(PreflightValidationError):
        PreflightResult.from_dict(bad_result)


def test_preflight_result_never_contains_sensitive_request_bodies():
    parts = guarded_executor()
    secret = "DO-NOT-LEAK-THIS-SECRET"
    result = parts[0].preflight(
        preflight_payload(
            "keyboard.type_text",
            {"text": secret, "sensitive": True},
        )
    )
    assert secret not in json.dumps(result.to_dict(), sort_keys=True)
    assert_no_side_effects(parts)


def test_jsonl_capabilities_and_preflight_transport_are_read_only():
    capabilities_request = {
        "request_id": "caps-transport",
        "action": "capabilities.get",
        "params": {},
    }
    preflight_request = {
        "request_id": "preflight-transport",
        "action": "action.preflight",
        "params": preflight_payload(
            "shell.run",
            {"argv": ["git", "status"]},
            request_id="logical-shell",
        ),
    }
    completed = subprocess.run(
        [sys.executable, "-m", "pc_executor"],
        input=(
            json.dumps(capabilities_request)
            + "\n"
            + json.dumps(preflight_request)
            + "\n"
        ),
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0
    lines = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
    assert len(lines) == 2
    validate_capabilities(lines[0]["data"]["capabilities"])
    result = PreflightResult.from_dict(lines[1]["data"]["preflight"])
    assert result.status == "ready"
    assert result.action == "shell.run"


def test_preflight_does_not_change_executor_dry_run_default():
    parts = guarded_executor(dry_run=True)
    before = parts[0].dry_run
    parts[0].preflight(preflight_payload("keyboard.press", {"key": "enter"}))
    assert parts[0].dry_run is before is True
    assert_no_side_effects(parts)


def test_capabilities_validator_rejects_tampering_and_shape_drift():
    payload = guarded_executor()[0].capabilities_snapshot()
    bad = copy.deepcopy(payload)
    bad["runtime"]["hostname"] = "should-not-exist"
    with pytest.raises(ValueError):
        validate_capabilities(bad)

    bad = copy.deepcopy(payload)
    bad["attestation"]["digest"] = "0" * 64
    with pytest.raises(ValueError):
        validate_capabilities(bad)


def test_cross_repo_preflight_fixture_pack_and_manifest_are_exact():
    root = Path(__file__).parent / "fixtures" / "preflight_v1"
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    sidecar = (root / "manifest.sha256").read_text(encoding="ascii").strip()
    manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()

    assert sidecar == f"{manifest_hash}  manifest.json"
    assert manifest["contract_version"] == "pc_executor.preflight_fixture_manifest.v1"
    assert manifest["capabilities_contract_version"] == CAPABILITIES_VERSION
    assert manifest["preflight_contract_version"] == PREFLIGHT_VERSION
    assert manifest["producer_repository"] == "foto6/help-pc-1"
    assert manifest["producer_branch"] == "agent/pc-executor"
    assert manifest["producer_base_head"] == "06217fe4246d0191ac3c93e69aac855bdd6e4136"
    assert len(manifest["producer_source_head"]) == 40
    int(manifest["producer_source_head"], 16)
    assert manifest["consumer_repository"] == "foto6/help-pc-2"
    assert manifest["consumer_branch"] == "agent/pc-control-plane"
    assert (
        manifest["consumer_compatibility_head"]
        == "ead172d3a54eeb861599ec5b0bbf4fd4a51bdfdc"
    )

    for name, metadata in manifest["files"].items():
        raw = (root / name).read_bytes()
        assert len(raw) == metadata["bytes"]
        assert hashlib.sha256(raw).hexdigest() == metadata["sha256"]

    repo_root = Path(__file__).parents[1]
    for name, expected_hash in manifest["source_provenance"]["files"].items():
        assert hashlib.sha256((repo_root / name).read_bytes()).hexdigest() == expected_hash

    frozen = manifest["frozen_action_outcome_fixture_sha256"]
    assert frozen == {
        "action_outcome_v1_not_started.json": "06278df0fd016093d67420f9e33b0504d7f72bc5da8ecbece063c649d9d2c913",
        "action_outcome_v1.json": "e73488314215a43768710247ee199aa878442d93f20025e35da567bb20757f10",
        "action_outcome_v1_unknown.json": "c4585b7b2ccd0788ee4d22be2dfee8f43c28e2f46555bbe731157b272d321951",
    }
    fixtures = Path(__file__).parent / "fixtures"
    for name, expected_hash in frozen.items():
        assert hashlib.sha256((fixtures / name).read_bytes()).hexdigest() == expected_hash

    journal_manifest = fixtures / "outcome_journal_v1" / "manifest.json"
    assert (
        hashlib.sha256(journal_manifest.read_bytes()).hexdigest()
        == manifest["outcome_journal_manifest_sha256"]
    )


@pytest.mark.parametrize(
    ("name", "status"),
    [
        ("ready.result.json", "ready"),
        ("blocked.result.json", "blocked"),
        ("unsupported.result.json", "unsupported"),
        ("stale_observation.result.json", "stale_observation"),
        ("ambiguous_target.result.json", "ambiguous_target"),
        ("invalid_request.result.json", "invalid_request"),
    ],
)
def test_transport_preflight_result_fixtures_parse_strictly(name, status):
    root = Path(__file__).parent / "fixtures" / "preflight_v1"
    payload = json.loads((root / name).read_text(encoding="utf-8"))
    result = PreflightResult.from_dict(payload)
    assert result.status == status
    assert result.executable is (status == "ready")


def test_transport_capabilities_and_request_fixtures_parse_strictly():
    root = Path(__file__).parent / "fixtures" / "preflight_v1"
    capabilities = json.loads((root / "capabilities.json").read_text(encoding="utf-8"))
    request = json.loads((root / "ready.request.json").read_text(encoding="utf-8"))

    validate_capabilities(capabilities)
    parsed = PreflightRequest.from_dict(request)
    assert parsed.action == "keyboard.press"
    assert parsed.request_id == "fixture-ready"
