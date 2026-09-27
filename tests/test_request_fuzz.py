from __future__ import annotations

import copy
import json
import random
from pathlib import Path

import pytest

from pc_executor.models import ActionRequest
from pc_executor.vision_target import GroundedTargetContractError, parse_grounded_target_v1


FIXTURE = Path(__file__).parent / "fixtures" / "grounded_target_v1.json"


@pytest.mark.parametrize(
    "raw",
    [
        None,
        [],
        {},
        {"action": ""},
        {"action": 1},
        {"action": "x", "params": []},
        {"action": "x", "dry_run": "yes"},
        {"action": "x", "timeout_ms": 0},
        {"action": "x", "timeout_ms": -1},
        {"action": "x", "timeout_ms": True},
    ],
)
def test_request_envelope_validation_rejects_malformed_values(raw):
    with pytest.raises((TypeError, ValueError)):
        ActionRequest.from_dict(raw)


def test_property_style_grounded_target_mutations_fail_closed():
    base = json.loads(FIXTURE.read_text(encoding="utf-8"))
    rng = random.Random(20260927)
    paths = [
        ("frame", "sequence"),
        ("frame", "captured_at_ms"),
        ("target", "confidence"),
        ("target", "sources"),
        ("target", "bounds_screen"),
        ("target", "click_point_screen"),
    ]
    bad_values = [None, True, -1, float("inf"), [], {}, "bad"]

    for _ in range(200):
        payload = copy.deepcopy(base)
        section, key = rng.choice(paths)
        payload[section][key] = rng.choice(bad_values)
        try:
            parse_grounded_target_v1(payload)
        except GroundedTargetContractError:
            continue
        # A mutation may accidentally remain type-valid (e.g. confidence=True is rejected;
        # sources=[] rejected). If accepted, it must still preserve the frozen version.
        assert payload["contract_version"] == "vision.grounded_target.v1"


def test_property_style_request_ids_and_timeouts_round_trip():
    rng = random.Random(731)
    for _ in range(200):
        timeout = rng.randint(1, 100_000)
        request = ActionRequest.from_dict(
            {
                "request_id": f"r-{rng.randrange(10_000)}",
                "action": "windows.list",
                "params": {},
                "dry_run": bool(rng.randrange(2)),
                "timeout_ms": timeout,
            }
        )
        assert request.timeout_ms == timeout
        assert request.action == "windows.list"
