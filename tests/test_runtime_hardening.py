from __future__ import annotations

import io
import os
import sys
import time
from pathlib import Path

import pytest
from PIL import Image

from pc_executor.cancellation import CancellationToken
from pc_executor.capture import screenshot_payload
from pc_executor.errors import OperationCancelledError, OperationTimeoutError
from pc_executor.executor import Executor
from pc_executor.models import (
    ActionRequest,
    DisplayGeometry,
    Rect,
    UIObservationSnapshot,
    UINodeSnapshot,
)
from pc_executor.shell import SafeShellAdapter


def png_bytes(width: int = 7, height: int = 5) -> bytes:
    image = Image.new("RGB", (width, height))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def test_screenshot_metadata_is_correlatable_and_digest_stable():
    raw = png_bytes()
    displays = [DisplayGeometry("display:primary", Rect(-100, 0, 1920, 1080), True)]

    first = screenshot_payload(raw, displays=displays)
    second = screenshot_payload(raw, displays=displays)

    assert first["capture_id"] == second["capture_id"]
    assert first["sha256"] == second["sha256"]
    assert first["width"] == 7
    assert first["height"] == 5
    assert first["coordinate_space"] == "physical_screen_px"
    assert first["display_geometry"][0]["bounds"]["x"] == -100


def test_snapshot_transport_is_canonical_with_stable_id_for_fixed_time():
    nodes = [
        UINodeSnapshot(
            node_id="b",
            role="ButtonControl",
            name="B",
            automation_id="b",
            class_name=None,
            is_enabled=True,
            is_offscreen=False,
            bounds=Rect(10, 10, 20, 20),
            display_id="d1",
            window_handle=2,
            process_id=3,
            supports_invoke=True,
            supports_value=False,
        ),
        UINodeSnapshot(
            node_id="a",
            role="EditControl",
            name="A",
            automation_id="a",
            class_name="Edit",
            is_enabled=True,
            is_offscreen=False,
            bounds=Rect(-5, 0, 10, 20),
            display_id="d0",
            window_handle=2,
            process_id=3,
            supports_invoke=False,
            supports_value=True,
        ),
    ]
    kwargs = dict(
        app={"name": "Demo", "process_id": 3},
        window={"title": "Demo", "handle": 2, "process_id": 3},
        displays=[
            DisplayGeometry("d1", Rect(0, 0, 100, 100)),
            DisplayGeometry("d0", Rect(-100, 0, 100, 100), True),
        ],
        nodes=nodes,
        captured_at="2026-09-27T07:00:00.000Z",
    )

    first = UIObservationSnapshot.create(**kwargs)
    second = UIObservationSnapshot.create(**kwargs)

    assert first.snapshot_id == second.snapshot_id
    assert first.to_json() == second.to_json()
    assert [node.node_id for node in first.nodes] == ["a", "b"]
    assert [display.display_id for display in first.displays] == ["d0", "d1"]
    assert first.to_dict()["coordinate_space"] == "physical_screen_px"


def test_shell_output_is_bounded_with_explicit_truncation_metadata():
    exe = Path(sys.executable).name
    shell = SafeShellAdapter(allow_executables={exe}, output_limit_bytes=64)
    result = shell.run(
        [sys.executable, "-c", "import sys;sys.stdout.write('x'*200);sys.stderr.write('y'*90)"],
        timeout_seconds=5,
    )

    assert len(result.stdout.encode("utf-8")) == 64
    assert len(result.stderr.encode("utf-8")) == 64
    assert result.stdout_bytes == 200
    assert result.stderr_bytes == 90
    assert result.stdout_truncated is True
    assert result.stderr_truncated is True
    assert result.output_limit_bytes == 64


def test_shell_timeout_terminates_and_classifies():
    exe = Path(sys.executable).name
    shell = SafeShellAdapter(allow_executables={exe})
    with pytest.raises(OperationTimeoutError):
        shell.run(
            [sys.executable, "-c", "import time; time.sleep(1)"],
            timeout_seconds=0.03,
        )


def test_shell_pre_cancel_has_no_process_side_effect():
    exe = Path(sys.executable).name
    shell = SafeShellAdapter(allow_executables={exe})
    token = CancellationToken()
    token.cancel()

    with pytest.raises(OperationCancelledError):
        shell.run([sys.executable, "-c", "print('never')"], cancellation=token)


class SlowInput:
    def click(self, x, y, *, button="left"):
        time.sleep(0.2)

    def press(self, key):
        time.sleep(0.2)

    def type_text(self, text):
        time.sleep(0.2)

    def clipboard_get(self):
        time.sleep(0.2)
        return ""

    def clipboard_set(self, text):
        time.sleep(0.2)


def test_input_timeout_is_structured():
    executor = Executor(input_adapter=SlowInput(), dry_run=False)
    result = executor.execute(
        ActionRequest("keyboard.press", {"key": "enter"}, timeout_ms=20)
    )
    assert result.status == "timeout"
    assert result.error_kind == "timeout"


def test_precancelled_request_is_structured_cancelled():
    token = CancellationToken()
    token.cancel()
    executor = Executor(dry_run=False)

    result = executor.execute(
        ActionRequest("keyboard.press", {"key": "enter"}),
        cancellation=token,
    )

    assert result.status == "cancelled"
    assert result.error_kind == "cancelled"
