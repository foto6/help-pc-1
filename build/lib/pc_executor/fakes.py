from __future__ import annotations

from dataclasses import replace
from typing import Iterable, Sequence

from .cancellation import CancellationToken
from .errors import AmbiguousTargetError, PolicyBlockedError, StaleTargetError
from .models import ElementInfo, ElementQuery, UIObservationSnapshot, WindowInfo
from .safety import ensure_argv_allowed, ensure_path_allowed
from .shell import ShellResult


class ReplayScreenshotProvider:
    def __init__(self, frames: Iterable[bytes]) -> None:
        self._frames = list(frames)
        self.calls = 0

    def capture_png(self) -> bytes:
        if self.calls >= len(self._frames):
            raise RuntimeError("screenshot replay exhausted")
        frame = self._frames[self.calls]
        self.calls += 1
        return frame


class ReplayInputAdapter:
    def __init__(self) -> None:
        self.events: list[tuple] = []
        self.clipboard = ""

    def click(self, x: int, y: int, *, button: str = "left") -> None:
        self.events.append(("click", x, y, button))

    def press(self, key: str) -> None:
        self.events.append(("press", key))

    def type_text(self, text: str) -> None:
        self.events.append(("type_text", len(text)))

    def clipboard_get(self) -> str:
        self.events.append(("clipboard_get",))
        return self.clipboard

    def clipboard_set(self, text: str) -> None:
        self.clipboard = text
        self.events.append(("clipboard_set", len(text)))


class ReplayUIAAdapter:
    """Replay UIA tree supporting deterministic stale/ambiguous/actionability tests."""

    def __init__(
        self,
        elements: Iterable[ElementInfo],
        *,
        snapshot: UIObservationSnapshot | None = None,
    ) -> None:
        self.elements = list(elements)
        self.snapshot_value = snapshot
        self.events: list[tuple[str, str | None]] = []

    def _resolve(self, query: ElementQuery) -> ElementInfo:
        matches = []
        for element in self.elements:
            pairs = (
                (query.automation_id, element.automation_id),
                (query.name, element.name),
                (query.control_type, element.control_type),
                (query.class_name, element.class_name),
            )
            if all(expected is None or expected.casefold() == (actual or "").casefold() for expected, actual in pairs):
                matches.append(element)
        matches.sort(
            key=lambda element: (
                (element.automation_id or "").casefold(),
                (element.name or "").casefold(),
                element.process_id or -1,
                element.native_handle or -1,
            )
        )
        if not matches:
            raise StaleTargetError(f"UIA automation_id not found: {query.automation_id}")
        if len(matches) > 1:
            raise AmbiguousTargetError(f"UIA selector matched {len(matches)} elements")
        return matches[0]

    def inspect(self, query: ElementQuery) -> ElementInfo:
        self.events.append(("inspect", query.automation_id))
        return self._resolve(query)

    def invoke(self, query: ElementQuery) -> ElementInfo:
        self.events.append(("invoke", query.automation_id))
        element = self._resolve(query)
        if not element.is_enabled or element.is_offscreen or not element.supports_invoke:
            raise PolicyBlockedError("UIA target does not expose a safe invoke capability")
        return replace(element)

    def focus(self, query: ElementQuery) -> ElementInfo:
        self.events.append(("focus", query.automation_id))
        element = self._resolve(query)
        if not element.is_enabled or element.is_offscreen:
            raise PolicyBlockedError("UIA target cannot be focused safely")
        return replace(element)

    def set_value(self, query: ElementQuery, value: str, *, sensitive: bool = False) -> ElementInfo:
        self.events.append(("set_value", query.automation_id))
        element = self._resolve(query)
        if sensitive or element.is_password:
            raise PolicyBlockedError("credential/sensitive text entry is not supported")
        if not element.is_enabled or element.is_offscreen or not element.supports_value:
            raise PolicyBlockedError("UIA target does not support deterministic value setting")
        return replace(element)

    def snapshot(self, *, window_title: str | None = None) -> UIObservationSnapshot:
        self.events.append(("snapshot", window_title))
        if self.snapshot_value is None:
            raise RuntimeError("UIA snapshot replay was not configured")
        return self.snapshot_value



class ReplayWindowEnumerator:
    def __init__(self, snapshots: Iterable[list[WindowInfo]]) -> None:
        self._snapshots = list(snapshots)
        self.calls = 0

    def list_windows(self) -> list[WindowInfo]:
        if self.calls >= len(self._snapshots):
            raise RuntimeError("window replay exhausted")
        value = list(self._snapshots[self.calls])
        self.calls += 1
        return value


class ReplayShellAdapter:
    def __init__(
        self,
        results: Iterable[ShellResult],
        *,
        allow_executables: set[str] | None = None,
    ) -> None:
        self._results = list(results)
        self.allow_executables = allow_executables or {"python", "python.exe", "git", "git.exe"}
        self.calls: list[tuple[list[str], str | None]] = []

    def validate(self, argv: Sequence[str], *, cwd: str | None = None) -> list[str]:
        args = ensure_argv_allowed(argv, self.allow_executables)
        ensure_path_allowed(cwd)
        return args

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | None = None,
        timeout_seconds: float | None = None,
        cancellation: CancellationToken | None = None,
    ) -> ShellResult:
        args = self.validate(argv, cwd=cwd)
        if cancellation is not None:
            cancellation.raise_if_cancelled()
        self.calls.append((args, cwd))
        if not self._results:
            raise RuntimeError("shell replay exhausted")
        return self._results.pop(0)
