from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from typing import Protocol

from .models import DisplayGeometry, Rect, WindowInfo


class WindowEnumerator(Protocol):
    def list_windows(self) -> list[WindowInfo]: ...


def list_display_geometries() -> list[DisplayGeometry]:
    if os.name != "nt":
        return []
    user32 = ctypes.windll.user32
    monitors: list[DisplayGeometry] = []
    monitor_enum_proc = ctypes.WINFUNCTYPE(
        ctypes.c_int, wintypes.HMONITOR, wintypes.HDC, ctypes.POINTER(wintypes.RECT), wintypes.LPARAM
    )

    class MONITORINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("rcMonitor", wintypes.RECT),
            ("rcWork", wintypes.RECT),
            ("dwFlags", wintypes.DWORD),
        ]

    @monitor_enum_proc
    def callback(hmonitor, _hdc, _rect, _lparam):
        info = MONITORINFO()
        info.cbSize = ctypes.sizeof(MONITORINFO)
        if user32.GetMonitorInfoW(hmonitor, ctypes.byref(info)):
            rect = info.rcMonitor
            bounds = Rect(rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top)
            monitors.append(
                DisplayGeometry(
                    display_id=f"monitor:{int(hmonitor)}",
                    bounds=bounds,
                    is_primary=bool(info.dwFlags & 1),
                )
            )
        return 1

    user32.EnumDisplayMonitors(0, 0, callback, 0)
    return sorted(monitors, key=lambda d: (d.bounds.x, d.bounds.y, d.display_id))


def display_for_rect(bounds: Rect | None, displays: list[DisplayGeometry] | None = None) -> str | None:
    if bounds is None:
        return None
    choices = displays if displays is not None else list_display_geometries()
    if not choices:
        return None
    cx = bounds.x + bounds.width / 2
    cy = bounds.y + bounds.height / 2
    containing = [
        d for d in choices
        if d.bounds.x <= cx < d.bounds.x + d.bounds.width
        and d.bounds.y <= cy < d.bounds.y + d.bounds.height
    ]
    if containing:
        return sorted(containing, key=lambda d: d.display_id)[0].display_id
    return min(
        choices,
        key=lambda d: abs((d.bounds.x + d.bounds.width / 2) - cx) + abs((d.bounds.y + d.bounds.height / 2) - cy),
    ).display_id


class Win32WindowEnumerator:
    def list_windows(self) -> list[WindowInfo]:
        if os.name != "nt":
            raise RuntimeError("window enumeration is only available on Windows")

        user32 = ctypes.windll.user32
        windows: list[WindowInfo] = []
        callback_type = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

        @callback_type
        def callback(hwnd: int, _lparam: int) -> bool:
            if not user32.IsWindowVisible(hwnd):
                return True
            length = user32.GetWindowTextLengthW(hwnd)
            if length <= 0:
                return True
            buffer = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buffer, length + 1)
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            windows.append(WindowInfo(hwnd=int(hwnd), title=buffer.value, visible=True, pid=int(pid.value)))
            return True

        user32.EnumWindows(callback, 0)
        return sorted(windows, key=lambda w: (w.title.casefold(), w.hwnd))
