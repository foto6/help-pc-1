from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path
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
        ctypes.c_int,
        wintypes.HMONITOR,
        wintypes.HDC,
        ctypes.POINTER(wintypes.RECT),
        wintypes.LPARAM,
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
            bounds = Rect(
                rect.left,
                rect.top,
                rect.right - rect.left,
                rect.bottom - rect.top,
            )
            monitors.append(
                DisplayGeometry(
                    display_id=f"monitor:{int(hmonitor)}",
                    bounds=bounds,
                    is_primary=bool(info.dwFlags & 1),
                )
            )
        return 1

    user32.EnumDisplayMonitors(0, 0, callback, 0)
    return sorted(
        monitors,
        key=lambda d: (d.bounds.x, d.bounds.y, d.display_id),
    )


def display_for_rect(
    bounds: Rect | None,
    displays: list[DisplayGeometry] | None = None,
) -> str | None:
    if bounds is None:
        return None
    choices = displays if displays is not None else list_display_geometries()
    if not choices:
        return None
    cx = bounds.x + bounds.width / 2
    cy = bounds.y + bounds.height / 2
    containing = [
        d
        for d in choices
        if d.bounds.x <= cx < d.bounds.x + d.bounds.width
        and d.bounds.y <= cy < d.bounds.y + d.bounds.height
    ]
    if containing:
        return sorted(containing, key=lambda d: d.display_id)[0].display_id
    return min(
        choices,
        key=lambda d: abs((d.bounds.x + d.bounds.width / 2) - cx)
        + abs((d.bounds.y + d.bounds.height / 2) - cy),
    ).display_id


def display_for_point(
    x: int,
    y: int,
    displays: list[DisplayGeometry] | None = None,
) -> str | None:
    choices = displays if displays is not None else list_display_geometries()
    if not choices:
        return None
    containing = [
        display
        for display in choices
        if display.bounds.x <= x < display.bounds.x + display.bounds.width
        and display.bounds.y <= y < display.bounds.y + display.bounds.height
    ]
    if containing:
        return sorted(containing, key=lambda d: d.display_id)[0].display_id
    return min(
        choices,
        key=lambda d: abs((d.bounds.x + d.bounds.width / 2) - x)
        + abs((d.bounds.y + d.bounds.height / 2) - y),
    ).display_id


def root_window_handle(hwnd: int | None) -> int | None:
    if hwnd is None:
        return None
    if os.name != "nt":
        return int(hwnd)
    user32 = ctypes.windll.user32
    user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
    user32.GetAncestor.restype = wintypes.HWND
    root = user32.GetAncestor(wintypes.HWND(hwnd), 2)
    return int(root or hwnd)


def _window_rect(hwnd: int) -> Rect | None:
    if os.name != "nt":
        return None
    rect = wintypes.RECT()
    if not ctypes.windll.user32.GetWindowRect(
        wintypes.HWND(hwnd),
        ctypes.byref(rect),
    ):
        return None
    return Rect(
        int(rect.left),
        int(rect.top),
        int(rect.right - rect.left),
        int(rect.bottom - rect.top),
    )


def process_start_epoch_ms(pid: int | None) -> int | None:
    if pid is None or pid <= 0:
        return None
    if os.name == "nt":
        kernel32 = ctypes.windll.kernel32
        process_query_limited_information = 0x1000
        kernel32.OpenProcess.argtypes = [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetProcessTimes.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        kernel32.GetProcessTimes.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(
            process_query_limited_information,
            False,
            int(pid),
        )
        if not handle:
            return None
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel_time = wintypes.FILETIME()
        user_time = wintypes.FILETIME()
        try:
            if not kernel32.GetProcessTimes(
                handle,
                ctypes.byref(creation),
                ctypes.byref(exit_time),
                ctypes.byref(kernel_time),
                ctypes.byref(user_time),
            ):
                return None
            value = (int(creation.dwHighDateTime) << 32) | int(
                creation.dwLowDateTime
            )
            unix_100ns = value - 116444736000000000
            if unix_100ns < 0:
                return None
            return unix_100ns // 10_000
        finally:
            kernel32.CloseHandle(handle)

    if os.name == "posix":
        try:
            stat_raw = Path(f"/proc/{pid}/stat").read_text(
                encoding="utf-8"
            )
            end = stat_raw.rfind(")")
            if end < 0:
                return None
            fields = stat_raw[end + 2 :].split()
            start_ticks = int(fields[19])
            clock_ticks = int(os.sysconf("SC_CLK_TCK"))
            btime = None
            for line in Path("/proc/stat").read_text(
                encoding="utf-8"
            ).splitlines():
                if line.startswith("btime "):
                    btime = int(line.split()[1])
                    break
            if btime is None or clock_ticks <= 0:
                return None
            return int((btime + start_ticks / clock_ticks) * 1000)
        except (OSError, ValueError, IndexError):
            return None
    return None


def foreground_window_info() -> WindowInfo | None:
    if os.name != "nt":
        return None
    user32 = ctypes.windll.user32
    user32.GetForegroundWindow.restype = wintypes.HWND
    hwnd = user32.GetForegroundWindow()
    if not hwnd:
        return None
    hwnd_value = int(hwnd)
    length = user32.GetWindowTextLengthW(hwnd)
    buffer = ctypes.create_unicode_buffer(max(1, length + 1))
    user32.GetWindowTextW(hwnd, buffer, len(buffer))
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    pid_value = int(pid.value) or None
    bounds = _window_rect(hwnd_value)
    return WindowInfo(
        hwnd=hwnd_value,
        title=buffer.value,
        visible=bool(user32.IsWindowVisible(hwnd)),
        pid=pid_value,
        process_start_epoch_ms=process_start_epoch_ms(pid_value),
        display_id=display_for_rect(bounds),
        is_foreground=True,
    )


class Win32WindowEnumerator:
    def list_windows(self) -> list[WindowInfo]:
        if os.name != "nt":
            raise RuntimeError(
                "window enumeration is only available on Windows"
            )

        user32 = ctypes.windll.user32
        windows: list[WindowInfo] = []
        displays = list_display_geometries()
        foreground = user32.GetForegroundWindow()
        foreground_value = int(foreground) if foreground else None
        callback_type = ctypes.WINFUNCTYPE(
            ctypes.c_bool,
            wintypes.HWND,
            wintypes.LPARAM,
        )

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
            pid_value = int(pid.value) or None
            hwnd_value = int(hwnd)
            windows.append(
                WindowInfo(
                    hwnd=hwnd_value,
                    title=buffer.value,
                    visible=True,
                    pid=pid_value,
                    process_start_epoch_ms=process_start_epoch_ms(pid_value),
                    display_id=display_for_rect(
                        _window_rect(hwnd_value),
                        displays,
                    ),
                    is_foreground=hwnd_value == foreground_value,
                )
            )
            return True

        user32.EnumWindows(callback, 0)
        return sorted(
            windows,
            key=lambda w: (w.title.casefold(), w.hwnd),
        )
