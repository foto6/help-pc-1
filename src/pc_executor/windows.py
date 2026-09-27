from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from typing import Protocol

from .models import WindowInfo


class WindowEnumerator(Protocol):
    def list_windows(self) -> list[WindowInfo]: ...


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
        return windows
