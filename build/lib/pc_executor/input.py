from __future__ import annotations

import os
from typing import Protocol

from .safety import SafetyViolation


class InputAdapter(Protocol):
    def click(self, x: int, y: int, *, button: str = "left") -> None: ...
    def press(self, key: str) -> None: ...
    def type_text(self, text: str) -> None: ...
    def clipboard_get(self) -> str: ...
    def clipboard_set(self, text: str) -> None: ...


class WindowsInputAdapter:
    """Raw input fallback. Coordinate clicks are controlled by Executor policy."""

    def _pyautogui(self):
        if os.name != "nt":
            raise RuntimeError("raw input is only available on Windows")
        try:
            import pyautogui
        except ImportError as exc:
            raise RuntimeError("install the Windows dependency pyautogui") from exc
        pyautogui.FAILSAFE = True
        return pyautogui

    def click(self, x: int, y: int, *, button: str = "left") -> None:
        if button not in {"left", "right", "middle"}:
            raise SafetyViolation(f"unsupported mouse button: {button}")
        self._pyautogui().click(x=x, y=y, button=button)

    def press(self, key: str) -> None:
        if not key or len(key) > 64:
            raise SafetyViolation("keyboard key must be a short non-empty name")
        self._pyautogui().press(key)

    def type_text(self, text: str) -> None:
        self._pyautogui().write(text, interval=0)

    def clipboard_get(self) -> str:
        if os.name != "nt":
            raise RuntimeError("clipboard is only available on Windows")
        import pyperclip
        return str(pyperclip.paste())

    def clipboard_set(self, text: str) -> None:
        if os.name != "nt":
            raise RuntimeError("clipboard is only available on Windows")
        import pyperclip
        pyperclip.copy(text)
