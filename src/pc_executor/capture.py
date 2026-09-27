from __future__ import annotations

import base64
import io
import os
from typing import Protocol


class ScreenshotProvider(Protocol):
    def capture_png(self) -> bytes: ...


class PillowScreenCapture:
    """Captures the desktop using Pillow's ImageGrab on Windows."""

    def capture_png(self) -> bytes:
        if os.name != "nt":
            raise RuntimeError("screenshot capture is only available on Windows")
        from PIL import ImageGrab

        image = ImageGrab.grab(all_screens=True)
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return buffer.getvalue()


def screenshot_payload(png_bytes: bytes) -> dict[str, object]:
    return {
        "encoding": "base64",
        "mime_type": "image/png",
        "bytes": len(png_bytes),
        "data": base64.b64encode(png_bytes).decode("ascii"),
    }
