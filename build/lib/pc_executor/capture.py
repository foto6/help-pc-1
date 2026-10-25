from __future__ import annotations

import base64
import hashlib
import io
import os
from typing import Protocol

from PIL import Image

from .models import DisplayGeometry
from .windows import list_display_geometries


class ScreenshotProvider(Protocol):
    def capture_png(self) -> bytes: ...


class PillowScreenCapture:
    """Captures the full virtual desktop using Pillow's ImageGrab on Windows."""

    def capture_png(self) -> bytes:
        if os.name != "nt":
            raise RuntimeError("screenshot capture is only available on Windows")
        from PIL import ImageGrab

        image = ImageGrab.grab(all_screens=True)
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return buffer.getvalue()


def screenshot_payload(
    png_bytes: bytes,
    *,
    displays: list[DisplayGeometry] | None = None,
) -> dict[str, object]:
    digest = hashlib.sha256(png_bytes).hexdigest()
    try:
        with Image.open(io.BytesIO(png_bytes)) as image:
            width, height = image.size
    except Exception:
        # Adapter fakes and legacy test doubles may return opaque PNG bytes.
        # Production Pillow capture always supplies a decodable image.
        width, height = 0, 0
    geometries = list_display_geometries() if displays is None else displays
    return {
        "capture_id": f"shot:{digest}",
        "encoding": "base64",
        "mime_type": "image/png",
        "bytes": len(png_bytes),
        "width": int(width),
        "height": int(height),
        "coordinate_space": "physical_screen_px",
        "display_geometry": [display.to_dict() for display in geometries],
        "sha256": digest,
        "data": base64.b64encode(png_bytes).decode("ascii"),
    }
