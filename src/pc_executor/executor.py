from __future__ import annotations

from typing import Any

from .audit import AuditSink, InMemoryAuditSink
from .capture import PillowScreenCapture, ScreenshotProvider, screenshot_payload
from .input import InputAdapter, WindowsInputAdapter
from .models import ActionRequest, ActionResult, AuditEvent, ElementQuery, utc_now_iso
from .safety import SafetyViolation, ensure_not_sensitive_text
from .shell import SafeShellAdapter
from .uia import AccessibilityAdapter, WindowsUIAutomationAdapter
from .windows import Win32WindowEnumerator, WindowEnumerator


class Executor:
    """Policy-enforcing facade for local Windows computer actions."""

    def __init__(
        self,
        *,
        screenshot: ScreenshotProvider | None = None,
        windows: WindowEnumerator | None = None,
        accessibility: AccessibilityAdapter | None = None,
        input_adapter: InputAdapter | None = None,
        shell: SafeShellAdapter | None = None,
        audit: AuditSink | None = None,
        dry_run: bool = True,
        allow_coordinate_fallback: bool = False,
    ) -> None:
        self.screenshot = screenshot or PillowScreenCapture()
        self.windows = windows or Win32WindowEnumerator()
        self.accessibility = accessibility or WindowsUIAutomationAdapter()
        self.input = input_adapter or WindowsInputAdapter()
        self.shell = shell or SafeShellAdapter()
        self.audit = audit or InMemoryAuditSink()
        self.dry_run = dry_run
        self.allow_coordinate_fallback = allow_coordinate_fallback

    def execute(self, request: ActionRequest) -> ActionResult:
        started = utc_now_iso()
        effective_dry_run = self.dry_run if request.dry_run is None else bool(request.dry_run)
        self._audit(request, "start", effective_dry_run)
        try:
            data = self._dispatch(request, effective_dry_run)
            result = ActionResult(
                request_id=request.request_id,
                action=request.action,
                ok=True,
                status="dry_run" if effective_dry_run else "completed",
                started_at=started,
                finished_at=utc_now_iso(),
                data=data,
                dry_run=effective_dry_run,
            )
            self._audit(request, "finish", effective_dry_run, outcome=result.status, details=data)
            return result
        except SafetyViolation as exc:
            result = ActionResult(
                request_id=request.request_id,
                action=request.action,
                ok=False,
                status="blocked",
                started_at=started,
                finished_at=utc_now_iso(),
                error=str(exc),
                dry_run=effective_dry_run,
            )
            self._audit(request, "finish", effective_dry_run, outcome="blocked", details={"error": str(exc)})
            return result
        except Exception as exc:
            result = ActionResult(
                request_id=request.request_id,
                action=request.action,
                ok=False,
                status="error",
                started_at=started,
                finished_at=utc_now_iso(),
                error=f"{type(exc).__name__}: {exc}",
                dry_run=effective_dry_run,
            )
            self._audit(request, "finish", effective_dry_run, outcome="error", details={"error": result.error})
            return result

    def _dispatch(self, request: ActionRequest, dry_run: bool) -> dict[str, Any]:
        action = request.action
        p = request.params

        if action == "screenshot.capture":
            if dry_run:
                return {"would_execute": action}
            return screenshot_payload(self.screenshot.capture_png())

        if action == "windows.list":
            if dry_run:
                return {"would_execute": action}
            return {"windows": [window.to_dict() for window in self.windows.list_windows()]}

        if action.startswith("uia."):
            query = ElementQuery.from_dict(dict(p.get("query") or {}))
            if action == "uia.inspect":
                if dry_run:
                    return {"would_execute": action, "query": p.get("query", {})}
                return {"element": self.accessibility.inspect(query).to_dict()}
            if action == "uia.invoke":
                if dry_run:
                    return {"would_execute": action, "query": p.get("query", {})}
                return {"element": self.accessibility.invoke(query).to_dict()}
            if action == "uia.focus":
                if dry_run:
                    return {"would_execute": action, "query": p.get("query", {})}
                return {"element": self.accessibility.focus(query).to_dict()}
            if action == "uia.set_value":
                value = str(p.get("value", ""))
                sensitive = bool(p.get("sensitive", False))
                if dry_run:
                    if sensitive:
                        raise SafetyViolation("credential/sensitive text entry is not supported")
                    return {"would_execute": action, "query": p.get("query", {}), "value_length": len(value)}
                return {
                    "element": self.accessibility.set_value(query, value, sensitive=sensitive).to_dict(),
                    "value_length": len(value),
                }
            raise SafetyViolation(f"unsupported UIA action: {action}")

        if action == "mouse.click":
            if not self.allow_coordinate_fallback:
                raise SafetyViolation("raw coordinate fallback is disabled; use UI Automation first")
            x, y = int(p["x"]), int(p["y"])
            button = str(p.get("button", "left"))
            if dry_run:
                return {"would_execute": action, "x": x, "y": y, "button": button}
            self.input.click(x, y, button=button)
            return {"x": x, "y": y, "button": button}

        if action == "keyboard.press":
            key = str(p["key"])
            if dry_run:
                return {"would_execute": action, "key": key}
            self.input.press(key)
            return {"key": key}

        if action == "keyboard.type_text":
            text = str(p.get("text", ""))
            sensitive = bool(p.get("sensitive", False))
            ensure_not_sensitive_text(is_password=False, sensitive=sensitive)
            if dry_run:
                return {"would_execute": action, "text_length": len(text)}
            self.input.type_text(text)
            return {"text_length": len(text)}

        if action == "clipboard.get":
            if dry_run:
                return {"would_execute": action}
            value = self.input.clipboard_get()
            return {"text": value}

        if action == "clipboard.set":
            value = str(p.get("text", ""))
            if bool(p.get("sensitive", False)):
                raise SafetyViolation("credential/sensitive clipboard entry is not supported")
            if dry_run:
                return {"would_execute": action, "text_length": len(value)}
            self.input.clipboard_set(value)
            return {"text_length": len(value)}

        if action == "shell.run":
            argv = [str(x) for x in p.get("argv", [])]
            cwd = p.get("cwd")
            validated = self.shell.validate(argv, cwd=cwd)
            if dry_run:
                return {"would_execute": action, "argv": validated, "cwd": cwd}
            return self.shell.run(validated, cwd=cwd).to_dict()

        raise SafetyViolation(f"unsupported action: {action}")

    def _audit(
        self,
        request: ActionRequest,
        phase: str,
        dry_run: bool,
        *,
        outcome: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        safe_details = dict(details or {})
        if request.action in {"keyboard.type_text", "clipboard.set", "uia.set_value"}:
            safe_details.pop("text", None)
            safe_details.pop("value", None)
        self.audit.emit(
            AuditEvent(
                request_id=request.request_id,
                action=request.action,
                phase=phase,
                timestamp=utc_now_iso(),
                dry_run=dry_run,
                outcome=outcome,
                details=safe_details,
            )
        )
