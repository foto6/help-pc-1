from __future__ import annotations

from pc_executor.audit import InMemoryAuditSink
from pc_executor.executor import Executor
from pc_executor.models import ActionRequest, ElementInfo, WindowInfo
from pc_executor.shell import SafeShellAdapter


class FakeCapture:
    def capture_png(self) -> bytes:
        return b"png"


class FakeWindows:
    def list_windows(self):
        return [WindowInfo(hwnd=1, title="Editor", visible=True, pid=99)]


class FakeAccessibility:
    def __init__(self, *, password: bool = False):
        self.password = password
        self.calls: list[str] = []

    def _info(self):
        return ElementInfo("Save", "save", "ButtonControl", True, self.password, 42)

    def inspect(self, query):
        self.calls.append("inspect")
        return self._info()

    def invoke(self, query):
        self.calls.append("invoke")
        return self._info()

    def focus(self, query):
        self.calls.append("focus")
        return self._info()

    def set_value(self, query, value, *, sensitive=False):
        self.calls.append("set_value")
        if self.password or sensitive:
            from pc_executor.safety import SafetyViolation
            raise SafetyViolation("credential/sensitive text entry is not supported")
        return self._info()


class FakeInput:
    def __init__(self):
        self.calls = []
        self.clipboard = ""

    def click(self, x, y, *, button="left"):
        self.calls.append(("click", x, y, button))

    def press(self, key):
        self.calls.append(("press", key))

    def type_text(self, text):
        self.calls.append(("type", text))

    def clipboard_get(self):
        return self.clipboard

    def clipboard_set(self, text):
        self.clipboard = text
        self.calls.append(("clipboard", text))


def make_executor(**kwargs):
    audit = kwargs.pop("audit", InMemoryAuditSink())
    executor = Executor(
        screenshot=FakeCapture(),
        windows=FakeWindows(),
        accessibility=kwargs.pop("accessibility", FakeAccessibility()),
        input_adapter=kwargs.pop("input_adapter", FakeInput()),
        shell=kwargs.pop("shell", SafeShellAdapter(allow_executables={"python", "python.exe"})),
        audit=audit,
        **kwargs,
    )
    return executor, audit


def test_dry_run_has_no_side_effect_and_audits():
    input_adapter = FakeInput()
    executor, audit = make_executor(dry_run=True, input_adapter=input_adapter)
    result = executor.execute(ActionRequest("keyboard.press", {"key": "enter"}, request_id="r1"))
    assert result.ok is True
    assert result.status == "dry_run"
    assert input_adapter.calls == []
    assert [event.phase for event in audit.events] == ["start", "finish"]
    assert audit.events[-1].outcome == "dry_run"


def test_coordinate_click_is_blocked_by_default_even_in_live_mode():
    executor, _ = make_executor(dry_run=False)
    result = executor.execute(ActionRequest("mouse.click", {"x": 5, "y": 9}))
    assert result.ok is False
    assert result.status == "blocked"
    assert "UI Automation first" in result.error


def test_coordinate_click_can_be_explicitly_enabled():
    input_adapter = FakeInput()
    executor, _ = make_executor(dry_run=False, allow_coordinate_fallback=True, input_adapter=input_adapter)
    result = executor.execute(ActionRequest("mouse.click", {"x": 5, "y": 9}))
    assert result.ok is True
    assert input_adapter.calls == [("click", 5, 9, "left")]


def test_uia_invoke_is_primary_deterministic_action():
    accessibility = FakeAccessibility()
    executor, _ = make_executor(dry_run=False, accessibility=accessibility)
    result = executor.execute(ActionRequest("uia.invoke", {"query": {"automation_id": "save"}}))
    assert result.ok is True
    assert result.data["element"]["automation_id"] == "save"
    assert accessibility.calls == ["invoke"]


def test_sensitive_keyboard_text_is_blocked():
    executor, _ = make_executor(dry_run=False)
    result = executor.execute(ActionRequest("keyboard.type_text", {"text": "secret", "sensitive": True}))
    assert result.status == "blocked"
    assert "credential/sensitive" in result.error


def test_password_uia_value_is_blocked_by_adapter():
    executor, _ = make_executor(dry_run=False, accessibility=FakeAccessibility(password=True))
    result = executor.execute(ActionRequest("uia.set_value", {"query": {"name": "Password"}, "value": "secret"}))
    assert result.status == "blocked"


def test_shell_rejects_non_allowlisted_executable():
    executor, _ = make_executor(dry_run=True)
    result = executor.execute(ActionRequest("shell.run", {"argv": ["powershell.exe", "Get-Process"]}))
    assert result.status == "blocked"
    assert "safe allowlist" in result.error


def test_shell_rejects_protected_path():
    executor, _ = make_executor(dry_run=True)
    result = executor.execute(ActionRequest("shell.run", {"argv": ["python", r"E:\manhwa\tool.py"]}))
    assert result.status == "blocked"
    assert "protected path" in result.error


def test_shell_dry_run_validates_without_execution():
    executor, _ = make_executor(dry_run=True)
    result = executor.execute(ActionRequest("shell.run", {"argv": ["python", "-V"]}))
    assert result.ok is True
    assert result.data["argv"] == ["python", "-V"]


def test_windows_list_and_screenshot_live_paths():
    executor, _ = make_executor(dry_run=False)
    windows = executor.execute(ActionRequest("windows.list"))
    shot = executor.execute(ActionRequest("screenshot.capture"))
    assert windows.data["windows"][0]["title"] == "Editor"
    assert shot.data["mime_type"] == "image/png"
    assert shot.data["bytes"] == 3
