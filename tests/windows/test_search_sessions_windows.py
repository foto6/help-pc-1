import ctypes
import os
import sys
import time
from pathlib import Path

import pytest

from pc_executor.operations import LocalOperations
from pc_executor.shell import SafeShellAdapter


pytestmark = pytest.mark.skipif(
    os.name != "nt",
    reason="Windows search lifecycle fixtures",
)


def _ops(tmp_path: Path) -> LocalOperations:
    executable = Path(sys.executable).name.lower()
    shell = SafeShellAdapter(
        allow_executables={"python", "python.exe", executable},
        output_limit_bytes=4096,
    )
    return LocalOperations(
        shell=shell,
        state_root=tmp_path / "ops-state",
        search_max_workers=1,
    )


def _wait(ops: LocalOperations, search_id: str) -> dict:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        result = ops.execute(
            "search.read",
            {"search_id": search_id, "offset": 0, "length": 100},
        )
        if result["status"] != "running":
            return result
        time.sleep(0.01)
    raise AssertionError("search did not finish")


def _set_hidden(path: Path) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_attrs = kernel32.GetFileAttributesW
    set_attrs = kernel32.SetFileAttributesW
    get_attrs.argtypes = [ctypes.c_wchar_p]
    get_attrs.restype = ctypes.c_uint32
    set_attrs.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    set_attrs.restype = ctypes.c_int
    attrs = get_attrs(str(path))
    if attrs == 0xFFFFFFFF:
        raise OSError(ctypes.get_last_error(), "GetFileAttributesW failed")
    if not set_attrs(str(path), attrs | 0x2):
        raise OSError(ctypes.get_last_error(), "SetFileAttributesW failed")


def test_windows_hidden_attribute_respects_include_hidden(tmp_path: Path) -> None:
    root = tmp_path / "hidden"
    root.mkdir()
    hidden = root / "hidden-match.txt"
    hidden.write_text("x", encoding="utf-8")
    _set_hidden(hidden)
    ops = _ops(tmp_path)

    default = ops.execute(
        "search.start",
        {
            "path": str(root),
            "pattern": "hidden",
            "search_type": "files",
            "literal_search": True,
        },
    )
    assert _wait(ops, default["search_id"])["result_count"] == 0

    included = ops.execute(
        "search.start",
        {
            "path": str(root),
            "pattern": "hidden",
            "search_type": "files",
            "literal_search": True,
            "include_hidden": True,
        },
    )
    result = _wait(ops, included["search_id"])
    assert [Path(item["path"]).name for item in result["results"]] == [
        "hidden-match.txt"
    ]


def test_windows_reparse_directory_is_not_followed(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret-match.txt").write_text("x", encoding="utf-8")
    link = root / "escape"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable on this runner: {exc}")

    ops = _ops(tmp_path)
    started = ops.execute(
        "search.start",
        {
            "path": str(root),
            "pattern": "secret",
            "search_type": "files",
            "literal_search": True,
            "include_hidden": True,
        },
    )
    result = _wait(ops, started["search_id"])
    assert result["status"] == "completed"
    assert result["result_count"] == 0
