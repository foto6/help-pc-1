from __future__ import annotations

import subprocess
from pathlib import Path

BASE = "2cc1e40f792a3d74560b726a0d246c90b7f077e9"
EXPECTED_CHANGED = {
    ".github/workflows/tests.yml",
    "docs/UIA_SNAPSHOT_BUDGET_R18.md",
    "src/pc_executor/executor.py",
    "src/pc_executor/models.py",
    "src/pc_executor/uia.py",
    "tests/test_uia_snapshot_budget.py",
    "tests/windows/test_uia_snapshot_budget_windows.py",
    "tools/audit_r18_uia_timeout.py",
}
FROZEN = {
    "src/pc_executor/cancellation.py",
    "src/pc_executor/context_binding.py",
    "src/pc_executor/input.py",
    "src/pc_executor/outcome.py",
    "src/pc_executor/outcome_journal.py",
    "src/pc_executor/preflight.py",
    "src/pc_executor/safety.py",
    "src/pc_executor/windows.py",
}


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        check=check,
        text=True,
        capture_output=True,
    )


def rev(spec: str) -> str:
    return git("rev-parse", spec).stdout.strip()


def names(base: str, head: str) -> set[str]:
    return {
        line
        for line in git("diff", "--name-only", base, head).stdout.splitlines()
        if line
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    head = rev("HEAD")
    assert git(
        "merge-base", "--is-ancestor", BASE, head, check=False
    ).returncode == 0
    assert rev(BASE) == BASE

    changed = names(BASE, head)
    assert changed == EXPECTED_CHANGED, (
        f"R18 changed-file drift: missing={sorted(EXPECTED_CHANGED - changed)} "
        f"extra={sorted(changed - EXPECTED_CHANGED)}"
    )

    for path in sorted(FROZEN):
        assert rev(f"{BASE}:{path}") == rev(f"{head}:{path}"), path

    workflow = (root / ".github" / "workflows" / "tests.yml").read_text(
        encoding="utf-8"
    )
    assert "agent/pc-control-uia-timeout-r18-20261001" in workflow
    assert "test_uia_snapshot_budget.py" in workflow
    assert "test_uia_snapshot_budget_windows.py" in workflow

    uia = (root / "src" / "pc_executor" / "uia.py").read_text(encoding="utf-8")
    for required in (
        "UIAutomationInitializerInThread",
        "UIASnapshotBudget",
        "max_nodes: int = 256",
        "max_children_per_node: int = 64",
        "max_work_units: int = 2048",
        "time_budget_seconds: float = 2.0",
        "coordinate_fallback_used",
        "side_effects",
    ):
        assert required in uia

    executor = (
        root / "src" / "pc_executor" / "executor.py"
    ).read_text(encoding="utf-8")
    assert "outer_timeout * 0.60" in executor
    assert 'payload["observation"]' in executor

    diff_check = git("diff", "--check", BASE, head, check=False)
    assert diff_check.returncode == 0, diff_check.stdout + diff_check.stderr

    print(
        "R18 UIA timeout audit: PASS "
        f"head={head} base={BASE} files={len(changed)}"
    )


if __name__ == "__main__":
    main()
