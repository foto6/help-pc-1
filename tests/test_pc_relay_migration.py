from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tools.pc_relay_migrate import (
    MigrationConfig,
    MigrationError,
    Migrator,
    inventory,
)


def git(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode:
        raise AssertionError(result.stderr or result.stdout)
    return result


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def remote_ref(remote: Path, ref: str) -> str | None:
    result = subprocess.run(
        ["git", "ls-remote", "--heads", str(remote), f"refs/heads/{ref}"],
        text=True,
        capture_output=True,
        check=True,
    )
    line = result.stdout.strip()
    return line.split()[0] if line else None


def fixture_repo(
    tmp_path: Path,
    *,
    unresolved: bool = False,
    duplicate_result: bool = False,
):
    remote = tmp_path / "remote.git"
    subprocess.run(
        ["git", "init", "--bare", str(remote)],
        check=True,
        capture_output=True,
    )
    seed = tmp_path / "seed"
    seed.mkdir()
    git(seed, "init")
    git(seed, "config", "user.name", "Fixture")
    git(seed, "config", "user.email", "fixture@invalid")

    write_json(
        seed / "relay" / "requests" / "legacy-1.json",
        {
            "version": "pc_relay.request.v1",
            "id": "legacy-1",
            "action": "shell.run",
            "params": {"argv": ["whoami"]},
            "timeout_ms": 5000,
        },
    )
    if not unresolved:
        write_json(
            seed / "relay" / "results" / "legacy-1.json",
            {
                "version": "pc_relay.result.v1",
                "id": "legacy-1",
                "action": "shell.run",
                "relay_status": "completed",
            },
        )
    if duplicate_result:
        write_json(
            seed / "relay" / "results" / "duplicate.json",
            {
                "version": "pc_relay.result.v1",
                "id": "legacy-1",
                "action": "shell.run",
                "relay_status": "completed",
            },
        )
    (seed / "README.md").write_text("prototype\n", encoding="utf-8")
    git(seed, "add", ".")
    git(seed, "commit", "-m", "prototype")
    prototype_sha = git(seed, "rev-parse", "HEAD").stdout.strip()
    git(seed, "branch", "agent/pc-github-relay", prototype_sha)

    (seed / "tools").mkdir(exist_ok=True)
    (seed / "tools" / "pc_relay.py").write_text(
        "print('fixture implementation')\n",
        encoding="utf-8",
    )
    git(seed, "add", ".")
    git(seed, "commit", "-m", "implementation")
    implementation_sha = git(seed, "rev-parse", "HEAD").stdout.strip()
    git(seed, "branch", "agent/pc-relay-hardening", implementation_sha)

    git(seed, "remote", "add", "origin", str(remote))
    git(
        seed,
        "push",
        "origin",
        "agent/pc-github-relay",
        "agent/pc-relay-hardening",
    )
    git(
        remote,
        "symbolic-ref",
        "HEAD",
        "refs/heads/agent/pc-github-relay",
    )

    prototype = tmp_path / "prototype"
    subprocess.run(
        [
            "git",
            "clone",
            "-b",
            "agent/pc-github-relay",
            str(remote),
            str(prototype),
        ],
        check=True,
        capture_output=True,
    )
    git(prototype, "config", "user.name", "Fixture")
    git(prototype, "config", "user.email", "fixture@invalid")
    return remote, seed, prototype, prototype_sha, implementation_sha


def config(
    tmp_path: Path,
    remote: Path,
    prototype: Path,
    implementation_sha: str,
    *,
    plan: bool = False,
) -> MigrationConfig:
    return MigrationConfig(
        prototype_checkout=prototype,
        implementation_checkout=tmp_path / "implementation",
        queue_checkout=tmp_path / "queue",
        repo_url=str(remote),
        remote="origin",
        prototype_ref="agent/pc-github-relay",
        implementation_ref="agent/pc-relay-hardening",
        queue_ref="agent/pc-relay-queue",
        expected_implementation_sha=implementation_sha,
        report_path=tmp_path / "state" / "migration-report.json",
        plan=plan,
    )


def heartbeat(c: MigrationConfig) -> dict:
    return {
        "version": "pc_relay.heartbeat.v1",
        "relay_alive": True,
        "queue_reachable": True,
        "executor_available": True,
        "queue_integrity": "ok",
        "last_processed_request": None,
        "implementation_sha": c.expected_implementation_sha,
        "queue_ref": c.queue_ref,
        "queue_remote_sha": git(c.queue_checkout, "rev-parse", "HEAD").stdout.strip(),
        "generated_at": "2026-09-27T00:00:00.000Z",
    }


def run_migration(c: MigrationConfig, output: list[str] | None = None):
    return Migrator(
        c,
        emit=(output if output is not None else []).append,
        health_preflight=heartbeat,
    ).run()


def test_fresh_migration_and_idempotent_rerun(tmp_path: Path) -> None:
    remote, _seed, prototype, prototype_sha, implementation_sha = fixture_repo(tmp_path)
    c = config(tmp_path, remote, prototype, implementation_sha)
    output: list[str] = []

    first = run_migration(c, output)
    queue_sha = remote_ref(remote, c.queue_ref)
    second = run_migration(c)

    assert first.passed is True
    assert second.passed is True
    assert queue_sha == prototype_sha
    assert remote_ref(remote, c.queue_ref) == queue_sha
    assert git(c.implementation_checkout, "rev-parse", "HEAD").stdout.strip() == implementation_sha
    assert inventory(prototype, "relay/results") == inventory(c.queue_checkout, "relay/results")
    assert c.report_path.exists()
    assert any("FINAL LIVE START COMMAND:" in line for line in output)


def test_dirty_checkout_fails_closed(tmp_path: Path) -> None:
    remote, _seed, prototype, _prototype_sha, implementation_sha = fixture_repo(tmp_path)
    (prototype / "dirty.txt").write_text("dirty", encoding="utf-8")

    with pytest.raises(MigrationError, match="prototype checkout is dirty"):
        run_migration(config(tmp_path, remote, prototype, implementation_sha))


def test_wrong_expected_implementation_sha_fails_closed(tmp_path: Path) -> None:
    remote, _seed, prototype, _prototype_sha, _implementation_sha = fixture_repo(tmp_path)

    with pytest.raises(MigrationError, match="wrong expected implementation SHA"):
        run_migration(config(tmp_path, remote, prototype, "0" * 40))


def test_missing_legacy_result_emits_conversion_plan_and_blocks_live(tmp_path: Path) -> None:
    remote, _seed, prototype, _prototype_sha, implementation_sha = fixture_repo(
        tmp_path,
        unresolved=True,
    )
    c = config(tmp_path, remote, prototype, implementation_sha)
    output: list[str] = []

    outcome = run_migration(c, output)
    report = json.loads(c.report_path.read_text(encoding="utf-8"))

    assert outcome.passed is False
    assert outcome.unresolved_legacy_v1_count == 1
    assert outcome.live_command is None
    assert report["legacy_v1_conversion_plan"][0]["id"] == "legacy-1"
    assert report["live_cutover_ready"] is False
    assert not any("FINAL LIVE START COMMAND:" in line for line in output)


def test_duplicate_result_id_fails_closed(tmp_path: Path) -> None:
    remote, _seed, prototype, _prototype_sha, implementation_sha = fixture_repo(
        tmp_path,
        duplicate_result=True,
    )

    with pytest.raises(MigrationError, match="duplicate logical id"):
        run_migration(config(tmp_path, remote, prototype, implementation_sha))


def test_mismatched_result_bytes_fail_closed(tmp_path: Path) -> None:
    remote, seed, prototype, prototype_sha, implementation_sha = fixture_repo(tmp_path)
    c = config(tmp_path, remote, prototype, implementation_sha)

    git(seed, "checkout", "-B", c.queue_ref, prototype_sha)
    result = seed / "relay" / "results" / "legacy-1.json"
    result.write_text(result.read_text(encoding="utf-8") + " ", encoding="utf-8")
    git(seed, "add", ".")
    git(seed, "commit", "-m", "corrupt queue result bytes")
    git(seed, "push", "origin", c.queue_ref)

    with pytest.raises(MigrationError, match="result inventory byte mismatch"):
        run_migration(c)


def test_preexisting_queue_ref_is_reused_when_correct(tmp_path: Path) -> None:
    remote, seed, prototype, prototype_sha, implementation_sha = fixture_repo(tmp_path)
    c = config(tmp_path, remote, prototype, implementation_sha)
    git(seed, "branch", c.queue_ref, prototype_sha)
    git(seed, "push", "origin", c.queue_ref)
    before = remote_ref(remote, c.queue_ref)

    outcome = run_migration(c)

    assert outcome.passed is True
    assert remote_ref(remote, c.queue_ref) == before


def test_preexisting_queue_ref_wrong_ancestry_fails_closed(tmp_path: Path) -> None:
    remote, seed, prototype, _prototype_sha, implementation_sha = fixture_repo(tmp_path)
    c = config(tmp_path, remote, prototype, implementation_sha)

    git(seed, "checkout", "--orphan", "unrelated")
    git(seed, "rm", "-rf", ".")
    (seed / "unrelated.txt").write_text("unrelated\n", encoding="utf-8")
    git(seed, "add", ".")
    git(seed, "commit", "-m", "unrelated queue")
    git(seed, "push", "origin", f"HEAD:{c.queue_ref}")

    with pytest.raises(MigrationError, match="does not descend from frozen prototype"):
        run_migration(c)


def test_interrupted_migration_resume_reuses_partial_checkouts(tmp_path: Path) -> None:
    remote, _seed, prototype, prototype_sha, implementation_sha = fixture_repo(tmp_path)
    c = config(tmp_path, remote, prototype, implementation_sha)

    subprocess.run(
        [
            "git",
            "clone",
            "--no-checkout",
            str(remote),
            str(c.implementation_checkout),
        ],
        check=True,
        capture_output=True,
    )
    git(c.implementation_checkout, "checkout", "--detach", implementation_sha)
    subprocess.run(
        [
            "git",
            "push",
            str(remote),
            f"{prototype_sha}:refs/heads/{c.queue_ref}",
        ],
        cwd=prototype,
        check=True,
        capture_output=True,
    )

    outcome = run_migration(c)

    assert outcome.passed is True
    assert c.queue_checkout.exists()
    assert remote_ref(remote, c.queue_ref) == prototype_sha


def test_plan_mode_mutates_nothing(tmp_path: Path) -> None:
    remote, _seed, prototype, _prototype_sha, implementation_sha = fixture_repo(tmp_path)
    c = config(tmp_path, remote, prototype, implementation_sha, plan=True)
    output: list[str] = []

    outcome = run_migration(c, output)

    assert outcome.passed is True
    assert remote_ref(remote, c.queue_ref) is None
    assert not c.implementation_checkout.exists()
    assert not c.queue_checkout.exists()
    assert not c.report_path.exists()
    assert any(line.startswith("PLAN:") for line in output)
