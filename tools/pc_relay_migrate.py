from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from pc_executor.safety import SafetyViolation, ensure_path_allowed

VERSION = "pc_relay.migration.v1"
REPO_URL = "https://github.com/foto6/help-pc-1.git"
PROTOTYPE_REF = "agent/pc-github-relay"
IMPLEMENTATION_REF = "agent/pc-relay-hardening"
QUEUE_REF = "agent/pc-relay-queue"
HEARTBEAT_ID = "migration-preflight"


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class InventoryEntry:
    path: str
    sha256: str
    bytes: int
    logical_id: str | None
    version: str | None
    action: str | None


@dataclass(frozen=True)
class MigrationConfig:
    prototype_checkout: Path
    implementation_checkout: Path
    queue_checkout: Path
    repo_url: str
    remote: str
    prototype_ref: str
    implementation_ref: str
    queue_ref: str
    expected_implementation_sha: str
    report_path: Path
    plan: bool = False


@dataclass(frozen=True)
class MigrationOutcome:
    passed: bool
    prototype_sha: str
    implementation_sha: str
    queue_sha: str | None
    request_count: int
    result_count: int
    unresolved_legacy_v1_count: int
    live_command: str | None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def run_command(
    argv: Sequence[str],
    cwd: Path | None = None,
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(argv),
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise MigrationError(f"command failed ({' '.join(argv)}): {detail}")
    return result


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run_command(["git", *args], repo, check=check)


def git_output(repo: Path, *args: str) -> str:
    return git(repo, *args).stdout.strip()


def remote_key(value: str) -> str:
    value = value.strip().rstrip("/")
    if value.endswith(".git"):
        value = value[:-4]
    if "://" not in value:
        try:
            value = str(Path(value).expanduser().resolve())
        except OSError:
            pass
    return value.replace("\\", "/")


def ls_remote(url: str, ref: str) -> str | None:
    result = run_command(["git", "ls-remote", "--heads", url, f"refs/heads/{ref}"])
    line = result.stdout.strip()
    return line.split()[0] if line else None


def fetch_ref(repo: Path, remote: str, ref: str) -> str:
    tracking = f"refs/remotes/{remote}/{ref}"
    git(repo, "fetch", "--no-tags", remote, f"+refs/heads/{ref}:{tracking}")
    return git_output(repo, "rev-parse", "--verify", tracking)


def assert_repo(path: Path, label: str, remote: str, repo_url: str) -> None:
    if not path.exists():
        raise MigrationError(f"{label} checkout does not exist: {path}")
    probe = git(path, "rev-parse", "--show-toplevel", check=False)
    if probe.returncode != 0:
        raise MigrationError(f"{label} is not a Git checkout: {path}")
    if Path(probe.stdout.strip()).resolve() != path.resolve():
        raise MigrationError(f"{label} must be a dedicated Git worktree root")
    actual = git(path, "remote", "get-url", remote, check=False)
    if actual.returncode != 0 or remote_key(actual.stdout) != remote_key(repo_url):
        raise MigrationError(f"{label} remote URL mismatch")


def assert_clean(path: Path, label: str) -> None:
    if git_output(path, "status", "--porcelain"):
        raise MigrationError(f"{label} checkout is dirty; refusing migration")


def assert_safe_paths(config: MigrationConfig) -> None:
    roots = {
        "prototype": config.prototype_checkout.resolve(),
        "implementation": config.implementation_checkout.resolve(),
        "queue": config.queue_checkout.resolve(),
    }
    if len(set(roots.values())) != 3:
        raise MigrationError("prototype, implementation, and queue checkouts must be distinct")
    items = list(roots.items())
    for index, (name, path) in enumerate(items):
        try:
            ensure_path_allowed(str(path))
        except SafetyViolation as exc:
            raise MigrationError(f"{name} checkout is protected: {exc}") from exc
        for other_name, other in items[index + 1 :]:
            if path.is_relative_to(other) or other.is_relative_to(path):
                raise MigrationError(f"{name} and {other_name} checkouts must not be nested")
        if config.report_path.resolve().is_relative_to(path):
            raise MigrationError(f"migration report must stay outside the {name} checkout")
    try:
        ensure_path_allowed(str(config.report_path.resolve()))
    except SafetyViolation as exc:
        raise MigrationError(f"migration report is protected: {exc}") from exc


def json_metadata(raw: bytes) -> tuple[str | None, str | None, str | None]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, None, None
    if not isinstance(value, Mapping):
        return None, None, None
    values = []
    for key in ("id", "version", "action"):
        item = value.get(key)
        values.append(item if isinstance(item, str) else None)
    return values[0], values[1], values[2]


def inventory(repo: Path, relative: str) -> list[InventoryEntry]:
    root = repo / relative
    if not root.exists():
        return []
    entries: list[InventoryEntry] = []
    seen: dict[str, str] = {}
    for path in sorted(root.glob("*.json")):
        raw = path.read_bytes()
        logical_id, version, action = json_metadata(raw)
        relative_path = path.relative_to(repo).as_posix()
        if logical_id:
            previous = seen.get(logical_id)
            if previous is not None and previous != relative_path:
                raise MigrationError(
                    f"duplicate logical id {logical_id!r} in {previous!r} and {relative_path!r}"
                )
            seen[logical_id] = relative_path
        entries.append(
            InventoryEntry(
                path=relative_path,
                sha256=hashlib.sha256(raw).hexdigest(),
                bytes=len(raw),
                logical_id=logical_id,
                version=version,
                action=action,
            )
        )
    return entries


def assert_inventory_equal(
    expected: Sequence[InventoryEntry],
    actual: Sequence[InventoryEntry],
    label: str,
) -> None:
    left = {entry.path: entry for entry in expected}
    right = {entry.path: entry for entry in actual}
    if set(left) != set(right):
        raise MigrationError(
            f"{label} inventory path mismatch; "
            f"missing={sorted(set(left) - set(right))}, "
            f"extra={sorted(set(right) - set(left))}"
        )
    changed = [
        path
        for path in sorted(left)
        if (left[path].sha256, left[path].bytes)
        != (right[path].sha256, right[path].bytes)
    ]
    if changed:
        raise MigrationError(f"{label} inventory byte mismatch: {changed}")


def legacy_conversion_plan(
    requests: Sequence[InventoryEntry],
    results: Sequence[InventoryEntry],
) -> list[dict[str, Any]]:
    completed_ids = {
        entry.logical_id or Path(entry.path).stem
        for entry in results
    }
    output: list[dict[str, Any]] = []
    for entry in requests:
        request_id = entry.logical_id or Path(entry.path).stem
        if entry.version != "pc_relay.request.v1" or request_id in completed_ids:
            continue
        output.append(
            {
                "id": request_id,
                "source_path": entry.path,
                "source_sha256": entry.sha256,
                "action": entry.action,
                "required_action": (
                    "manually convert semantic action/params to pc_relay.request.v2 "
                    "and review the new request_sha256"
                ),
            }
        )
    return output


def atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def report_identity(value: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(
        value.get(key)
        for key in (
            "repo_url",
            "prototype_ref",
            "prototype_remote_sha",
            "implementation_ref",
            "expected_implementation_sha",
            "queue_ref",
        )
    )


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise MigrationError("existing migration report is unreadable") from exc
        if (
            not isinstance(existing, Mapping)
            or existing.get("version") != VERSION
            or report_identity(existing) != report_identity(report)
        ):
            raise MigrationError(
                "existing migration report belongs to a different migration snapshot"
            )
    atomic_json(path, report)


def validate_heartbeat(value: Mapping[str, Any], config: MigrationConfig) -> None:
    fields = {
        "version",
        "relay_alive",
        "queue_reachable",
        "executor_available",
        "queue_integrity",
        "last_processed_request",
        "implementation_sha",
        "queue_ref",
        "queue_remote_sha",
        "generated_at",
    }
    if set(value) != fields or value.get("version") != "pc_relay.heartbeat.v1":
        raise MigrationError("migration heartbeat schema/version mismatch")
    if (
        value.get("relay_alive") is not True
        or value.get("queue_reachable") is not True
        or value.get("executor_available") is not True
    ):
        raise MigrationError("migration heartbeat health check failed")
    if value.get("queue_integrity") != "ok":
        raise MigrationError(
            f"migration heartbeat queue integrity is {value.get('queue_integrity')!r}"
        )
    if value.get("implementation_sha") != config.expected_implementation_sha:
        raise MigrationError("migration heartbeat implementation SHA mismatch")
    if value.get("queue_ref") != config.queue_ref:
        raise MigrationError("migration heartbeat queue ref mismatch")
    if value.get("last_processed_request") is not None:
        raise MigrationError("health-only preflight unexpectedly processed a request")
    queue_sha = value.get("queue_remote_sha")
    if not isinstance(queue_sha, str) or len(queue_sha) != 40:
        raise MigrationError("migration heartbeat queue_remote_sha is invalid")


def default_health_preflight(config: MigrationConfig) -> dict[str, Any]:
    command = [
        sys.executable,
        str(config.implementation_checkout / "tools" / "pc_relay.py"),
        "--implementation-repo",
        str(config.implementation_checkout),
        "--queue-repo",
        str(config.queue_checkout),
        "--queue-ref",
        config.queue_ref,
        "--heartbeat-id",
        HEARTBEAT_ID,
        "--once",
        "--health-only",
    ]
    run_command(command, config.implementation_checkout)
    path = (
        config.queue_checkout
        / "relay"
        / "heartbeat"
        / f"{HEARTBEAT_ID}.json"
    )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MigrationError(
            "hardened relay did not publish a valid migration heartbeat"
        ) from exc
    if not isinstance(value, dict):
        raise MigrationError("migration heartbeat must be an object")
    return value


class Migrator:
    def __init__(
        self,
        config: MigrationConfig,
        *,
        emit: Callable[[str], None] = print,
        health_preflight: Callable[[MigrationConfig], Mapping[str, Any]]
        = default_health_preflight,
    ) -> None:
        self.config = config
        self.emit = emit
        self.health_preflight = health_preflight

    def inspect_prototype(
        self,
    ) -> tuple[str, list[InventoryEntry], list[InventoryEntry]]:
        config = self.config
        assert_repo(
            config.prototype_checkout,
            "prototype",
            config.remote,
            config.repo_url,
        )
        assert_clean(config.prototype_checkout, "prototype")
        local_sha = git_output(config.prototype_checkout, "rev-parse", "HEAD")
        remote_sha = (
            ls_remote(config.repo_url, config.prototype_ref)
            if config.plan
            else fetch_ref(
                config.prototype_checkout,
                config.remote,
                config.prototype_ref,
            )
        )
        if remote_sha is None:
            raise MigrationError(
                f"prototype ref does not exist: {config.prototype_ref}"
            )
        if local_sha != remote_sha:
            raise MigrationError(
                "prototype local/remote SHA mismatch: "
                f"local={local_sha}, remote={remote_sha}"
            )
        return (
            local_sha,
            inventory(config.prototype_checkout, "relay/requests"),
            inventory(config.prototype_checkout, "relay/results"),
        )

    def prepare_implementation(self) -> str:
        config = self.config
        remote_sha = ls_remote(config.repo_url, config.implementation_ref)
        if remote_sha != config.expected_implementation_sha:
            raise MigrationError(
                "wrong expected implementation SHA: "
                f"argument={config.expected_implementation_sha}, remote={remote_sha}"
            )
        if config.plan:
            if config.implementation_checkout.exists():
                assert_repo(
                    config.implementation_checkout,
                    "implementation",
                    config.remote,
                    config.repo_url,
                )
                assert_clean(config.implementation_checkout, "implementation")
            else:
                self.emit(
                    "PLAN: clone implementation checkout "
                    f"{config.implementation_checkout} at "
                    f"{config.expected_implementation_sha}"
                )
            return config.expected_implementation_sha

        created = not config.implementation_checkout.exists()
        if created:
            config.implementation_checkout.parent.mkdir(
                parents=True, exist_ok=True
            )
            run_command(
                [
                    "git",
                    "clone",
                    "-o",
                    config.remote,
                    "--no-checkout",
                    config.repo_url,
                    str(config.implementation_checkout),
                ]
            )
        assert_repo(
            config.implementation_checkout,
            "implementation",
            config.remote,
            config.repo_url,
        )
        if not created:
            assert_clean(config.implementation_checkout, "implementation")
        fetched = fetch_ref(
            config.implementation_checkout,
            config.remote,
            config.implementation_ref,
        )
        if fetched != config.expected_implementation_sha:
            raise MigrationError("implementation ref changed during migration")

        current = git(
            config.implementation_checkout,
            "rev-parse",
            "HEAD",
            check=False,
        )
        if (
            current.returncode != 0
            or current.stdout.strip() != config.expected_implementation_sha
        ):
            branch = git(
                config.implementation_checkout,
                "symbolic-ref",
                "--short",
                "-q",
                "HEAD",
                check=False,
            ).stdout.strip()
            if (
                not created
                and branch
                and branch != config.implementation_ref
            ):
                raise MigrationError(
                    f"implementation checkout is on unexpected branch {branch!r}"
                )
            git(
                config.implementation_checkout,
                "checkout",
                "--detach",
                config.expected_implementation_sha,
            )
        assert_clean(config.implementation_checkout, "implementation")
        return config.expected_implementation_sha

    def prepare_queue_ref(self, prototype_sha: str) -> str:
        config = self.config
        queue_sha = ls_remote(config.repo_url, config.queue_ref)
        if config.plan:
            operation = "create" if queue_sha is None else "reuse"
            self.emit(
                f"PLAN: {operation} queue ref {config.queue_ref} "
                f"at {queue_sha or prototype_sha}"
            )
            return queue_sha or prototype_sha

        if queue_sha is None:
            push = git(
                config.prototype_checkout,
                "push",
                config.remote,
                f"{prototype_sha}:refs/heads/{config.queue_ref}",
                check=False,
            )
            queue_sha = ls_remote(config.repo_url, config.queue_ref)
            if queue_sha is None:
                detail = (push.stderr or push.stdout).strip()
                raise MigrationError(
                    f"failed to create queue ref without force: {detail}"
                )
        return queue_sha

    def prepare_queue_checkout(self, prototype_sha: str) -> str:
        config = self.config
        if config.plan:
            if config.queue_checkout.exists():
                assert_repo(
                    config.queue_checkout,
                    "queue",
                    config.remote,
                    config.repo_url,
                )
                assert_clean(config.queue_checkout, "queue")
                branch = git(
                    config.queue_checkout,
                    "symbolic-ref",
                    "--short",
                    "-q",
                    "HEAD",
                    check=False,
                ).stdout.strip()
                if branch and branch != config.queue_ref:
                    raise MigrationError(
                        f"queue checkout is on unexpected branch {branch!r}"
                    )
            else:
                self.emit(
                    f"PLAN: create dedicated queue checkout at "
                    f"{config.queue_checkout}"
                )
            return ls_remote(config.repo_url, config.queue_ref) or prototype_sha

        created = not config.queue_checkout.exists()
        if created:
            config.queue_checkout.parent.mkdir(parents=True, exist_ok=True)
            run_command(
                [
                    "git",
                    "clone",
                    "-o",
                    config.remote,
                    "--no-checkout",
                    config.repo_url,
                    str(config.queue_checkout),
                ]
            )
        assert_repo(
            config.queue_checkout,
            "queue",
            config.remote,
            config.repo_url,
        )
        if not created:
            assert_clean(config.queue_checkout, "queue")
        remote_sha = fetch_ref(
            config.queue_checkout,
            config.remote,
            config.queue_ref,
        )
        branch = git(
            config.queue_checkout,
            "symbolic-ref",
            "--short",
            "-q",
            "HEAD",
            check=False,
        ).stdout.strip()
        if not created and branch and branch != config.queue_ref:
            raise MigrationError(
                f"queue checkout is on unexpected branch {branch!r}"
            )
        if created:
            git(
                config.queue_checkout,
                "checkout",
                "-B",
                config.queue_ref,
                f"{config.remote}/{config.queue_ref}",
            )
        else:
            local = git(
                config.queue_checkout,
                "rev-parse",
                "HEAD",
                check=False,
            )
            if local.returncode != 0:
                git(
                    config.queue_checkout,
                    "checkout",
                    "-B",
                    config.queue_ref,
                    f"{config.remote}/{config.queue_ref}",
                )
            elif local.stdout.strip() != remote_sha:
                if (
                    git(
                        config.queue_checkout,
                        "merge-base",
                        "--is-ancestor",
                        local.stdout.strip(),
                        remote_sha,
                        check=False,
                    ).returncode
                    != 0
                ):
                    raise MigrationError(
                        "queue checkout has local divergence; "
                        "refusing rewrite or force-push"
                    )
                git(
                    config.queue_checkout,
                    "merge",
                    "--ff-only",
                    remote_sha,
                )
        assert_clean(config.queue_checkout, "queue")
        if (
            git(
                config.queue_checkout,
                "merge-base",
                "--is-ancestor",
                prototype_sha,
                remote_sha,
                check=False,
            ).returncode
            != 0
        ):
            raise MigrationError(
                f"pre-existing queue ref {config.queue_ref} does not "
                f"descend from frozen prototype SHA {prototype_sha}"
            )
        return remote_sha

    def live_command(self) -> str:
        config = self.config
        executable = "py" if os.name == "nt" else sys.executable
        parts = [
            executable,
            str(config.implementation_checkout / "tools" / "pc_relay.py"),
            "--implementation-repo",
            str(config.implementation_checkout),
            "--queue-repo",
            str(config.queue_checkout),
            "--queue-ref",
            config.queue_ref,
            "--live",
        ]
        if os.name == "nt":
            return subprocess.list2cmdline(parts)
        return shlex.join(parts)

    def run(self) -> MigrationOutcome:
        config = self.config
        assert_safe_paths(config)
        if (
            len(config.expected_implementation_sha) != 40
            or any(
                ch not in "0123456789abcdef"
                for ch in config.expected_implementation_sha
            )
        ):
            raise MigrationError(
                "expected implementation SHA must be exact lowercase "
                "40-character Git SHA"
            )

        prototype_sha, requests, results = self.inspect_prototype()
        conversion_plan = legacy_conversion_plan(requests, results)
        self.emit(
            f"prototype snapshot sha={prototype_sha} "
            f"requests={len(requests)} results={len(results)}"
        )
        if conversion_plan:
            self.emit("legacy v1 conversion plan:")
            for item in conversion_plan:
                self.emit(
                    f"CONVERT v1 {item['id']} {item['source_path']} "
                    f"sha256:{item['source_sha256']}"
                )

        implementation_sha = self.prepare_implementation()
        self.prepare_queue_ref(prototype_sha)
        queue_sha = self.prepare_queue_checkout(prototype_sha)

        report: dict[str, Any] = {
            "version": VERSION,
            "generated_at": utc_now(),
            "plan_only": config.plan,
            "repo_url": config.repo_url,
            "remote": config.remote,
            "prototype_ref": config.prototype_ref,
            "prototype_local_sha": prototype_sha,
            "prototype_remote_sha": prototype_sha,
            "implementation_ref": config.implementation_ref,
            "expected_implementation_sha": config.expected_implementation_sha,
            "queue_ref": config.queue_ref,
            "queue_remote_sha": queue_sha,
            "prototype_requests": [asdict(entry) for entry in requests],
            "prototype_results": [asdict(entry) for entry in results],
            "legacy_v1_conversion_plan": conversion_plan,
        }

        if config.plan:
            self.emit(f"PLAN: write migration report {config.report_path}")
            self.emit(
                "PLAN: verify request/result bytes; run relay "
                "--once --health-only; validate heartbeat"
            )
            if conversion_plan:
                self.emit(
                    "PLAN BLOCKED: unresolved legacy v1 requests require "
                    "manual conversion"
                )
                live = None
            else:
                live = self.live_command()
                self.emit(
                    f"PLAN final live command (not executed): {live}"
                )
            return MigrationOutcome(
                passed=not conversion_plan,
                prototype_sha=prototype_sha,
                implementation_sha=implementation_sha,
                queue_sha=queue_sha,
                request_count=len(requests),
                result_count=len(results),
                unresolved_legacy_v1_count=len(conversion_plan),
                live_command=live,
            )

        assert_inventory_equal(
            requests,
            inventory(config.queue_checkout, "relay/requests"),
            "request",
        )
        assert_inventory_equal(
            results,
            inventory(config.queue_checkout, "relay/results"),
            "result",
        )
        write_report(config.report_path, report)

        heartbeat = dict(self.health_preflight(config))
        validate_heartbeat(heartbeat, config)
        assert_inventory_equal(
            results,
            inventory(config.queue_checkout, "relay/results"),
            "post-preflight result",
        )

        report.update(
            {
                "heartbeat": heartbeat,
                "queue_remote_sha_after_preflight": ls_remote(
                    config.repo_url,
                    config.queue_ref,
                ),
                "verified_at": utc_now(),
                "result_inventory_verified": True,
                "live_cutover_ready": not conversion_plan,
            }
        )
        write_report(config.report_path, report)

        if conversion_plan:
            self.emit(
                "MIGRATION PRECHECKS PASSED, LIVE CUTOVER BLOCKED: "
                "convert unresolved legacy v1 requests and rerun; "
                "no live command emitted."
            )
            return MigrationOutcome(
                passed=False,
                prototype_sha=prototype_sha,
                implementation_sha=implementation_sha,
                queue_sha=queue_sha,
                request_count=len(requests),
                result_count=len(results),
                unresolved_legacy_v1_count=len(conversion_plan),
                live_command=None,
            )

        live = self.live_command()
        self.emit("MIGRATION CHECKS PASS. Live relay was NOT started.")
        self.emit(f"FINAL LIVE START COMMAND: {live}")
        return MigrationOutcome(
            passed=True,
            prototype_sha=prototype_sha,
            implementation_sha=implementation_sha,
            queue_sha=queue_sha,
            request_count=len(requests),
            result_count=len(results),
            unresolved_legacy_v1_count=0,
            live_command=live,
        )


def default_report_path() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA") or Path.home())
    else:
        root = Path(
            os.environ.get("XDG_STATE_HOME")
            or Path.home() / ".local" / "state"
        )
    return root / "pc-relay-hardening" / "migration-report.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Zero-loss prototype-to-hardened PC relay migration helper"
        )
    )
    parser.add_argument(
        "--prototype-checkout",
        default=r"E:\pc-github-relay",
    )
    parser.add_argument(
        "--implementation-checkout",
        default=r"E:\pc-relay-hardening",
    )
    parser.add_argument(
        "--queue-checkout",
        default=r"E:\pc-relay-queue",
    )
    parser.add_argument("--repo-url", default=REPO_URL)
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--prototype-ref", default=PROTOTYPE_REF)
    parser.add_argument("--implementation-ref", default=IMPLEMENTATION_REF)
    parser.add_argument("--queue-ref", default=QUEUE_REF)
    parser.add_argument(
        "--expected-implementation-sha",
        required=True,
        help="exact 40-character CI-proven agent/pc-relay-hardening SHA",
    )
    parser.add_argument(
        "--report",
        default=str(default_report_path()),
    )
    parser.add_argument(
        "--plan",
        "--dry-run",
        dest="plan",
        action="store_true",
        help="print intended operations and mutate nothing",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    config = MigrationConfig(
        prototype_checkout=Path(args.prototype_checkout).expanduser().resolve(),
        implementation_checkout=Path(
            args.implementation_checkout
        ).expanduser().resolve(),
        queue_checkout=Path(args.queue_checkout).expanduser().resolve(),
        repo_url=args.repo_url,
        remote=args.remote,
        prototype_ref=args.prototype_ref,
        implementation_ref=args.implementation_ref,
        queue_ref=args.queue_ref,
        expected_implementation_sha=args.expected_implementation_sha,
        report_path=Path(args.report).expanduser().resolve(),
        plan=args.plan,
    )
    try:
        outcome = Migrator(config).run()
    except MigrationError as exc:
        print(f"MIGRATION FAILED: {exc}", file=sys.stderr)
        return 2
    return 0 if outcome.passed else 3


if __name__ == "__main__":
    raise SystemExit(main())
