from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pc_relay.evidence as evidence_module
from pc_relay.evidence import (
    DEFAULT_MAX_AGE_SECONDS,
    DEFAULT_MAX_SNAPSHOT_BYTES,
    read_progress_evidence,
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read one atomic PC relay progress/liveness evidence envelope"
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="dedicated relay checkout containing .pc-relay/progress.v1.json",
    )
    parser.add_argument(
        "--observed-pid",
        action="append",
        default=[],
        type=int,
        help="already-observed matching relay PID; repeatable; reader never enumerates processes",
    )
    parser.add_argument("--expected-pid", type=int)
    parser.add_argument(
        "--max-age-seconds",
        type=float,
        default=DEFAULT_MAX_AGE_SECONDS,
    )
    parser.add_argument("--stall-seconds", type=float, default=15.0)
    parser.add_argument(
        "--max-snapshot-bytes",
        type=int,
        default=DEFAULT_MAX_SNAPSHOT_BYTES,
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    repo = Path(args.repo).resolve()
    progress_path = repo / ".pc-relay" / "progress.v1.json"
    script_path = Path(__file__).resolve()
    module_path = Path(evidence_module.__file__).resolve()

    envelope = read_progress_evidence(
        progress_path,
        reader_script_sha256=_sha256_file(script_path),
        evidence_module_sha256=_sha256_file(module_path),
        observed_pids=args.observed_pid if args.observed_pid else None,
        expected_pid=args.expected_pid,
        max_age_seconds=args.max_age_seconds,
        stall_seconds=args.stall_seconds,
        max_snapshot_bytes=args.max_snapshot_bytes,
    )
    print(
        json.dumps(
            envelope,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0 if envelope["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
