from __future__ import annotations

import argparse
import json
import sys

from .audit import JsonlAuditSink
from .executor import Executor
from .models import ActionRequest
from .ops_outcome import OpsOutcomeJournal
from .outcome_journal import OutcomeJournal


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safe Windows PC executor")
    parser.add_argument("--live", action="store_true", help="execute side effects; default is dry-run")
    parser.add_argument("--allow-coordinate-fallback", action="store_true")
    parser.add_argument("--audit-jsonl", default=None)
    parser.add_argument(
        "--outcome-journal",
        default=None,
        help=(
            "append-only legacy outcome journal path; live mode defaults to the "
            "platform state directory"
        ),
    )
    parser.add_argument(
        "--ops-outcome-journal",
        default=None,
        help=(
            "append-only structured-operations outcome journal path; live mode "
            "defaults to the platform state directory"
        ),
    )
    parser.add_argument(
        "--ops-state-dir",
        default=None,
        help="durable managed process/session state directory",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    audit = JsonlAuditSink(args.audit_jsonl) if args.audit_jsonl else None
    journal_path = args.outcome_journal
    if journal_path is None and args.live:
        journal_path = str(OutcomeJournal.default_path())
    outcome_journal = OutcomeJournal(journal_path) if journal_path else None
    ops_journal_path = args.ops_outcome_journal
    if ops_journal_path is None and args.live:
        ops_journal_path = str(OpsOutcomeJournal.default_path())
    ops_outcome_journal = (
        OpsOutcomeJournal(ops_journal_path) if ops_journal_path else None
    )
    executor = Executor(
        dry_run=not args.live,
        allow_coordinate_fallback=args.allow_coordinate_fallback,
        audit=audit,
        outcome_journal=outcome_journal,
        ops_outcome_journal=ops_outcome_journal,
        operations_state_root=args.ops_state_dir,
    )
    exit_code = 0
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
            request = ActionRequest.from_dict(raw)
            result = executor.execute(request)
            if not result.ok:
                exit_code = 1
            print(json.dumps(result.to_dict(), ensure_ascii=False), flush=True)
        except Exception as exc:
            exit_code = 2
            print(json.dumps({"ok": False, "status": "invalid_request", "error": str(exc)}), flush=True)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
