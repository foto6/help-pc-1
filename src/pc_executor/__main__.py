from __future__ import annotations

import argparse
import json
import sys

from .audit import JsonlAuditSink
from .executor import Executor
from .models import ActionRequest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safe Windows PC executor")
    parser.add_argument("--live", action="store_true", help="execute side effects; default is dry-run")
    parser.add_argument("--allow-coordinate-fallback", action="store_true")
    parser.add_argument("--audit-jsonl", default=None)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    audit = JsonlAuditSink(args.audit_jsonl) if args.audit_jsonl else None
    executor = Executor(
        dry_run=not args.live,
        allow_coordinate_fallback=args.allow_coordinate_fallback,
        audit=audit,
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
