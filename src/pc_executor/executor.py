from __future__ import annotations

from typing import Any, Callable, TypeVar

from .audit import AuditSink, InMemoryAuditSink
from .cancellation import CancellationToken, run_bounded
from .capabilities import build_capabilities
from .capture import PillowScreenCapture, ScreenshotProvider, screenshot_payload
from .errors import ExecutorError, ExecutorFailureError, PolicyBlockedError
from .input import InputAdapter, WindowsInputAdapter
from .models import ActionRequest, ActionResult, AuditEvent, ElementQuery, utc_now_iso
from .outcome import ActionOutcomeEvidence, SIDE_EFFECTING_ACTIONS
from .outcome_journal import (
    ExecutionCorrelation,
    LOOKUP_CONTRACT_VERSION,
    SOURCE as OUTCOME_JOURNAL_SOURCE,
    OutcomeJournal,
    OutcomeJournalError,
)
from .preflight import (
    PreflightRequest,
    PreflightResult,
    PreflightValidationError,
    evaluate_preflight,
    invalid_result,
)
from .safety import SafetyViolation, ensure_not_sensitive_text
from .shell import SafeShellAdapter
from .uia import AccessibilityAdapter, WindowsUIAutomationAdapter
from .vision_target import GroundedTargetContractError, parse_grounded_target_v1
from .windows import Win32WindowEnumerator, WindowEnumerator

T = TypeVar("T")


class _OutcomeTracker:
    def __init__(self, action: str) -> None:
        self.side_effecting = action in SIDE_EFFECTING_ACTIONS
        self.dispatch_started = False
        self.completed = False
        self.correlation: ExecutionCorrelation | None = None
        self.journal_blocked = False

    def mark_dispatch(
        self,
        correlation: ExecutionCorrelation | None = None,
    ) -> None:
        self.dispatch_started = True
        self.correlation = correlation

    def mark_completed(self) -> None:
        self.completed = True


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
        outcome_journal: OutcomeJournal | None = None,
        dry_run: bool = True,
        allow_coordinate_fallback: bool = False,
        operation_timeout_seconds: float = 5.0,
    ) -> None:
        self.screenshot = screenshot or PillowScreenCapture()
        self.windows = windows or Win32WindowEnumerator()
        self.accessibility = accessibility or WindowsUIAutomationAdapter()
        self.input = input_adapter or WindowsInputAdapter()
        self.shell = shell or SafeShellAdapter()
        self.audit = audit or InMemoryAuditSink()
        self.outcome_journal = outcome_journal
        self.dry_run = dry_run
        self.allow_coordinate_fallback = allow_coordinate_fallback
        self.operation_timeout_seconds = operation_timeout_seconds

    def capabilities_snapshot(self) -> dict[str, Any]:
        return build_capabilities(
            screenshot=self.screenshot,
            windows=self.windows,
            accessibility=self.accessibility,
            input_adapter=self.input,
            shell=self.shell,
            outcome_journal_configured=self.outcome_journal is not None,
            dry_run_default=self.dry_run,
            allow_coordinate_fallback=self.allow_coordinate_fallback,
            operation_timeout_seconds=self.operation_timeout_seconds,
        )

    def preflight(self, payload: Any) -> PreflightResult:
        capabilities = self.capabilities_snapshot()
        digest = capabilities["attestation"]["digest"]
        default_deadline_ms = max(1, int(self.operation_timeout_seconds * 1000))
        try:
            request = PreflightRequest.from_dict(payload)
        except PreflightValidationError as exc:
            return invalid_result(
                payload,
                capabilities_digest=digest,
                default_deadline_ms=default_deadline_ms,
                message=str(exc),
            )
        return evaluate_preflight(
            request,
            capabilities=capabilities,
            accessibility=self.accessibility,
            input_adapter=self.input,
            shell=self.shell,
            default_timeout_ms=default_deadline_ms,
            allow_coordinate_fallback=self.allow_coordinate_fallback,
        )

    def execute(
        self,
        request: ActionRequest,
        *,
        cancellation: CancellationToken | None = None,
    ) -> ActionResult:
        started = utc_now_iso()
        effective_dry_run = self.dry_run if request.dry_run is None else bool(request.dry_run)
        token = cancellation or CancellationToken()
        tracker = _OutcomeTracker(request.action)
        self._audit(request, "start", effective_dry_run)
        try:
            self._journal_preflight(request, tracker)
            token.raise_if_cancelled()
            data = self._dispatch(request, effective_dry_run, token, tracker)
            outcome_evidence = self._outcome_evidence(
                request,
                tracker,
                dry_run=effective_dry_run,
                success=True,
            )
            self._persist_terminal_outcome(
                outcome_evidence,
                tracker,
                raise_on_failure=True,
            )
            result = ActionResult(
                request_id=request.request_id,
                action=request.action,
                ok=True,
                status="dry_run" if effective_dry_run else "completed",
                started_at=started,
                finished_at=utc_now_iso(),
                data=data,
                dry_run=effective_dry_run,
                outcome_evidence=outcome_evidence,
            )
            audit_details = dict(data)
            if outcome_evidence is not None:
                audit_details["outcome_evidence"] = outcome_evidence.to_dict()
            self._audit(
                request,
                "finish",
                effective_dry_run,
                outcome=result.status,
                details=audit_details,
            )
            return result
        except SafetyViolation as exc:
            return self._error_result(
                request,
                started,
                effective_dry_run,
                PolicyBlockedError(str(exc)),
                tracker,
            )
        except ExecutorError as exc:
            return self._error_result(
                request,
                started,
                effective_dry_run,
                exc,
                tracker,
            )
        except (KeyError, TypeError, ValueError) as exc:
            return self._error_result(
                request,
                started,
                effective_dry_run,
                PolicyBlockedError(f"invalid request: {exc}"),
                tracker,
            )
        except Exception as exc:
            return self._error_result(
                request,
                started,
                effective_dry_run,
                ExecutorFailureError(f"{type(exc).__name__}: {exc}"),
                tracker,
            )

    def _error_result(
        self,
        request: ActionRequest,
        started: str,
        dry_run: bool,
        exc: ExecutorError,
        tracker: _OutcomeTracker,
    ) -> ActionResult:
        status = {
            "policy_blocked": "blocked",
            "executor_failure": "error",
        }.get(exc.kind, exc.kind)
        outcome_evidence = self._outcome_evidence(
            request,
            tracker,
            dry_run=dry_run,
            success=False,
            error_kind=exc.kind,
        )
        journal_error = self._persist_terminal_outcome(
            outcome_evidence,
            tracker,
            raise_on_failure=False,
        )
        result = ActionResult(
            request_id=request.request_id,
            action=request.action,
            ok=False,
            status=status,
            started_at=started,
            finished_at=utc_now_iso(),
            error=str(exc),
            error_kind=exc.kind,
            dry_run=dry_run,
            outcome_evidence=outcome_evidence,
        )
        details = {"error": result.error, "error_kind": result.error_kind}
        if outcome_evidence is not None:
            details["outcome_evidence"] = outcome_evidence.to_dict()
        if journal_error is not None:
            details["outcome_journal_error"] = journal_error
        self._audit(
            request,
            "finish",
            dry_run,
            outcome=status,
            details=details,
        )
        return result

    def read_outcome_evidence(
        self,
        *,
        request_id: str,
        action: str,
        execution_attempt: int | None = None,
    ) -> dict[str, Any]:
        if self.outcome_journal is None:
            return {
                "contract_version": LOOKUP_CONTRACT_VERSION,
                "source": OUTCOME_JOURNAL_SOURCE,
                "request_id": request_id,
                "requestId": request_id,
                "action": action,
                "execution_attempt": execution_attempt,
                "outcome": "unknown",
                "reason": "journal_not_configured",
                "replay_authorized": False,
                "latest_valid_evidence": None,
                "latest_valid_record": None,
                "history": [],
                "provenance": {
                    "record_contract_version": None,
                    "total_valid_records": 0,
                    "matched_records": 0,
                    "journal_sha256": None,
                    "integrity": "unavailable",
                    "corruption": None,
                },
            }
        return self.outcome_journal.lookup(
            request_id=request_id,
            action=action,
            execution_attempt=execution_attempt,
        ).to_dict()

    def _journal_preflight(
        self,
        request: ActionRequest,
        tracker: _OutcomeTracker,
    ) -> None:
        if not tracker.side_effecting or self.outcome_journal is None:
            return
        try:
            self.outcome_journal.preflight_new_attempt(
                request_id=request.request_id,
                action=request.action,
            )
        except OutcomeJournalError as exc:
            tracker.journal_blocked = True
            raise PolicyBlockedError(
                f"outcome journal blocked side-effect attempt: {exc}"
            ) from exc

    def _persist_terminal_outcome(
        self,
        evidence: ActionOutcomeEvidence | None,
        tracker: _OutcomeTracker,
        *,
        raise_on_failure: bool,
    ) -> str | None:
        if (
            evidence is None
            or self.outcome_journal is None
            or tracker.journal_blocked
        ):
            return None
        try:
            self.outcome_journal.append_terminal(
                evidence,
                correlation=tracker.correlation,
            )
            return None
        except OutcomeJournalError as exc:
            tracker.journal_blocked = True
            if raise_on_failure:
                raise ExecutorFailureError(
                    f"outcome journal terminal persistence failed: {exc}"
                ) from exc
            return f"{type(exc).__name__}: {exc}"

    def _outcome_evidence(
        self,
        request: ActionRequest,
        tracker: _OutcomeTracker,
        *,
        dry_run: bool,
        success: bool,
        error_kind: str | None = None,
    ) -> ActionOutcomeEvidence | None:
        if not tracker.side_effecting:
            return None
        if dry_run:
            state = "not_started"
            reason = "dry_run" if success else (error_kind or "executor_failure")
        elif success and tracker.completed:
            state, reason = "completed", "completed"
        elif not tracker.dispatch_started:
            state, reason = "not_started", error_kind or "executor_failure"
        elif error_kind in {"stale_target", "ambiguous_target", "policy_blocked"}:
            state, reason = "not_started", error_kind
        else:
            state, reason = "unknown", error_kind or "executor_failure"
        return ActionOutcomeEvidence.create(
            request_id=request.request_id,
            action=request.action,
            effect_state=state,
            dispatch_started=tracker.dispatch_started,
            reason=reason,
        )

    def _effectful(
        self,
        request: ActionRequest,
        dry_run: bool,
        tracker: _OutcomeTracker,
        operation: Callable[[], T],
    ) -> T:
        provisional = ActionOutcomeEvidence.create(
            request_id=request.request_id,
            action=request.action,
            effect_state="unknown",
            dispatch_started=True,
            reason="dispatch_started",
        )
        correlation = None
        if self.outcome_journal is not None:
            try:
                correlation = self.outcome_journal.start_dispatch(provisional)
            except OutcomeJournalError as exc:
                tracker.journal_blocked = True
                raise PolicyBlockedError(
                    f"outcome journal blocked side-effect dispatch: {exc}"
                ) from exc
        tracker.mark_dispatch(correlation)
        self._audit(
            request,
            "effect_dispatch",
            dry_run,
            outcome="unknown",
            details={
                "outcome_evidence": provisional.to_dict(),
                "execution_correlation": (
                    correlation.to_dict() if correlation is not None else None
                ),
            },
        )
        result = operation()
        tracker.mark_completed()
        return result

    def _bounded_effectful(
        self,
        request: ActionRequest,
        dry_run: bool,
        token: CancellationToken,
        tracker: _OutcomeTracker,
        label: str,
        operation: Callable[[], T],
    ) -> T:
        return self._effectful(
            request,
            dry_run,
            tracker,
            lambda: self._bounded(request, token, label, operation),
        )

    def _timeout(self, request: ActionRequest) -> float:
        if request.timeout_ms is None:
            return self.operation_timeout_seconds
        return request.timeout_ms / 1000.0

    def _bounded(
        self,
        request: ActionRequest,
        token: CancellationToken,
        label: str,
        operation: Callable[[], T],
    ) -> T:
        return run_bounded(
            operation,
            timeout_seconds=self._timeout(request),
            cancellation=token,
            label=label,
        )

    def _query(self, raw: object) -> ElementQuery:
        try:
            return ElementQuery.from_dict(dict(raw or {}))
        except (TypeError, ValueError) as exc:
            raise PolicyBlockedError(f"invalid UIA query: {exc}") from exc

    def _dispatch(
        self,
        request: ActionRequest,
        dry_run: bool,
        token: CancellationToken,
        tracker: _OutcomeTracker,
    ) -> dict[str, Any]:
        action = request.action
        p = request.params

        if action == "capabilities.get":
            if p:
                raise PolicyBlockedError(
                    "capabilities.get does not accept parameters"
                )
            return {"capabilities": self.capabilities_snapshot()}

        if action == "action.preflight":
            return {"preflight": self.preflight(p).to_dict()}

        if action == "outcome.lookup":
            target_request_id = p.get("request_id")
            target_action = p.get("action")
            execution_attempt = p.get("execution_attempt")
            if not isinstance(target_request_id, str) or not target_request_id:
                raise PolicyBlockedError(
                    "outcome.lookup request_id must be a non-empty string"
                )
            if not isinstance(target_action, str) or not target_action:
                raise PolicyBlockedError(
                    "outcome.lookup action must be a non-empty string"
                )
            if execution_attempt is not None and (
                isinstance(execution_attempt, bool)
                or not isinstance(execution_attempt, int)
                or execution_attempt <= 0
            ):
                raise PolicyBlockedError(
                    "outcome.lookup execution_attempt must be a positive integer"
                )
            return {
                "outcome_evidence": self.read_outcome_evidence(
                    request_id=target_request_id,
                    action=target_action,
                    execution_attempt=execution_attempt,
                )
            }

        if action == "screenshot.capture":
            if dry_run:
                return {"would_execute": action}
            png = self._bounded(request, token, action, self.screenshot.capture_png)
            return screenshot_payload(png)

        if action == "windows.list":
            if dry_run:
                return {"would_execute": action}
            windows = self._bounded(request, token, action, self.windows.list_windows)
            return {"windows": [window.to_dict() for window in windows]}

        if action == "uia.snapshot":
            window_title = p.get("window_title")
            if window_title is not None and not isinstance(window_title, str):
                raise PolicyBlockedError("uia.snapshot window_title must be a string or null")
            if dry_run:
                return {"would_execute": action, "window_title": window_title}
            snapshot = self._bounded(
                request,
                token,
                action,
                lambda: self.accessibility.snapshot(window_title=window_title),
            )
            return {"snapshot": snapshot.to_dict(), "canonical_json": snapshot.to_json()}

        if action == "vision.target.invoke":
            try:
                target = parse_grounded_target_v1(p.get("target"))
            except GroundedTargetContractError as exc:
                raise PolicyBlockedError(f"invalid vision target contract: {exc}") from exc
            automation_id = target.automation_id
            if "uia" not in target.sources or not automation_id or not automation_id.strip():
                raise PolicyBlockedError(
                    "vision target is not actionable through UIA; non-empty automation_id is required"
                )
            query = ElementQuery(automation_id=automation_id)
            if dry_run:
                return {"would_execute": action, "query": {"automation_id": automation_id}}
            element = self._bounded_effectful(
                request,
                dry_run,
                token,
                tracker,
                action,
                lambda: self.accessibility.invoke(query),
            )
            return {"element": element.to_dict()}

        if action.startswith("uia."):
            query = self._query(p.get("query"))
            if action == "uia.inspect":
                if dry_run:
                    return {"would_execute": action, "query": p.get("query", {})}
                element = self._bounded(request, token, action, lambda: self.accessibility.inspect(query))
                return {"element": element.to_dict()}
            if action == "uia.invoke":
                if dry_run:
                    return {"would_execute": action, "query": p.get("query", {})}
                element = self._bounded_effectful(
                    request,
                    dry_run,
                    token,
                    tracker,
                    action,
                    lambda: self.accessibility.invoke(query),
                )
                return {"element": element.to_dict()}
            if action == "uia.focus":
                if dry_run:
                    return {"would_execute": action, "query": p.get("query", {})}
                element = self._bounded_effectful(
                    request,
                    dry_run,
                    token,
                    tracker,
                    action,
                    lambda: self.accessibility.focus(query),
                )
                return {"element": element.to_dict()}
            if action == "uia.set_value":
                value = str(p.get("value", ""))
                sensitive = bool(p.get("sensitive", False))
                if sensitive:
                    raise PolicyBlockedError("credential/sensitive text entry is not supported")
                if dry_run:
                    return {"would_execute": action, "query": p.get("query", {}), "value_length": len(value)}
                element = self._bounded_effectful(
                    request,
                    dry_run,
                    token,
                    tracker,
                    action,
                    lambda: self.accessibility.set_value(
                        query,
                        value,
                        sensitive=sensitive,
                    ),
                )
                return {"element": element.to_dict(), "value_length": len(value)}
            raise PolicyBlockedError(f"unsupported UIA action: {action}")

        if action == "mouse.click":
            if not self.allow_coordinate_fallback:
                raise PolicyBlockedError("raw coordinate fallback is disabled; use UI Automation first")
            x, y = int(p["x"]), int(p["y"])
            button = str(p.get("button", "left"))
            if dry_run:
                return {"would_execute": action, "x": x, "y": y, "button": button}
            self._bounded_effectful(
                request,
                dry_run,
                token,
                tracker,
                action,
                lambda: self.input.click(x, y, button=button),
            )
            return {"x": x, "y": y, "button": button}

        if action == "keyboard.press":
            key = str(p["key"])
            if dry_run:
                return {"would_execute": action, "key": key}
            self._bounded_effectful(
                request,
                dry_run,
                token,
                tracker,
                action,
                lambda: self.input.press(key),
            )
            return {"key": key}

        if action == "keyboard.type_text":
            text = str(p.get("text", ""))
            sensitive = bool(p.get("sensitive", False))
            ensure_not_sensitive_text(is_password=False, sensitive=sensitive)
            if dry_run:
                return {"would_execute": action, "text_length": len(text)}
            self._bounded_effectful(
                request,
                dry_run,
                token,
                tracker,
                action,
                lambda: self.input.type_text(text),
            )
            return {"text_length": len(text)}

        if action == "clipboard.get":
            if dry_run:
                return {"would_execute": action}
            value = self._bounded(request, token, action, self.input.clipboard_get)
            return {"text": value}

        if action == "clipboard.set":
            value = str(p.get("text", ""))
            if bool(p.get("sensitive", False)):
                raise PolicyBlockedError("credential/sensitive clipboard entry is not supported")
            if dry_run:
                return {"would_execute": action, "text_length": len(value)}
            self._bounded_effectful(
                request,
                dry_run,
                token,
                tracker,
                action,
                lambda: self.input.clipboard_set(value),
            )
            return {"text_length": len(value)}

        if action == "shell.run":
            argv = [str(x) for x in p.get("argv", [])]
            cwd = p.get("cwd")
            validated = self.shell.validate(argv, cwd=cwd)
            if dry_run:
                return {"would_execute": action, "argv": validated, "cwd": cwd}
            result = self._effectful(
                request,
                dry_run,
                tracker,
                lambda: self.shell.run(
                    validated,
                    cwd=cwd,
                    timeout_seconds=self._timeout(request),
                    cancellation=token,
                ),
            )
            return result.to_dict()

        raise PolicyBlockedError(f"unsupported action: {action}")

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
