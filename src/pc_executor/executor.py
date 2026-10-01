from __future__ import annotations

from pathlib import Path
from time import monotonic
from typing import Any, Callable, TypeVar

from .audit import AuditSink, InMemoryAuditSink
from .cancellation import CancellationToken, run_bounded
from .capabilities import build_capabilities
from .context_binding import (
    ContextMismatchBlockedError,
    ExecutionContextBindingError,
    ExecutionContextObserver,
    SystemExecutionContextObserver,
    derive_execution_context_binding,
    validate_bound_execution_context,
)
from .capture import PillowScreenCapture, ScreenshotProvider, screenshot_payload
from .errors import (
    ExecutorError,
    ExecutorFailureError,
    OperationCancelledError,
    OperationTimeoutError,
    PolicyBlockedError,
)
from .input import InputAdapter, WindowsInputAdapter
from .models import ActionRequest, ActionResult, AuditEvent, ElementQuery, utc_now_iso
from .operations import (
    OPS_ACTIONS,
    OPS_SIDE_EFFECT_ACTIONS,
    LocalOperations,
    register_native_outcome_actions,
)
from .outcome import ActionOutcomeEvidence
from .outcome_journal import (
    ExecutionCorrelation,
    LOOKUP_CONTRACT_VERSION,
    SOURCE as OUTCOME_JOURNAL_SOURCE,
    OutcomeJournal,
    OutcomeJournalError,
)
from .runtime_health import (
    CONTRACT_VERSION as RUNTIME_HEALTH_VERSION,
    DEFAULT_PROBE_TIMEOUT_SECONDS,
    RuntimeHealthMonitor,
    validate_runtime_health,
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

_REGISTERED_SIDE_EFFECTING_ACTIONS = register_native_outcome_actions()


_AUDIT_REDACT_KEYS = frozenset(
    {
        "text",
        "value",
        "content",
        "data_base64",
        "stdout",
        "stderr",
        "lines",
        "matches",
        "env",
        "old_text",
        "new_text",
    }
)


def _sanitize_audit_details(value: Any) -> Any:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).casefold() in _AUDIT_REDACT_KEYS:
                if isinstance(item, str):
                    output[str(key) + "_redacted_bytes"] = len(
                        item.encode("utf-8")
                    )
                else:
                    output[str(key) + "_redacted"] = True
            else:
                output[str(key)] = _sanitize_audit_details(item)
        return output
    if isinstance(value, list):
        return [_sanitize_audit_details(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_audit_details(item) for item in value]
    return value


class _OutcomeTracker:
    def __init__(self, action: str) -> None:
        self.side_effecting = action in _REGISTERED_SIDE_EFFECTING_ACTIONS
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
        operations: LocalOperations | None = None,
        operations_state_root: str | Path | None = None,
        audit: AuditSink | None = None,
        outcome_journal: OutcomeJournal | None = None,
        context_observer: ExecutionContextObserver | None = None,
        dry_run: bool = True,
        allow_coordinate_fallback: bool = False,
        operation_timeout_seconds: float = 5.0,
    ) -> None:
        self.screenshot = screenshot or PillowScreenCapture()
        self.windows = windows or Win32WindowEnumerator()
        self.accessibility = accessibility or WindowsUIAutomationAdapter()
        self.input = input_adapter or WindowsInputAdapter()
        self.shell = shell or SafeShellAdapter()
        self.operations = operations or LocalOperations(
            shell=self.shell,
            state_root=operations_state_root,
        )
        self.audit = audit or InMemoryAuditSink()
        self.outcome_journal = outcome_journal
        self.context_observer = context_observer or SystemExecutionContextObserver()
        self.dry_run = dry_run
        self.allow_coordinate_fallback = allow_coordinate_fallback
        self.operation_timeout_seconds = operation_timeout_seconds
        self.runtime_health = RuntimeHealthMonitor(
            operation_timeout_seconds=operation_timeout_seconds,
        )

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
        if request.action in OPS_ACTIONS:
            ops_capabilities = self.operations.capabilities_snapshot()
            ops_digest = ops_capabilities["attestation"]["digest"]
            deadline = request.timeout_ms or default_deadline_ms
            try:
                self.operations.preflight(request.action, request.params)
            except SafetyViolation as exc:
                return PreflightResult(
                    request_id=request.request_id,
                    action=request.action,
                    status="blocked",
                    executable=False,
                    capabilities_digest=ops_digest,
                    deadline_budget_ms=deadline,
                    reasons=(
                        {"code": "native_policy_blocked", "message": str(exc)},
                    ),
                )
            except (KeyError, TypeError, ValueError) as exc:
                return PreflightResult(
                    request_id=request.request_id,
                    action=request.action,
                    status="invalid_request",
                    executable=False,
                    capabilities_digest=ops_digest,
                    deadline_budget_ms=deadline,
                    reasons=(
                        {"code": "invalid_request", "message": str(exc)},
                    ),
                )
            return PreflightResult(
                request_id=request.request_id,
                action=request.action,
                status="ready",
                executable=True,
                capabilities_digest=ops_digest,
                deadline_budget_ms=deadline,
                reasons=(
                    {
                        "code": "ready",
                        "message": "native operation preflight checks passed",
                    },
                ),
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

    def bind_execution_context(
        self,
        request: ActionRequest,
        *,
        capture_id: str | None = None,
        display_id: str | None = None,
    ) -> dict[str, Any]:
        return derive_execution_context_binding(
            request_id=request.request_id,
            action=request.action,
            params=request.params,
            accessibility=self.accessibility,
            shell_adapter=self.shell,
            observer=self.context_observer,
            capture_id=capture_id,
            display_id=display_id,
        ).to_dict()

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
            self._journal_preflight(request, tracker, dry_run=effective_dry_run)
            if (
                request.execution_context_binding is not None
                and not tracker.side_effecting
            ):
                raise PolicyBlockedError(
                    "execution_context_binding is only valid for side-effecting actions"
                )
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
            self._record_runtime_call(result)
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
        except UnicodeError as exc:
            return self._error_result(
                request,
                started,
                effective_dry_run,
                ExecutorFailureError(f"{type(exc).__name__}: {exc}"),
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
        error_data: dict[str, Any] = {}
        if isinstance(exc, ContextMismatchBlockedError):
            error_data["execution_context_validation"] = dict(
                exc.validation_evidence
            )
        result = ActionResult(
            request_id=request.request_id,
            action=request.action,
            ok=False,
            status=status,
            started_at=started,
            finished_at=utc_now_iso(),
            data=error_data,
            error=str(exc),
            error_kind=exc.kind,
            dry_run=dry_run,
            outcome_evidence=outcome_evidence,
        )
        details = {"error": result.error, "error_kind": result.error_kind}
        if error_data:
            details.update(error_data)
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
        self._record_runtime_call(result)
        return result

    def _record_runtime_call(self, result: ActionResult) -> None:
        if result.action.startswith("diagnostics.") or result.action.startswith("ops."):
            return
        recorder = getattr(self.operations, "record_runtime_call", None)
        if not callable(recorder):
            return
        evidence = result.outcome_evidence
        recorder(
            request_id=result.request_id,
            action=result.action,
            status=result.status,
            started_at=result.started_at,
            finished_at=result.finished_at,
            dry_run=result.dry_run,
            effect_state=(evidence.effect_state if evidence is not None else None),
        )

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
        *,
        dry_run: bool,
    ) -> None:
        if not tracker.side_effecting or dry_run:
            return
        if (
            request.action in OPS_SIDE_EFFECT_ACTIONS
            and self.outcome_journal is None
        ):
            tracker.journal_blocked = True
            raise PolicyBlockedError(
                "native side-effect requires configured outcome journal"
            )
        if self.outcome_journal is None:
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

    def _validate_execution_context(
        self,
        request: ActionRequest,
    ) -> dict[str, Any] | None:
        binding = request.execution_context_binding
        if binding is None:
            return None
        try:
            return validate_bound_execution_context(
                request_id=request.request_id,
                action=request.action,
                params=request.params,
                binding_payload=binding,
                accessibility=self.accessibility,
                shell_adapter=self.shell,
                observer=self.context_observer,
            )
        except ContextMismatchBlockedError:
            raise
        except (
            ExecutionContextBindingError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise PolicyBlockedError(
                f"invalid execution_context_binding: {exc}"
            ) from exc

    def _effectful(
        self,
        request: ActionRequest,
        dry_run: bool,
        tracker: _OutcomeTracker,
        operation: Callable[[], T],
        *,
        token: CancellationToken | None = None,
    ) -> T:
        self._validate_execution_context(request)
        if token is not None:
            token.raise_if_cancelled()
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
            token=token,
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

    def _uia_diagnostics(self) -> dict[str, Any]:
        if isinstance(self.accessibility, WindowsUIAutomationAdapter):
            snapshot = getattr(self.accessibility, "diagnostics_snapshot", None)
            if callable(snapshot):
                value = snapshot()
                if isinstance(value, dict):
                    allowed = {
                        "operation",
                        "window_title_sha256",
                        "selector_fields",
                        "nodes_visited",
                        "current_depth",
                        "max_depth",
                        "max_nodes",
                        "target_process_id",
                        "target_window_handle",
                        "probe",
                        "root_process_id",
                        "root_window_handle",
                        "tree_walk_performed",
                    }
                    return {
                        key: value[key]
                        for key in sorted(allowed)
                        if key in value
                    }
        return {}

    def _adapter_bounded(
        self,
        adapter: str,
        request: ActionRequest,
        token: CancellationToken,
        label: str,
        operation: Callable[[], T],
    ) -> T:
        if adapter == "uia" and not self.runtime_health.operation_allowed("uia"):
            raise OperationTimeoutError(
                "UIA runtime circuit is open after repeated bounded timeouts"
            )
        try:
            result = self._bounded(request, token, label, operation)
        except OperationTimeoutError:
            self.runtime_health.record_failure(
                adapter,
                kind="timeout",
                diagnostics=self._uia_diagnostics() if adapter == "uia" else None,
            )
            raise
        except OperationCancelledError:
            self.runtime_health.record_failure(
                adapter,
                kind="cancelled",
                diagnostics=self._uia_diagnostics() if adapter == "uia" else None,
            )
            raise
        except ExecutorError:
            # Stale/ambiguous/policy failures describe a target/request, not a
            # runtime adapter outage. Keep the last runtime state truthful.
            raise
        except Exception as exc:
            self.runtime_health.record_failure(
                adapter,
                kind=type(exc).__name__,
                diagnostics=self._uia_diagnostics() if adapter == "uia" else None,
            )
            raise
        self.runtime_health.record_success(
            adapter,
            diagnostics=self._uia_diagnostics() if adapter == "uia" else None,
        )
        return result

    def _uia_call(
        self,
        method: str,
        request: ActionRequest,
        token: CancellationToken,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        target = getattr(self.accessibility, method)
        deadline = monotonic() + self._timeout(request)

        def invoke() -> Any:
            if isinstance(self.accessibility, WindowsUIAutomationAdapter):
                native_kwargs = dict(kwargs)
                native_kwargs["cancellation"] = token
                native_kwargs["deadline_monotonic"] = deadline
                return target(*args, **native_kwargs)
            return target(*args, **kwargs)

        return self._adapter_bounded("uia", request, token, f"uia.{method}", invoke)

    def _runtime_health_snapshot(
        self,
        *,
        cancellation: CancellationToken,
        budget_seconds: float,
    ) -> dict[str, Any]:
        started = monotonic()
        budget = max(0.01, min(float(budget_seconds), 2.0))
        deadline = started + budget
        generation_id = getattr(self.operations, "generation_id", None)
        capabilities = self.capabilities_snapshot()
        adapter_caps = capabilities.get("adapters", {})

        def available(name: str) -> bool:
            entry = adapter_caps.get(name)
            return bool(isinstance(entry, dict) and entry.get("available") is True)

        def provider(name: str, fallback: object | None = None) -> str:
            entry = adapter_caps.get(name)
            if isinstance(entry, dict) and isinstance(entry.get("provider"), str):
                return entry["provider"]
            if fallback is None:
                return "missing"
            return type(fallback).__name__

        def remaining() -> float:
            cancellation.raise_if_cancelled()
            return max(0.0, deadline - monotonic())

        def bounded_timeout() -> float:
            return max(
                0.001,
                min(DEFAULT_PROBE_TIMEOUT_SECONDS, remaining()),
            )

        def probe_uia(child: CancellationToken, probe_deadline: float) -> dict[str, Any]:
            if not isinstance(self.accessibility, WindowsUIAutomationAdapter):
                return {"probe": "not_available_for_injected_adapter"}
            return self.accessibility.health_probe(
                cancellation=child,
                deadline_monotonic=probe_deadline,
            )

        def probe_windows(child: CancellationToken, _probe_deadline: float) -> dict[str, Any]:
            child.raise_if_cancelled()
            rows = self.windows.list_windows()
            child.raise_if_cancelled()
            return {"window_count": len(rows), "window_metadata_emitted": False}

        journal_result: dict[str, Any] = {}
        def probe_journal(child: CancellationToken, _probe_deadline: float) -> dict[str, Any]:
            nonlocal journal_result
            if self.outcome_journal is None:
                return {}
            journal_result = self.outcome_journal.integrity_status(
                max_bytes=2 * 1024 * 1024,
                cancellation=child,
            )
            return {
                key: journal_result[key]
                for key in (
                    "integrity",
                    "reason",
                    "bytes_checked",
                    "record_count",
                    "journal_sha256",
                    "corruption",
                    "bounded",
                    "max_bytes",
                )
            }

        def probe_search(child: CancellationToken, _probe_deadline: float) -> dict[str, Any]:
            child.raise_if_cancelled()
            manager = getattr(self.operations, "searches", None)
            if manager is None:
                raise RuntimeError("search manager unavailable")
            data = manager.list()
            child.raise_if_cancelled()
            rows = data.get("searches", []) if isinstance(data, dict) else []
            running = sum(
                1 for row in rows
                if isinstance(row, dict) and row.get("status") == "running"
            )
            return {
                "recent_count": len(rows),
                "running_count": running,
                "result_payload_emitted": False,
            }

        def probe_process(child: CancellationToken, _probe_deadline: float) -> dict[str, Any]:
            child.raise_if_cancelled()
            registry = getattr(self.operations, "registry", None)
            if registry is None:
                raise RuntimeError("managed process registry unavailable")
            rows, _ = registry.list_handles(
                include_stale=True,
                max_results=500,
            )
            child.raise_if_cancelled()
            live = sum(
                1 for row in rows
                if isinstance(row, dict) and row.get("owned_by_current_gateway") is True
            )
            return {
                "managed_count": len(rows),
                "current_generation_count": live,
                "process_arguments_emitted": False,
            }

        specs: list[tuple[str, bool, str, Callable[[CancellationToken, float], dict[str, Any]] | None, dict[str, Any] | None]] = [
            (
                "uia",
                available("uia"),
                provider("uia", self.accessibility),
                probe_uia if available("uia") else None,
                self._uia_diagnostics(),
            ),
            ("screenshot", available("screenshot"), provider("screenshot", self.screenshot), None, None),
            ("windows", available("windows"), provider("windows", self.windows), probe_windows if available("windows") else None, None),
            ("shell", available("shell"), provider("shell", self.shell), None, None),
            ("clipboard", available("clipboard"), provider("clipboard", self.input), None, None),
            ("input", available("input"), provider("input", self.input), None, None),
            (
                "outcome_journal",
                self.outcome_journal is not None,
                type(self.outcome_journal).__name__ if self.outcome_journal is not None else "missing",
                probe_journal if self.outcome_journal is not None else None,
                None,
            ),
            (
                "search",
                getattr(self.operations, "searches", None) is not None,
                type(getattr(self.operations, "searches", None)).__name__
                if getattr(self.operations, "searches", None) is not None else "missing",
                probe_search if getattr(self.operations, "searches", None) is not None else None,
                None,
            ),
            (
                "process",
                getattr(self.operations, "registry", None) is not None,
                type(getattr(self.operations, "registry", None)).__name__
                if getattr(self.operations, "registry", None) is not None else "missing",
                probe_process if getattr(self.operations, "registry", None) is not None else None,
                None,
            ),
        ]
        entries: dict[str, dict[str, Any]] = {}
        complete = True
        for name, is_available, provider_name, probe_fn, passive in specs:
            left = remaining()
            if left <= 0.002:
                complete = False
                probe_fn = None
                left = 0.001
            entries[name] = self.runtime_health.probe(
                name,
                available=is_available,
                provider=provider_name,
                probe=probe_fn,
                parent_cancellation=cancellation,
                timeout_seconds=min(DEFAULT_PROBE_TIMEOUT_SECONDS, left),
                generation_id=generation_id,
                passive_diagnostics=passive,
            )

        if self.outcome_journal is None:
            journal_result = {
                "configured": False,
                "integrity": "unconfigured",
                "reason": "journal_not_configured",
                "bytes_checked": 0,
                "record_count": None,
                "journal_sha256": None,
                "corruption": None,
                "bounded": True,
                "max_bytes": 2 * 1024 * 1024,
            }
        elif not journal_result:
            state = entries["outcome_journal"]["state"]
            journal_result = {
                "configured": True,
                "integrity": "unknown",
                "reason": "probe_timeout_or_error" if state != "responsive" else "unknown",
                "bytes_checked": 0,
                "record_count": None,
                "journal_sha256": None,
                "corruption": None,
                "bounded": True,
                "max_bytes": 2 * 1024 * 1024,
            }
        if journal_result["integrity"] == "corrupt":
            entries["outcome_journal"]["state"] = "unhealthy"
        elif journal_result["integrity"] == "unknown" and entries["outcome_journal"]["available"]:
            entries["outcome_journal"]["state"] = "degraded"

        counts = {
            state: sum(1 for entry in entries.values() if entry["state"] == state)
            for state in ("responsive", "degraded", "unhealthy", "unknown")
        }
        elapsed_ms = max(0, int((monotonic() - started) * 1000))
        payload = {
            "contract_version": RUNTIME_HEALTH_VERSION,
            "observed_at": utc_now_iso(),
            "complete": complete and monotonic() <= deadline,
            "probe_budget_ms": max(1, int(budget * 1000)),
            "elapsed_ms": elapsed_ms,
            "generation": {
                "executor_process_id": __import__("os").getpid(),
                "operations_generation_id": generation_id,
            },
            "adapters": entries,
            "outcome_journal": journal_result,
            "summary": counts,
        }
        validate_runtime_health(payload)
        return payload

    def _health_get(
        self,
        request: ActionRequest,
        token: CancellationToken,
    ) -> dict[str, Any]:
        started = monotonic()
        overall_budget = max(0.01, min(self._timeout(request), 2.0))
        deadline = started + overall_budget
        child = CancellationToken()
        legacy_timeout = min(0.2, max(0.001, deadline - monotonic()))
        try:
            legacy = run_bounded(
                lambda: self.operations.execute(
                    "health.get",
                    {},
                    cancellation=child,
                ),
                timeout_seconds=legacy_timeout,
                cancellation=child,
                label="legacy health.get",
            )
        except (OperationTimeoutError, OperationCancelledError):
            legacy = {
                "contract_version": getattr(
                    __import__("pc_executor.operations", fromlist=["OPS_CONTRACT_VERSION"]),
                    "OPS_CONTRACT_VERSION",
                ),
                "status": "degraded",
                "generation_id": getattr(self.operations, "generation_id", None),
                "managed_processes_live": -1,
                "managed_processes_stale": -1,
                "managed_searches_running": -1,
                "managed_searches_recent": -1,
                "state_root": None,
            }
        token.raise_if_cancelled()
        remaining_budget = max(0.01, deadline - monotonic())
        runtime = self._runtime_health_snapshot(
            cancellation=token,
            budget_seconds=remaining_budget,
        )
        return {**legacy, "runtime_health": runtime}

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

        if action in {"ops.capabilities.get", "ops.preflight"}:
            return self.operations.execute(
                action,
                p,
                cancellation=token,
            )

        if action in OPS_ACTIONS:
            preflight_payload = {
                "contract_version": "pc_executor.action_preflight.v1",
                "request": {
                    "request_id": request.request_id,
                    "action": action,
                    "params": p,
                    "dry_run": dry_run,
                    "timeout_ms": request.timeout_ms,
                },
            }
            native_preflight = self.preflight(preflight_payload)
            if not native_preflight.executable:
                reason = native_preflight.reasons[0]["message"]
                raise PolicyBlockedError(
                    f"native operation preflight blocked: {reason}"
                )
            if dry_run:
                return {
                    "would_execute": action,
                    "preflight": native_preflight.to_dict(),
                }
            if action in OPS_SIDE_EFFECT_ACTIONS:
                return self._bounded_effectful(
                    request,
                    dry_run,
                    token,
                    tracker,
                    action,
                    lambda: self.operations.execute(
                        action,
                        p,
                        cancellation=token,
                    ),
                )
            return self._bounded(
                request,
                token,
                action,
                lambda: self.operations.execute(
                    action,
                    p,
                    cancellation=token,
                ),
            )

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
                token=token,
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
        safe_details = _sanitize_audit_details(dict(details or {}))
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
