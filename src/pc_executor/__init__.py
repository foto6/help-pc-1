"""Safe Windows executor primitives."""

from .cancellation import CancellationToken
from .capabilities import (
    CONTRACT_VERSION as CAPABILITIES_CONTRACT_VERSION,
    build_capabilities,
    validate_capabilities,
)
from .context_binding import (
    CONTRACT_VERSION as EXECUTION_CONTEXT_BINDING_CONTRACT_VERSION,
    VALIDATION_CONTRACT_VERSION as EXECUTION_CONTEXT_VALIDATION_CONTRACT_VERSION,
    ContextMismatchBlockedError,
    ExecutionContextBinding,
    ExecutionContextBindingError,
    ForegroundContext,
    SystemExecutionContextObserver,
    binding_from_foreground,
    binding_from_shell,
    binding_from_uia_element,
    derive_execution_context_binding,
    parse_execution_context_binding,
    validate_execution_context_binding,
    validate_bound_execution_context,
)
from .executor import Executor
from .models import ActionRequest, ActionResult, AuditEvent, UIObservationSnapshot
from .preflight import (
    CONTRACT_VERSION as ACTION_PREFLIGHT_CONTRACT_VERSION,
    PreflightRequest,
    PreflightResult,
    PreflightValidationError,
)
from .outcome import (
    CONTRACT_VERSION as ACTION_OUTCOME_CONTRACT_VERSION,
    ActionOutcomeEvidence,
    ActionOutcomeValidationError,
    parse_action_outcome,
    validate_action_outcome,
)
from .outcome_journal import (
    LOOKUP_CONTRACT_VERSION as OUTCOME_JOURNAL_LOOKUP_CONTRACT_VERSION,
    RECORD_CONTRACT_VERSION as OUTCOME_JOURNAL_RECORD_CONTRACT_VERSION,
    ExecutionCorrelation,
    OutcomeJournal,
    OutcomeJournalConflictError,
    OutcomeJournalIntegrityError,
    OutcomeJournalLookup,
    OutcomeJournalRecord,
    OutcomeJournalReplayUnsafeError,
)

__all__ = [
    "Executor",
    "ActionRequest",
    "ActionResult",
    "AuditEvent",
    "CancellationToken",
    "UIObservationSnapshot",
    "CAPABILITIES_CONTRACT_VERSION",
    "build_capabilities",
    "validate_capabilities",
    "EXECUTION_CONTEXT_BINDING_CONTRACT_VERSION",
    "EXECUTION_CONTEXT_VALIDATION_CONTRACT_VERSION",
    "ExecutionContextBinding",
    "ExecutionContextBindingError",
    "ContextMismatchBlockedError",
    "ForegroundContext",
    "SystemExecutionContextObserver",
    "binding_from_foreground",
    "binding_from_shell",
    "binding_from_uia_element",
    "derive_execution_context_binding",
    "parse_execution_context_binding",
    "validate_execution_context_binding",
    "validate_bound_execution_context",
    "ACTION_PREFLIGHT_CONTRACT_VERSION",
    "PreflightRequest",
    "PreflightResult",
    "PreflightValidationError",
    "ActionOutcomeEvidence",
    "ActionOutcomeValidationError",
    "ACTION_OUTCOME_CONTRACT_VERSION",
    "parse_action_outcome",
    "validate_action_outcome",
    "OutcomeJournal",
    "OutcomeJournalRecord",
    "OutcomeJournalLookup",
    "ExecutionCorrelation",
    "OutcomeJournalIntegrityError",
    "OutcomeJournalConflictError",
    "OutcomeJournalReplayUnsafeError",
    "OUTCOME_JOURNAL_RECORD_CONTRACT_VERSION",
    "OUTCOME_JOURNAL_LOOKUP_CONTRACT_VERSION",
]
