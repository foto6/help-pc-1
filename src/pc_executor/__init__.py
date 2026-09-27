"""Safe Windows executor primitives."""

from .cancellation import CancellationToken
from .executor import Executor
from .models import ActionRequest, ActionResult, AuditEvent, UIObservationSnapshot
from .outcome import (
    CONTRACT_VERSION as ACTION_OUTCOME_CONTRACT_VERSION,
    ActionOutcomeEvidence,
    ActionOutcomeValidationError,
    parse_action_outcome,
    validate_action_outcome,
)

__all__ = [
    "Executor",
    "ActionRequest",
    "ActionResult",
    "AuditEvent",
    "CancellationToken",
    "UIObservationSnapshot",
    "ActionOutcomeEvidence",
    "ActionOutcomeValidationError",
    "ACTION_OUTCOME_CONTRACT_VERSION",
    "parse_action_outcome",
    "validate_action_outcome",
]
