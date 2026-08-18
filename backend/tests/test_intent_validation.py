"""
Tests for `intent.validation.IntentValidationService`.

These use the same in-memory reference repositories as
`tests/test_authorization.py` (no MongoDB required) and assert that
validation reuses — rather than reimplements — the canonicalizer,
policy engine, and risk engine.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from authorization import InMemoryDeviceRepository, InMemorySessionRepository
from intent.canonicalizer import canonicalize_cid, compute_intent_hash
from intent.lifecycle import IntentState
from intent.schema import CID
from intent.validation import IdentityCheckResult, IntentValidationService
from policy.engine import PolicyEngine
from policy.risk import RiskEngine, RiskFactors
from policy.rules import PolicyContext, PolicyRule, RuleOutcome

NOW = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)


def _cid(**overrides) -> CID:
    kwargs = dict(
        sender="alice",
        receiver="bob",
        purpose="quarterly-report-share",
        resource="reports/q3.pdf",
        operation="decrypt",
        device_id="device-001",
        session_id="session-abc",
        valid_from=NOW - timedelta(minutes=5),
        valid_until=NOW + timedelta(hours=1),
    )
    kwargs.update(overrides)
    return CID(**kwargs)


def _service(policy_engine=None, risk_engine=None) -> IntentValidationService:
    return IntentValidationService(
        InMemoryDeviceRepository(),
        InMemorySessionRepository(),
        policy_engine=policy_engine,
        risk_engine=risk_engine,
    )


# ---------------------------------------------------------------------
# Structure / canonicalization / hash happen automatically
# ---------------------------------------------------------------------

def test_canonicalization_and_hash_are_automatic_and_match_the_shared_implementation():
    cid = _cid()
    service = _service()
    result = service.validate(cid, current_lifecycle=IntentState.DRAFT, requesting_user_role="user", now=NOW)

    # No duplicated implementation: identical to calling the shared
    # canonicalizer functions directly.
    assert result.canonicalized_intent == canonicalize_cid(cid)
    assert result.intent_hash == compute_intent_hash(cid)
    assert result.resource == cid.resource
    assert result.operation == cid.operation
    assert result.purpose == cid.purpose


def test_malformed_cid_never_reaches_validation():
    # Required-field / validity-window structure checks are enforced
    # by CID's own pydantic validators, before a CID instance exists.
    with pytest.raises(ValueError):
        _cid(sender="")
    with pytest.raises(ValueError):
        _cid(valid_from=NOW, valid_until=NOW - timedelta(hours=1))


# ---------------------------------------------------------------------
# A fresh (never-yet-approved) intent is eligible for approval
# ---------------------------------------------------------------------

def test_draft_intent_with_no_problems_is_approval_eligible():
    service = _service()
    result = service.validate(_cid(), current_lifecycle=IntentState.DRAFT, requesting_user_role="user", now=NOW)
    assert result.valid is True
    assert result.approval_eligible is True
    assert result.reason is None
    assert result.current_lifecycle is IntentState.DRAFT


@pytest.mark.parametrize(
    "state", [IntentState.APPROVED, IntentState.USED, IntentState.EXPIRED, IntentState.ARCHIVED, IntentState.DESTROYED]
)
def test_non_draft_intent_is_never_approval_eligible(state):
    service = _service()
    result = service.validate(_cid(), current_lifecycle=state, requesting_user_role="user", now=NOW)
    assert result.approval_eligible is False
    assert result.reason is not None


# ---------------------------------------------------------------------
# Policy / risk / device / session / identity all feed the result
# ---------------------------------------------------------------------

class _AlwaysFailRule(PolicyRule):
    name = "always_fail"

    def evaluate(self, cid: CID, context: PolicyContext) -> RuleOutcome:
        return RuleOutcome(self.name, False, "denied for test purposes")


def test_policy_failure_marks_invalid_and_not_approval_eligible():
    engine = PolicyEngine(rules=[_AlwaysFailRule()])
    service = _service(policy_engine=engine)
    result = service.validate(_cid(), current_lifecycle=IntentState.DRAFT, requesting_user_role="user", now=NOW)
    assert result.policy_result.passed is False
    assert result.valid is False
    assert result.approval_eligible is False
    assert "policy" in result.reason


def test_revoked_device_marks_invalid_and_not_approval_eligible():
    devices = InMemoryDeviceRepository()
    devices.revoke("device-001")
    service = IntentValidationService(devices, InMemorySessionRepository())
    result = service.validate(_cid(), current_lifecycle=IntentState.DRAFT, requesting_user_role="user", now=NOW)
    assert result.device.revoked is True
    assert result.valid is False
    assert result.approval_eligible is False


def test_high_risk_blocks_approval_eligibility_but_not_validity():
    service = _service()
    high_risk_factors = RiskFactors(qber=0.9, device_mismatch=True)
    result = service.validate(
        _cid(),
        current_lifecycle=IntentState.DRAFT,
        requesting_user_role="user",
        risk_factors=high_risk_factors,
        now=NOW,
    )
    assert result.risk.level.value == "high"
    assert result.approval_eligible is False


def test_critical_risk_also_blocks_approval_eligibility():
    """PHASE 4: CRITICAL is a superset of HIGH for approval-eligibility
    purposes — a critical-risk request is at least as blocked as a
    high-risk one, never treated as somehow acceptable."""
    service = _service()
    critical_risk_factors = RiskFactors(qber=0.9, device_mismatch=True, session_expired=True)
    result = service.validate(
        _cid(),
        current_lifecycle=IntentState.DRAFT,
        requesting_user_role="user",
        risk_factors=critical_risk_factors,
        now=NOW,
    )
    assert result.risk.level.value == "critical"
    assert result.approval_eligible is False


def test_failed_identity_check_blocks_approval_eligibility():
    service = _service()
    result = service.validate(
        _cid(),
        current_lifecycle=IntentState.DRAFT,
        requesting_user_role="user",
        identity=IdentityCheckResult(checked=True, verified=False, confidence=0.1),
        now=NOW,
    )
    assert result.approval_eligible is False
    assert "identity" in result.reason


def test_identity_not_attempted_is_reported_but_does_not_itself_block():
    service = _service()
    result = service.validate(_cid(), current_lifecycle=IntentState.DRAFT, requesting_user_role="user", now=NOW)
    assert result.identity.checked is False
    assert result.approval_eligible is True


def test_unknown_session_is_reported_as_not_yet_known_but_not_invalid():
    service = _service()
    result = service.validate(_cid(), current_lifecycle=IntentState.DRAFT, requesting_user_role="user", now=NOW)
    assert result.session.known is False
    assert result.session.valid is True


# ---------------------------------------------------------------------
# Persisted policy config actually affects runtime validation
# ---------------------------------------------------------------------

class _FakePolicyRow:
    def __init__(self, rule_type, config_json, active=True):
        self.rule_type = rule_type
        self.config_json = config_json
        self.active = active


class _FakePolicyConfigRepository:
    def __init__(self, rows):
        self._rows = list(rows)

    def list_all(self):
        return self._rows


def test_persisted_resource_policy_marks_disallowed_resource_invalid():
    policy_config = _FakePolicyConfigRepository(
        [_FakePolicyRow("resource_matching", {"resources": ["reports/other.pdf"]})]
    )
    service = IntentValidationService(
        InMemoryDeviceRepository(), InMemorySessionRepository(),
        policy_config_repository=policy_config,
    )
    result = service.validate(
        _cid(resource="reports/q3.pdf"),
        current_lifecycle=IntentState.DRAFT,
        requesting_user_role="user",
        now=NOW,
    )
    assert not result.valid
    assert not result.policy_result.passed


def test_omitting_policy_config_repository_preserves_unrestricted_default():
    result = _service().validate(
        _cid(), current_lifecycle=IntentState.DRAFT, requesting_user_role="user", now=NOW,
    )
    assert result.policy_result.passed
