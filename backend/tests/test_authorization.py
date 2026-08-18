"""
Tests for `authorization/` and its effect on the cryptographic session.

Covers the explicit rejection categories the continuous-authorization
architecture is required to distinguish (device, session, lifecycle,
policy), replay/staleness via session re-authorization, and the full
"invalidate -> reject -> establish fresh session -> succeed again"
demo scenario end to end, using the in-memory reference repositories
(no MongoDB required for these tests).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from authorization import (
    AuthorizationService,
    DeviceRevokedError,
    InMemoryDeviceRepository,
    InMemorySessionRepository,
    LifecycleRejectedError,
    PolicyRejectedError,
    SessionInvalidError,
)
from crypto.service import AuthorizationStateMismatchError, EncryptionService
from intent.lifecycle import IntentState
from intent.schema import CID
from policy.engine import PolicyEngine
from policy.rules import PolicyContext, PolicyRule, RuleOutcome

NOW = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)
QUANTUM_KEY = bytes(range(32))


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


def _service() -> AuthorizationService:
    return AuthorizationService(InMemoryDeviceRepository(), InMemorySessionRepository())


# ---------------------------------------------------------------------
# Explicit rejection categories
# ---------------------------------------------------------------------

def test_valid_state_is_authorized():
    service = _service()
    decision = service.authorize(
        _cid(), intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
        user_id=1, requesting_user_role="user", now=NOW,
    )
    assert decision.authorization_state_hash
    assert decision.policy_decision.passed


def test_revoked_device_is_rejected():
    devices = InMemoryDeviceRepository()
    devices.revoke("device-001")
    service = AuthorizationService(devices, InMemorySessionRepository())
    with pytest.raises(DeviceRevokedError):
        service.authorize(
            _cid(), intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
            user_id=1, requesting_user_role="user", now=NOW,
        )


def test_revoked_session_is_rejected():
    sessions = InMemorySessionRepository()
    sessions.get_or_create("session-abc", user_id=1, device_id="device-001", ttl=timedelta(hours=1))
    sessions.revoke("session-abc")
    service = AuthorizationService(InMemoryDeviceRepository(), sessions)
    with pytest.raises(SessionInvalidError):
        service.authorize(
            _cid(), intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
            user_id=1, requesting_user_role="user", now=NOW,
        )


def test_expired_session_is_rejected():
    sessions = InMemorySessionRepository()
    sessions.get_or_create("session-abc", user_id=1, device_id="device-001", ttl=timedelta(seconds=-1), now=NOW)
    service = AuthorizationService(InMemoryDeviceRepository(), sessions)
    with pytest.raises(SessionInvalidError):
        service.authorize(
            _cid(), intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
            user_id=1, requesting_user_role="user", now=NOW,
        )


@pytest.mark.parametrize(
    "state",
    [IntentState.DRAFT, IntentState.EXPIRED, IntentState.ARCHIVED, IntentState.DESTROYED],
)
def test_ineligible_lifecycle_states_are_rejected(state):
    service = _service()
    with pytest.raises(LifecycleRejectedError):
        service.authorize(
            _cid(), intent_id=1, intent_lifecycle_state=state,
            user_id=1, requesting_user_role="user", now=NOW,
        )


@pytest.mark.parametrize("state", [IntentState.APPROVED, IntentState.USED])
def test_eligible_lifecycle_states_are_authorized(state):
    service = _service()
    decision = service.authorize(
        _cid(), intent_id=1, intent_lifecycle_state=state,
        user_id=1, requesting_user_role="user", now=NOW,
    )
    assert decision.security_state.intent_lifecycle_state is state


class _AlwaysFailRule(PolicyRule):
    name = "always_fail"

    def evaluate(self, cid: CID, context: PolicyContext) -> RuleOutcome:
        return RuleOutcome(self.name, False, "denied for test purposes")


def test_policy_rejection_is_distinguishable_from_other_rejections():
    engine = PolicyEngine(rules=[_AlwaysFailRule()])
    service = AuthorizationService(InMemoryDeviceRepository(), InMemorySessionRepository(), engine)
    with pytest.raises(PolicyRejectedError):
        service.authorize(
            _cid(), intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
            user_id=1, requesting_user_role="user", now=NOW,
        )


# ---------------------------------------------------------------------
# Session re-authorization changes the bound state (replay protection)
# ---------------------------------------------------------------------

def test_session_refresh_changes_authorization_state_hash():
    sessions = InMemorySessionRepository()
    service = AuthorizationService(InMemoryDeviceRepository(), sessions)

    first = service.authorize(
        _cid(), intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
        user_id=1, requesting_user_role="user", now=NOW,
    )

    sessions.refresh("session-abc", ttl=timedelta(hours=1), now=NOW)

    second = service.authorize(
        _cid(), intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
        user_id=1, requesting_user_role="user", now=NOW,
    )

    assert first.authorization_state_hash != second.authorization_state_hash
    assert second.security_state.session_version == first.security_state.session_version + 1


# ---------------------------------------------------------------------
# Full demo scenario, end to end, against the crypto layer
# ---------------------------------------------------------------------

def test_full_scenario_invalidate_then_reauthorize():
    """
    1. Valid device+session+intent -> authorize -> encrypt -> decrypt succeeds.
    2. Device is revoked -> re-running authorize for the SAME record
       rejects explicitly, before any crypto call.
    3. A fresh session is established for a different (valid) device
       -> a brand-new encrypt+decrypt cycle succeeds again.

    Note what this deliberately does NOT claim: re-authorizing does not
    retroactively make the OLD ciphertext decryptable again. Once
    encrypted under authorization-state hash A, that ciphertext stays
    bound to A forever — a fresh authorization can only back a fresh
    encryption. That is a security property (forward invalidation),
    not a limitation of the demo.
    """
    devices = InMemoryDeviceRepository()
    sessions = InMemorySessionRepository()
    authz = AuthorizationService(devices, sessions)
    crypto = EncryptionService()

    cid = _cid()
    decision = authz.authorize(
        cid, intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
        user_id=1, requesting_user_role="user", now=NOW,
    )
    envelope = crypto.encrypt_for_intent(
        b"top secret", QUANTUM_KEY, cid, decision.authorization_state_hash
    )
    plaintext = crypto.decrypt_for_intent(
        envelope, envelope.intent_hash, QUANTUM_KEY, cid, decision.authorization_state_hash
    )
    assert plaintext == b"top secret"

    # Step 5-7: revoke the device -> explicit rejection before any crypto call.
    devices.revoke("device-001")
    with pytest.raises(DeviceRevokedError):
        authz.authorize(
            cid, intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
            user_id=1, requesting_user_role="user", now=NOW,
        )

    # Step 8-10: establish a fresh authorized session on a different,
    # valid device, and demonstrate the system working again with a
    # freshly derived operational key (new plaintext, not the old
    # ciphertext -- see docstring).
    fresh_cid = _cid(device_id="device-002", session_id="session-def")
    fresh_decision = authz.authorize(
        fresh_cid, intent_id=2, intent_lifecycle_state=IntentState.APPROVED,
        user_id=1, requesting_user_role="user", now=NOW,
    )
    assert fresh_decision.authorization_state_hash != decision.authorization_state_hash

    fresh_envelope = crypto.encrypt_for_intent(
        b"fresh secret", QUANTUM_KEY, fresh_cid, fresh_decision.authorization_state_hash
    )
    fresh_plaintext = crypto.decrypt_for_intent(
        fresh_envelope,
        fresh_envelope.intent_hash,
        QUANTUM_KEY,
        fresh_cid,
        fresh_decision.authorization_state_hash,
    )
    assert fresh_plaintext == b"fresh secret"

    # And the OLD ciphertext really does stay dead: even resupplying
    # the original (pre-revocation) authorization state hash to the
    # crypto layer directly (bypassing authz.authorize, which would
    # itself now reject on the revoked device) still cannot decrypt
    # under the fresh state hash.
    with pytest.raises(AuthorizationStateMismatchError):
        crypto.decrypt_for_intent(
            envelope, envelope.intent_hash, QUANTUM_KEY, cid, fresh_decision.authorization_state_hash
        )


# ---------------------------------------------------------------------
# Persisted policy config actually affects runtime enforcement
# (policy.config.policy_context_overrides wiring)
# ---------------------------------------------------------------------

@dataclass
class _FakePolicyRow:
    rule_type: str
    config_json: dict
    active: bool = True


class _FakePolicyConfigRepository:
    def __init__(self, rows):
        self._rows = list(rows)

    def list_all(self):
        return self._rows


def test_persisted_device_policy_rejects_device_not_in_allow_list():
    """A Policy row of rule_type='allowed_device' restricting
    encryption to a different device must actually reject this CID's
    device once a policy_config_repository is wired in -- proving the
    Policy Management page has a real runtime effect."""
    devices = InMemoryDeviceRepository()
    sessions = InMemorySessionRepository()
    policy_config = _FakePolicyConfigRepository(
        [_FakePolicyRow(rule_type="allowed_device", config_json={"devices": ["device-999"]})]
    )
    authz = AuthorizationService(devices, sessions, policy_config_repository=policy_config)

    cid = _cid(device_id="device-001")
    with pytest.raises(PolicyRejectedError):
        authz.authorize(
            cid, intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
            user_id=1, requesting_user_role="user", now=NOW,
        )


def test_persisted_policy_allows_when_device_is_in_allow_list():
    devices = InMemoryDeviceRepository()
    sessions = InMemorySessionRepository()
    policy_config = _FakePolicyConfigRepository(
        [_FakePolicyRow(rule_type="allowed_device", config_json={"devices": ["device-001"]})]
    )
    authz = AuthorizationService(devices, sessions, policy_config_repository=policy_config)

    cid = _cid(device_id="device-001")
    decision = authz.authorize(
        cid, intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
        user_id=1, requesting_user_role="user", now=NOW,
    )
    assert decision.policy_decision.passed


def test_inactive_persisted_policy_has_no_effect():
    devices = InMemoryDeviceRepository()
    sessions = InMemorySessionRepository()
    policy_config = _FakePolicyConfigRepository(
        [_FakePolicyRow(
            rule_type="allowed_device", config_json={"devices": ["device-999"]}, active=False,
        )]
    )
    authz = AuthorizationService(devices, sessions, policy_config_repository=policy_config)

    cid = _cid(device_id="device-001")
    decision = authz.authorize(
        cid, intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
        user_id=1, requesting_user_role="user", now=NOW,
    )
    assert decision.policy_decision.passed


def test_omitting_policy_config_repository_preserves_unrestricted_default():
    """Existing behavior for every caller that doesn't pass
    policy_config_repository (i.e. every pre-existing test and any
    deployment with no policies configured) must stay exactly as
    permissive as before this change."""
    decision = _service().authorize(
        _cid(), intent_id=1, intent_lifecycle_state=IntentState.APPROVED,
        user_id=1, requesting_user_role="user", now=NOW,
    )
    assert decision.policy_decision.passed
