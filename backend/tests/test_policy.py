from datetime import datetime, timedelta, timezone

from policy.engine import PolicyEngine
from policy.rules import (
    AllowedDeviceRule,
    AllowedOperationRule,
    PolicyContext,
    ResourceMatchingRule,
    RoleMatchingRule,
    SessionTimeoutRule,
    ValidityPeriodRule,
    default_rules,
)
from intent.schema import CID


def _cid(**overrides) -> CID:
    now = datetime(2026, 7, 23, 10, 0, 0, tzinfo=timezone.utc)
    kwargs = dict(
        sender="alice",
        receiver="bob",
        purpose="quarterly-report-share",
        resource="reports/q3.pdf",
        operation="decrypt",
        device_id="device-001",
        session_id="session-abc",
        valid_from=now,
        valid_until=now + timedelta(hours=1),
    )
    kwargs.update(overrides)
    return CID(**kwargs)


def _context(**overrides) -> PolicyContext:
    kwargs = dict(
        now=datetime(2026, 7, 23, 10, 5, 0, tzinfo=timezone.utc),
        requesting_user_role="analyst",
    )
    kwargs.update(overrides)
    return PolicyContext(**kwargs)


def test_allowed_operation_rule():
    rule = AllowedOperationRule()
    cid = _cid(operation="decrypt")
    assert rule.evaluate(cid, _context(allowed_operations=frozenset({"decrypt", "read"}))).passed
    assert not rule.evaluate(cid, _context(allowed_operations=frozenset({"encrypt"}))).passed
    # None = unrestricted
    assert rule.evaluate(cid, _context(allowed_operations=None)).passed


def test_allowed_device_rule():
    rule = AllowedDeviceRule()
    cid = _cid(device_id="device-001")
    assert rule.evaluate(cid, _context(allowed_devices=frozenset({"device-001"}))).passed
    assert not rule.evaluate(cid, _context(allowed_devices=frozenset({"device-999"}))).passed


def test_session_timeout_rule():
    rule = SessionTimeoutRule()
    cid = _cid()
    within = _context(now=cid.valid_from + timedelta(minutes=30), max_session_duration=timedelta(hours=1))
    over = _context(now=cid.valid_from + timedelta(hours=2), max_session_duration=timedelta(hours=1))
    assert rule.evaluate(cid, within).passed
    assert not rule.evaluate(cid, over).passed


def test_validity_period_rule():
    rule = ValidityPeriodRule()
    cid = _cid()
    inside = _context(now=cid.valid_from + timedelta(minutes=1))
    before = _context(now=cid.valid_from - timedelta(minutes=1))
    after = _context(now=cid.valid_until + timedelta(minutes=1))
    assert rule.evaluate(cid, inside).passed
    assert not rule.evaluate(cid, before).passed
    assert not rule.evaluate(cid, after).passed


def test_resource_matching_rule():
    rule = ResourceMatchingRule()
    cid = _cid(resource="reports/q3.pdf")
    assert rule.evaluate(cid, _context(allowed_resources=frozenset({"reports/q3.pdf"}))).passed
    assert not rule.evaluate(cid, _context(allowed_resources=frozenset({"reports/q4.pdf"}))).passed


def test_role_matching_rule():
    rule = RoleMatchingRule()
    cid = _cid(operation="decrypt")
    matching = _context(requesting_user_role="analyst", required_role_for_operation={"decrypt": "analyst"})
    mismatched = _context(requesting_user_role="intern", required_role_for_operation={"decrypt": "analyst"})
    unconfigured = _context(required_role_for_operation=None)
    assert rule.evaluate(cid, matching).passed
    assert not rule.evaluate(cid, mismatched).passed
    assert rule.evaluate(cid, unconfigured).passed


def test_engine_passes_when_all_rules_pass():
    engine = PolicyEngine(default_rules())
    cid = _cid()
    context = _context(
        allowed_devices=frozenset({"device-001"}),
        allowed_operations=frozenset({"decrypt"}),
        allowed_resources=frozenset({"reports/q3.pdf"}),
    )
    decision = engine.evaluate(cid, context)
    assert decision.passed
    assert decision.failures == ()


def test_engine_fails_and_reports_which_rules_failed():
    engine = PolicyEngine(default_rules())
    cid = _cid(device_id="device-999", resource="reports/other.pdf")
    context = _context(
        allowed_devices=frozenset({"device-001"}),
        allowed_resources=frozenset({"reports/q3.pdf"}),
    )
    decision = engine.evaluate(cid, context)
    assert not decision.passed
    failed_names = {outcome.rule_name for outcome in decision.failures}
    assert "allowed_device" in failed_names
    assert "resource_matching" in failed_names
