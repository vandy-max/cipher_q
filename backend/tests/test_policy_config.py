"""
Tests for `policy.config.policy_context_overrides` — the function that
turns persisted `Policy` rows into `PolicyContext` overrides so that
policies configured via the Policy Management page/API actually
affect runtime authorization (previously they had zero effect: see
`authorization.service.AuthorizationService` and
`intent.validation.IntentValidationService`).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from policy.config import policy_context_overrides


@dataclass
class _Row:
    rule_type: str
    config_json: dict = field(default_factory=dict)
    active: bool = True


def test_no_policies_means_no_overrides():
    assert policy_context_overrides([]) == {}


def test_inactive_policy_is_ignored():
    row = _Row(rule_type="allowed_device", config_json={"devices": ["device-001"]}, active=False)
    assert policy_context_overrides([row]) == {}


def test_unknown_rule_type_is_ignored():
    row = _Row(rule_type="not_a_real_rule", config_json={"anything": True})
    assert policy_context_overrides([row]) == {}


def test_allowed_operation_maps_to_frozenset():
    row = _Row(rule_type="allowed_operation", config_json={"operations": ["encrypt", "decrypt"]})
    overrides = policy_context_overrides([row])
    assert overrides == {"allowed_operations": frozenset({"encrypt", "decrypt"})}


def test_allowed_device_maps_to_frozenset():
    row = _Row(rule_type="allowed_device", config_json={"devices": ["device-001"]})
    overrides = policy_context_overrides([row])
    assert overrides == {"allowed_devices": frozenset({"device-001"})}


def test_resource_matching_maps_to_frozenset():
    row = _Row(rule_type="resource_matching", config_json={"resources": ["reports/q3.pdf"]})
    overrides = policy_context_overrides([row])
    assert overrides == {"allowed_resources": frozenset({"reports/q3.pdf"})}


def test_role_matching_maps_to_dict():
    row = _Row(rule_type="role_matching", config_json={"roles": {"decrypt": "SECURITY_ANALYST"}})
    overrides = policy_context_overrides([row])
    assert overrides == {"required_role_for_operation": {"decrypt": "SECURITY_ANALYST"}}


def test_session_timeout_maps_to_timedelta():
    row = _Row(rule_type="session_timeout", config_json={"seconds": 1800})
    overrides = policy_context_overrides([row])
    assert overrides == {"max_session_duration": timedelta(seconds=1800)}


def test_validity_period_has_no_context_field():
    row = _Row(rule_type="validity_period", config_json={})
    assert policy_context_overrides([row]) == {}


def test_multiple_active_rows_of_same_set_type_union():
    rows = [
        _Row(rule_type="allowed_device", config_json={"devices": ["device-001"]}),
        _Row(rule_type="allowed_device", config_json={"devices": ["device-002"]}),
    ]
    overrides = policy_context_overrides(rows)
    assert overrides == {"allowed_devices": frozenset({"device-001", "device-002"})}


def test_multiple_active_rows_of_scalar_type_last_wins():
    rows = [
        _Row(rule_type="session_timeout", config_json={"seconds": 3600}),
        _Row(rule_type="session_timeout", config_json={"seconds": 900}),
    ]
    overrides = policy_context_overrides(rows)
    assert overrides == {"max_session_duration": timedelta(seconds=900)}


def test_role_matching_rows_merge_dicts():
    rows = [
        _Row(rule_type="role_matching", config_json={"roles": {"decrypt": "ADMIN"}}),
        _Row(rule_type="role_matching", config_json={"roles": {"encrypt": "USER_LEVEL_2"}}),
    ]
    overrides = policy_context_overrides(rows)
    assert overrides == {
        "required_role_for_operation": {"decrypt": "ADMIN", "encrypt": "USER_LEVEL_2"}
    }
