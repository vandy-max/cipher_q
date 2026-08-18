"""
Tests for `policy.ml_risk` — the advisory ML risk-analysis layer.

These exercise the model in isolation (no FastAPI/db involved),
matching the style of `tests/test_risk.py` for the deterministic
engine it sits alongside.
"""
from __future__ import annotations

from policy.ml_risk import MLRiskModel
from policy.risk import RiskFactors, RiskLevel


def test_clean_factors_score_low():
    result = MLRiskModel().assess(RiskFactors())
    assert result.level is RiskLevel.LOW
    assert 0.0 <= result.probability < 0.30


def test_revoked_device_or_session_dominates_the_score():
    result = MLRiskModel().assess(RiskFactors(revoked_device_or_session=True))
    assert result.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_compounding_signals_raise_the_level():
    low = MLRiskModel().assess(RiskFactors())
    high = MLRiskModel().assess(
        RiskFactors(
            device_mismatch=True,
            session_expired=True,
            repeated_denied_requests=5,
            device_changed=True,
        )
    )
    assert high.probability > low.probability


def test_explanation_lists_only_positive_contributors_and_is_sorted():
    result = MLRiskModel().assess(
        RiskFactors(device_mismatch=True, qber=0.9, session_changed=True), top_n=2
    )
    assert len(result.top_factors) <= 2
    contributions = [f.contribution for f in result.top_factors]
    assert contributions == sorted(contributions, reverse=True)
    assert all(c > 0 for c in contributions)


def test_probability_is_bounded():
    result = MLRiskModel().assess(
        RiskFactors(
            qber=1.0,
            failed_login_count=999,
            device_mismatch=True,
            session_expired=True,
            rapid_access_attempts=999,
            policy_failure_count=999,
            unusual_resource_access=True,
            unusual_operation=True,
            sensitive_resource_access=True,
            repeated_denied_requests=999,
            repeated_face_failures=999,
            device_changed=True,
            session_changed=True,
            intent_changed=True,
            lifecycle_changed=True,
            authorization_changed=True,
            revoked_device_or_session=True,
        )
    )
    assert 0.0 <= result.probability <= 1.0
    assert result.level is RiskLevel.CRITICAL


def test_model_is_advisory_prototype_flagged():
    result = MLRiskModel().assess(RiskFactors())
    assert result.is_prototype is True
