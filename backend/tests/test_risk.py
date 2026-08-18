from policy.risk import RiskAction, RiskEngine, RiskFactors, RiskLevel


def test_no_risk_factors_is_low():
    result = RiskEngine().assess(RiskFactors())
    assert result.level is RiskLevel.LOW
    assert result.action is RiskAction.DECRYPT
    assert result.score == 0.0


def test_low_face_confidence_alone_pushes_to_medium():
    result = RiskEngine().assess(RiskFactors(face_confidence=0.3))
    assert result.level is RiskLevel.MEDIUM
    assert result.action is RiskAction.REQUIRE_FACE_VERIFICATION


def test_high_face_confidence_does_not_add_risk():
    result = RiskEngine().assess(RiskFactors(face_confidence=0.95))
    assert result.level is RiskLevel.LOW


def test_session_expired_pushes_to_medium_or_higher():
    result = RiskEngine().assess(RiskFactors(session_expired=True))
    assert result.level in (RiskLevel.MEDIUM, RiskLevel.HIGH)


def test_multiple_moderate_factors_compound_to_high():
    result = RiskEngine().assess(
        RiskFactors(qber=0.15, device_mismatch=True, session_expired=True)
    )
    assert result.level is RiskLevel.HIGH
    assert result.action is RiskAction.REJECT


def test_high_qber_alone_is_significant_but_not_necessarily_high():
    result = RiskEngine().assess(RiskFactors(qber=1.0))
    # qber weight alone (40) is below the HIGH threshold (60) but above MEDIUM (30)
    assert result.level is RiskLevel.MEDIUM


def test_factors_are_capped_not_unbounded():
    modest = RiskEngine().assess(RiskFactors(failed_login_count=5))
    excessive = RiskEngine().assess(RiskFactors(failed_login_count=500))
    assert modest.score == excessive.score  # capped at the same countable maximum
