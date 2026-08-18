import pytest

from authentication.face_auth import (
    DESCRIPTOR_LENGTH,
    FaceAuthService,
    InMemoryFaceDescriptorRepository,
)

_ENROLLED = [0.1] * DESCRIPTOR_LENGTH


def _service() -> FaceAuthService:
    return FaceAuthService(InMemoryFaceDescriptorRepository())


def test_matching_descriptor_is_verified_with_high_confidence():
    service = _service()
    service.enroll(user_id=1, descriptor=_ENROLLED)
    result = service.verify(user_id=1, probe_descriptor=_ENROLLED)
    assert result.verified
    assert result.confidence > 0.9
    assert result.distance == 0.0


def test_different_descriptor_is_not_verified():
    service = _service()
    service.enroll(user_id=1, descriptor=_ENROLLED)
    far_probe = [0.9] * DESCRIPTOR_LENGTH
    result = service.verify(user_id=1, probe_descriptor=far_probe)
    assert not result.verified
    assert result.confidence < 0.5


def test_no_enrollment_is_never_verified():
    service = _service()
    result = service.verify(user_id=999, probe_descriptor=_ENROLLED)
    assert not result.verified
    assert result.confidence == 0.0


def test_wrong_descriptor_length_rejected():
    service = _service()
    with pytest.raises(ValueError):
        service.enroll(user_id=1, descriptor=[0.1, 0.2])
    with pytest.raises(ValueError):
        service.verify(user_id=1, probe_descriptor=[0.1, 0.2])
