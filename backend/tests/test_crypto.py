from datetime import datetime, timedelta, timezone

import pytest

from crypto.key_derivation import derive_intent_bound_key
from crypto.aes_gcm import decrypt, encrypt
from crypto.service import AuthorizationStateMismatchError, EncryptionService, IntentHashMismatchError
from intent.schema import CID

pytest.importorskip("cryptography")

QUANTUM_KEY_A = bytes(range(32))
QUANTUM_KEY_B = bytes(range(1, 33))

AUTH_HASH = "authz-state-hash-1"
AUTH_HASH_OTHER = "authz-state-hash-2"


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


# ---------------------------------------------------------------------
# HKDF key derivation
# ---------------------------------------------------------------------

def test_same_inputs_give_same_key():
    key_a = derive_intent_bound_key(QUANTUM_KEY_A, "hash1", "session-1", "decrypt", "device-1", AUTH_HASH)
    key_b = derive_intent_bound_key(QUANTUM_KEY_A, "hash1", "session-1", "decrypt", "device-1", AUTH_HASH)
    assert key_a == key_b
    assert len(key_a) == 32


def test_different_intent_hash_gives_different_key():
    key_a = derive_intent_bound_key(QUANTUM_KEY_A, "hash1", "session-1", "decrypt", "device-1", AUTH_HASH)
    key_b = derive_intent_bound_key(QUANTUM_KEY_A, "hash2", "session-1", "decrypt", "device-1", AUTH_HASH)
    assert key_a != key_b


def test_different_device_gives_different_key():
    key_a = derive_intent_bound_key(QUANTUM_KEY_A, "hash1", "session-1", "decrypt", "device-1", AUTH_HASH)
    key_b = derive_intent_bound_key(QUANTUM_KEY_A, "hash1", "session-1", "decrypt", "device-2", AUTH_HASH)
    assert key_a != key_b


def test_different_quantum_key_gives_different_key():
    key_a = derive_intent_bound_key(QUANTUM_KEY_A, "hash1", "session-1", "decrypt", "device-1", AUTH_HASH)
    key_b = derive_intent_bound_key(QUANTUM_KEY_B, "hash1", "session-1", "decrypt", "device-1", AUTH_HASH)
    assert key_a != key_b


def test_different_authorization_state_hash_gives_different_key():
    """The core new behavior: identical intent/session/device/operation,
    but a different CURRENT authorization state, yields an unrelated key.
    This is what lets a lifecycle transition, a policy change, or a
    session re-authorization invalidate an already-derived session."""
    key_a = derive_intent_bound_key(QUANTUM_KEY_A, "hash1", "session-1", "decrypt", "device-1", AUTH_HASH)
    key_b = derive_intent_bound_key(QUANTUM_KEY_A, "hash1", "session-1", "decrypt", "device-1", AUTH_HASH_OTHER)
    assert key_a != key_b


def test_empty_inputs_rejected():
    with pytest.raises(ValueError):
        derive_intent_bound_key(b"", "hash1", "session-1", "decrypt", "device-1", AUTH_HASH)
    with pytest.raises(ValueError):
        derive_intent_bound_key(QUANTUM_KEY_A, "", "session-1", "decrypt", "device-1", AUTH_HASH)
    with pytest.raises(ValueError):
        derive_intent_bound_key(QUANTUM_KEY_A, "hash1", "session-1", "decrypt", "device-1", "")


# ---------------------------------------------------------------------
# AES-256-GCM
# ---------------------------------------------------------------------

def test_encrypt_then_decrypt_round_trip():
    key = derive_intent_bound_key(QUANTUM_KEY_A, "hash1", "session-1", "decrypt", "device-1", AUTH_HASH)
    envelope = encrypt(b"top secret payload", key, "hash1", extra_aad=AUTH_HASH)
    plaintext = decrypt(
        envelope.ciphertext, envelope.nonce, envelope.auth_tag, key, "hash1", extra_aad=AUTH_HASH
    )
    assert plaintext == b"top secret payload"


def test_decrypt_fails_with_wrong_intent_hash_as_aad():
    key = derive_intent_bound_key(QUANTUM_KEY_A, "hash1", "session-1", "decrypt", "device-1", AUTH_HASH)
    envelope = encrypt(b"payload", key, "hash1", extra_aad=AUTH_HASH)
    with pytest.raises(Exception):  # cryptography.exceptions.InvalidTag
        decrypt(
            envelope.ciphertext, envelope.nonce, envelope.auth_tag, key, "hash-different",
            extra_aad=AUTH_HASH,
        )


def test_decrypt_fails_with_wrong_authorization_state_as_aad():
    key = derive_intent_bound_key(QUANTUM_KEY_A, "hash1", "session-1", "decrypt", "device-1", AUTH_HASH)
    envelope = encrypt(b"payload", key, "hash1", extra_aad=AUTH_HASH)
    with pytest.raises(Exception):  # cryptography.exceptions.InvalidTag
        decrypt(
            envelope.ciphertext, envelope.nonce, envelope.auth_tag, key, "hash1",
            extra_aad=AUTH_HASH_OTHER,
        )


def test_decrypt_fails_with_wrong_key():
    key_a = derive_intent_bound_key(QUANTUM_KEY_A, "hash1", "session-1", "decrypt", "device-1", AUTH_HASH)
    key_b = derive_intent_bound_key(QUANTUM_KEY_B, "hash1", "session-1", "decrypt", "device-1", AUTH_HASH)
    envelope = encrypt(b"payload", key_a, "hash1", extra_aad=AUTH_HASH)
    with pytest.raises(Exception):
        decrypt(
            envelope.ciphertext, envelope.nonce, envelope.auth_tag, key_b, "hash1",
            extra_aad=AUTH_HASH,
        )


# ---------------------------------------------------------------------
# End-to-end EncryptionService — the core research claim
# ---------------------------------------------------------------------

def test_successful_decryption_when_context_and_authorization_state_unchanged():
    service = EncryptionService()
    cid = _cid()
    envelope = service.encrypt_for_intent(b"classified", QUANTUM_KEY_A, cid, AUTH_HASH)

    plaintext = service.decrypt_for_intent(
        envelope,
        envelope.intent_hash,
        QUANTUM_KEY_A,
        recreated_cid=_cid(),
        current_authorization_state_hash=AUTH_HASH,
    )
    assert plaintext == b"classified"


@pytest.mark.parametrize(
    "field,value",
    [
        ("purpose", "unauthorized-purpose"),
        ("device_id", "device-999"),
        ("resource", "reports/q4.pdf"),
        ("operation", "encrypt"),
        ("session_id", "session-xyz"),
    ],
)
def test_changed_context_field_is_rejected_before_key_derivation(field, value):
    service = EncryptionService()
    original_cid = _cid()
    envelope = service.encrypt_for_intent(b"classified", QUANTUM_KEY_A, original_cid, AUTH_HASH)

    tampered_cid = _cid(**{field: value})
    with pytest.raises(IntentHashMismatchError):
        service.decrypt_for_intent(
            envelope,
            envelope.intent_hash,
            QUANTUM_KEY_A,
            recreated_cid=tampered_cid,
            current_authorization_state_hash=AUTH_HASH,
        )


def test_changed_authorization_state_is_rejected_before_key_derivation():
    """CID is byte-for-byte identical, but the surrounding security
    state has moved on (e.g. intent expired, policy now fails, session
    was re-authorized) — this is the distinct "cryptographic context
    mismatch" rejection path, separate from a changed CID field."""
    service = EncryptionService()
    cid = _cid()
    envelope = service.encrypt_for_intent(b"classified", QUANTUM_KEY_A, cid, AUTH_HASH)

    with pytest.raises(AuthorizationStateMismatchError):
        service.decrypt_for_intent(
            envelope,
            envelope.intent_hash,
            QUANTUM_KEY_A,
            recreated_cid=_cid(),
            current_authorization_state_hash=AUTH_HASH_OTHER,
        )


def test_expired_validity_window_is_rejected():
    service = EncryptionService()
    now = datetime(2026, 7, 23, 10, 0, 0, tzinfo=timezone.utc)
    original_cid = _cid(valid_from=now, valid_until=now + timedelta(hours=1))
    envelope = service.encrypt_for_intent(b"classified", QUANTUM_KEY_A, original_cid, AUTH_HASH)

    # A different validity window changes the canonical hash even
    # though the "meaning" (same purpose/device/etc.) is otherwise the
    # same -- this is intentional: an intent's validity window is part
    # of what was authorized.
    changed_window_cid = _cid(valid_from=now, valid_until=now + timedelta(hours=2))
    with pytest.raises(IntentHashMismatchError):
        service.decrypt_for_intent(
            envelope,
            envelope.intent_hash,
            QUANTUM_KEY_A,
            recreated_cid=changed_window_cid,
            current_authorization_state_hash=AUTH_HASH,
        )


def test_same_intent_but_wrong_quantum_key_fails_at_aes_not_hash_check():
    service = EncryptionService()
    cid = _cid()
    envelope = service.encrypt_for_intent(b"classified", QUANTUM_KEY_A, cid, AUTH_HASH)

    with pytest.raises(Exception):  # InvalidTag, not IntentHashMismatchError
        service.decrypt_for_intent(
            envelope,
            envelope.intent_hash,
            QUANTUM_KEY_B,
            recreated_cid=_cid(),
            current_authorization_state_hash=AUTH_HASH,
        )
