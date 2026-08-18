"""
Live-demo script for the continuous-authorization-bound cryptography
architecture. Runs entirely in-memory (in-memory audit log, device,
and session repositories) so it can be run immediately, without
MongoDB, to walk through the exact sequence described in the
deliverables writeup.

Run with:  python3 demo_continuous_authorization.py
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from audit.service import AuditLogService, InMemoryAuditLogRepository
from authorization import (
    AuthorizationError,
    AuthorizationService,
    InMemoryDeviceRepository,
    InMemorySessionRepository,
)
from crypto.service import AuthorizationStateMismatchError, EncryptionService
from intent.lifecycle import IntentState
from intent.schema import CID

NOW = datetime.now(timezone.utc)
QUANTUM_KEY = bytes(range(32))  # stand-in for a BB84-derived shared key


def cid(**overrides) -> CID:
    kwargs = dict(
        sender="alice",
        receiver="bob",
        purpose="quarterly-report-share",
        resource="reports/q3.pdf",
        operation="decrypt",
        device_id="device-001",
        session_id="session-abc",
        valid_from=NOW - timedelta(minutes=1),
        valid_until=NOW + timedelta(hours=1),
    )
    kwargs.update(overrides)
    return CID(**kwargs)


def line(label: str) -> None:
    print(f"\n{'-' * 70}\n{label}\n{'-' * 70}")


def main() -> None:
    devices = InMemoryDeviceRepository()
    sessions = InMemorySessionRepository()
    audit = AuditLogService(InMemoryAuditLogRepository())
    authz = AuthorizationService(devices, sessions)
    crypto = EncryptionService()

    # ---- 1-3: valid device + session + intent, encrypt + decrypt succeed
    line("1-3. Establish valid session, encrypt, decrypt")
    intent_state = IntentState.APPROVED
    request_cid = cid()

    decision = authz.authorize(
        request_cid, intent_id=1, intent_lifecycle_state=intent_state,
        user_id=1, requesting_user_role="user",
    )
    audit.record("authorized", "success", user_id=1, intent_hash=decision.security_state.intent_hash)
    print(f"authorized. authorization_state_hash={decision.authorization_state_hash[:16]}...")

    envelope = crypto.encrypt_for_intent(
        b"quarterly numbers: up 12%", QUANTUM_KEY, request_cid, decision.authorization_state_hash
    )
    audit.record("message_encrypted", "success", user_id=1, intent_hash=envelope.intent_hash)
    print(f"encrypted. ciphertext={envelope.ciphertext.hex()[:32]}...")

    plaintext = crypto.decrypt_for_intent(
        envelope, envelope.intent_hash, QUANTUM_KEY, request_cid, decision.authorization_state_hash
    )
    audit.record("message_decrypted", "success", user_id=1, intent_hash=envelope.intent_hash)
    print(f"decrypted: {plaintext!r}")

    # ---- 4: show current authorization/security state
    line("4. Current authorization/security state")
    print(decision.security_state.as_dict())

    # ---- 5-7: revoke the device, attempt again, show explicit rejection
    line("5-7. Revoke device, attempt cryptographic operation again")
    devices.revoke("device-001")
    try:
        authz.authorize(
            request_cid, intent_id=1, intent_lifecycle_state=intent_state,
            user_id=1, requesting_user_role="user",
        )
        print("UNEXPECTED: authorization succeeded after device revocation")
    except AuthorizationError as exc:
        audit.record(
            f"decrypt_rejected_{type(exc).__name__}", "rejected", user_id=1,
            intent_hash=envelope.intent_hash,
        )
        print(f"rejected as expected: {type(exc).__name__}: {exc}")
        print("(rejected before any key derivation or AES call was attempted)")

    # ---- 8-10: establish a fresh authorized session, fresh key, success
    line("8-10. Establish fresh session (different device), fresh key, succeed again")
    fresh_cid = cid(device_id="device-002", session_id="session-def")
    fresh_decision = authz.authorize(
        fresh_cid, intent_id=2, intent_lifecycle_state=IntentState.APPROVED,
        user_id=1, requesting_user_role="user",
    )
    audit.record(
        "authorized", "success", user_id=1, intent_hash=fresh_decision.security_state.intent_hash
    )
    print(f"fresh authorization_state_hash={fresh_decision.authorization_state_hash[:16]}...")
    print(
        "(different from the original: "
        f"{fresh_decision.authorization_state_hash != decision.authorization_state_hash})"
    )

    fresh_envelope = crypto.encrypt_for_intent(
        b"a brand new message", QUANTUM_KEY, fresh_cid, fresh_decision.authorization_state_hash
    )
    audit.record("message_encrypted", "success", user_id=1, intent_hash=fresh_envelope.intent_hash)
    fresh_plaintext = crypto.decrypt_for_intent(
        fresh_envelope, fresh_envelope.intent_hash, QUANTUM_KEY, fresh_cid,
        fresh_decision.authorization_state_hash,
    )
    audit.record("message_decrypted", "success", user_id=1, intent_hash=fresh_envelope.intent_hash)
    print(f"decrypted under fresh session: {fresh_plaintext!r}")

    # Prove the OLD ciphertext really does stay dead under the NEW state
    # (this is a security property, not a limitation -- see the
    # deliverables writeup / test_authorization.py docstring).
    try:
        crypto.decrypt_for_intent(
            envelope, envelope.intent_hash, QUANTUM_KEY, request_cid,
            fresh_decision.authorization_state_hash,
        )
        print("UNEXPECTED: old ciphertext decrypted under the new authorization state")
    except AuthorizationStateMismatchError:
        print("confirmed: old ciphertext cannot be decrypted under the new authorization state")

    # ---- 11: show the audit trail
    line("11. Audit trail")
    for entry in audit._repository.all_entries():  # demo-only direct access
        print(f"{entry.timestamp.isoformat()}  {entry.action:45s}  {entry.result}")


if __name__ == "__main__":
    main()
