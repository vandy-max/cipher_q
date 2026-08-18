from datetime import datetime, timedelta, timezone

from audit.hash_chain import GENESIS_HASH, AuditEntry, build_entry, verify_chain
from audit.service import AuditLogService, InMemoryAuditLogRepository


def _now(offset_seconds: int = 0) -> datetime:
    return datetime(2026, 7, 23, 10, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=offset_seconds)


def test_first_entry_chains_from_genesis():
    entry = build_entry(GENESIS_HASH, _now(), user_id=1, action="login", intent_hash=None, result="success")
    assert entry.prev_log_hash == GENESIS_HASH
    assert len(entry.current_log_hash) == 64


def test_valid_chain_verifies():
    service = AuditLogService(InMemoryAuditLogRepository())
    service.record("login", "success", user_id=1, timestamp=_now(0))
    service.record("create_intent", "success", user_id=1, intent_hash="abc123", timestamp=_now(1))
    service.record("decrypt", "success", user_id=1, intent_hash="abc123", timestamp=_now(2))

    result = service.verify_integrity()
    assert result.valid
    assert result.first_invalid_index is None


def test_tampering_with_a_historical_entry_is_detected():
    repository = InMemoryAuditLogRepository()
    service = AuditLogService(repository)
    service.record("login", "success", user_id=1, timestamp=_now(0))
    service.record("decrypt", "success", user_id=1, intent_hash="abc123", timestamp=_now(1))
    service.record("decrypt", "success", user_id=1, intent_hash="abc123", timestamp=_now(2))

    entries = list(repository.all_entries())
    # Tamper with the middle entry's result, as if someone tried to
    # quietly hide a rejected decrypt attempt after the fact.
    tampered = AuditEntry(
        timestamp=entries[1].timestamp,
        user_id=entries[1].user_id,
        action=entries[1].action,
        intent_hash=entries[1].intent_hash,
        result="rejected",  # changed from "success"
        prev_log_hash=entries[1].prev_log_hash,
        current_log_hash=entries[1].current_log_hash,  # NOT recomputed -> now stale
    )
    entries[1] = tampered

    result = verify_chain(entries)
    assert not result.valid
    assert result.first_invalid_index == 1


def test_reordering_entries_is_detected():
    repository = InMemoryAuditLogRepository()
    service = AuditLogService(repository)
    service.record("login", "success", user_id=1, timestamp=_now(0))
    service.record("decrypt", "success", user_id=1, intent_hash="abc123", timestamp=_now(1))

    entries = list(repository.all_entries())
    swapped = [entries[1], entries[0]]

    result = verify_chain(swapped)
    assert not result.valid
    assert result.first_invalid_index == 0


def test_empty_chain_is_valid():
    result = verify_chain([])
    assert result.valid
