"""
Tamper-evident audit log — pure hash-chain logic.

    current_log_hash = SHA256(prev_log_hash || timestamp || user_id ||
                               action || intent_hash || result ||
                               session_id || device_id || resource ||
                               operation || risk || reason)

Verifying integrity is a single linear walk recomputing the chain: any
modified historical entry breaks the chain from that point forward.
This module has no database/service dependency — persistence lives in
`service.py` behind a small repository interface.

PHASE 4 extends the entry with `session_id`, `device_id`, `resource`,
`operation`, `risk`, and `reason` — all optional (`None` when not
applicable to a given event) — so the tamper-evident chain can carry
full context for revocation, risk, and monitoring events without
breaking any Phase 1-3 entry that only ever set the original fields.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditEntry:
    timestamp: datetime
    user_id: int | None
    action: str
    intent_hash: str | None
    result: str
    prev_log_hash: str
    current_log_hash: str
    session_id: str | None = None
    device_id: str | None = None
    resource: str | None = None
    operation: str | None = None
    risk: str | None = None
    reason: str | None = None


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def compute_entry_hash(
    prev_log_hash: str,
    timestamp: datetime,
    user_id: int | None,
    action: str,
    intent_hash: str | None,
    result: str,
    session_id: str | None = None,
    device_id: str | None = None,
    resource: str | None = None,
    operation: str | None = None,
    risk: str | None = None,
    reason: str | None = None,
) -> str:
    material = "|".join(
        [
            prev_log_hash,
            _iso(timestamp),
            str(user_id) if user_id is not None else "",
            action,
            intent_hash or "",
            result,
            session_id or "",
            device_id or "",
            resource or "",
            operation or "",
            risk or "",
            reason or "",
        ]
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def build_entry(
    prev_log_hash: str,
    timestamp: datetime,
    user_id: int | None,
    action: str,
    intent_hash: str | None,
    result: str,
    session_id: str | None = None,
    device_id: str | None = None,
    resource: str | None = None,
    operation: str | None = None,
    risk: str | None = None,
    reason: str | None = None,
) -> AuditEntry:
    current_hash = compute_entry_hash(
        prev_log_hash,
        timestamp,
        user_id,
        action,
        intent_hash,
        result,
        session_id,
        device_id,
        resource,
        operation,
        risk,
        reason,
    )
    return AuditEntry(
        timestamp=timestamp,
        user_id=user_id,
        action=action,
        intent_hash=intent_hash,
        result=result,
        prev_log_hash=prev_log_hash,
        current_log_hash=current_hash,
        session_id=session_id,
        device_id=device_id,
        resource=resource,
        operation=operation,
        risk=risk,
        reason=reason,
    )


@dataclass(frozen=True)
class ChainVerificationResult:
    valid: bool
    first_invalid_index: int | None = None
    reason: str | None = None


def verify_chain(entries: Sequence[AuditEntry]) -> ChainVerificationResult:
    """Walk the chain from the genesis hash, recomputing every entry's
    hash. Returns the index of the first entry that breaks the chain
    (either its stated `prev_log_hash` doesn't match the previous
    entry's `current_log_hash`, or its own `current_log_hash` doesn't
    match what recomputing it produces — i.e. the entry itself was
    edited after the fact)."""
    expected_prev = GENESIS_HASH
    for index, entry in enumerate(entries):
        if entry.prev_log_hash != expected_prev:
            return ChainVerificationResult(
                valid=False,
                first_invalid_index=index,
                reason=(
                    f"entry {index}: prev_log_hash does not match the "
                    "previous entry's current_log_hash"
                ),
            )
        recomputed = compute_entry_hash(
            entry.prev_log_hash,
            entry.timestamp,
            entry.user_id,
            entry.action,
            entry.intent_hash,
            entry.result,
            entry.session_id,
            entry.device_id,
            entry.resource,
            entry.operation,
            entry.risk,
            entry.reason,
        )
        if recomputed != entry.current_log_hash:
            return ChainVerificationResult(
                valid=False,
                first_invalid_index=index,
                reason=f"entry {index}: current_log_hash does not match recomputed hash",
            )
        expected_prev = entry.current_log_hash

    return ChainVerificationResult(valid=True)
