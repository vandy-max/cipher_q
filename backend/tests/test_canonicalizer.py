from datetime import datetime, timedelta, timezone

import pytest

from intent.canonicalizer import canonical_json_bytes, compute_intent_hash
from intent.schema import CID


def _base_kwargs(**overrides):
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
    return kwargs


def test_same_logical_intent_same_hash_regardless_of_field_order():
    cid_a = CID(**_base_kwargs())
    # Pydantic model construction order doesn't affect internal field
    # order, so rebuild via a dict with keys shuffled to simulate a
    # client sending fields in a different order.
    kwargs = _base_kwargs()
    shuffled = dict(reversed(list(kwargs.items())))
    cid_b = CID(**shuffled)

    assert compute_intent_hash(cid_a) == compute_intent_hash(cid_b)


def test_absent_optional_field_equals_explicit_none():
    cid_absent = CID(**_base_kwargs())
    cid_none = CID(**_base_kwargs(classification=None, department=None, project=None))

    assert compute_intent_hash(cid_absent) == compute_intent_hash(cid_none)


def test_changing_any_field_changes_the_hash():
    baseline = compute_intent_hash(CID(**_base_kwargs()))

    variants = [
        _base_kwargs(purpose="different-purpose"),
        _base_kwargs(device_id="device-002"),
        _base_kwargs(session_id="session-xyz"),
        _base_kwargs(operation="encrypt"),
        _base_kwargs(resource="reports/q4.pdf"),
        _base_kwargs(classification="confidential"),
    ]
    for kwargs in variants:
        assert compute_intent_hash(CID(**kwargs)) != baseline


def test_sub_second_precision_does_not_change_hash():
    kwargs = _base_kwargs()
    cid_a = CID(**kwargs)

    kwargs_with_micros = dict(kwargs)
    kwargs_with_micros["valid_from"] = kwargs["valid_from"].replace(microsecond=123456)
    cid_b = CID(**kwargs_with_micros)

    assert compute_intent_hash(cid_a) == compute_intent_hash(cid_b)


def test_naive_datetime_assumed_utc_matches_explicit_utc():
    kwargs = _base_kwargs()
    naive_kwargs = dict(kwargs)
    naive_kwargs["valid_from"] = kwargs["valid_from"].replace(tzinfo=None)
    naive_kwargs["valid_until"] = kwargs["valid_until"].replace(tzinfo=None)

    assert compute_intent_hash(CID(**kwargs)) == compute_intent_hash(CID(**naive_kwargs))


def test_canonical_json_is_compact_and_sorted():
    cid = CID(**_base_kwargs(metadata={"z": 1, "a": 2}))
    payload = canonical_json_bytes(cid).decode("utf-8")

    assert " " not in payload  # no whitespace
    # None-valued optional fields are dropped entirely
    assert '"classification"' not in payload
    # top-level keys must appear in sorted order
    assert payload.index('"device_id"') < payload.index('"metadata"')
    assert payload.index('"metadata"') < payload.index('"operation"')
    # nested metadata keys also sorted
    assert payload.index('"a":2') < payload.index('"z":1')


def test_hash_is_hex_sha256_length():
    cid = CID(**_base_kwargs())
    digest = compute_intent_hash(cid)
    assert len(digest) == 64
    int(digest, 16)  # raises ValueError if not valid hex


def test_valid_until_before_valid_from_is_rejected():
    kwargs = _base_kwargs()
    kwargs["valid_until"] = kwargs["valid_from"] - timedelta(minutes=1)
    with pytest.raises(ValueError):
        CID(**kwargs)


def test_empty_required_field_is_rejected():
    kwargs = _base_kwargs(purpose="   ")
    with pytest.raises(ValueError):
        CID(**kwargs)
