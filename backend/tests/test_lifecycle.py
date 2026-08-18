import pytest

from intent.lifecycle import (
    IntentState,
    InvalidTransitionError,
    allowed_next_states,
    apply_transition,
    validate_transition,
)


def test_full_happy_path():
    state = IntentState.DRAFT
    state = apply_transition(state, IntentState.APPROVED)
    assert state is IntentState.APPROVED
    state = apply_transition(state, IntentState.USED)
    assert state is IntentState.USED
    state = apply_transition(state, IntentState.EXPIRED)
    assert state is IntentState.EXPIRED
    state = apply_transition(state, IntentState.ARCHIVED)
    assert state is IntentState.ARCHIVED
    state = apply_transition(state, IntentState.DESTROYED)
    assert state is IntentState.DESTROYED


def test_used_can_be_reused_within_validity_window():
    # Default policy: Approved/Used intents may be used repeatedly
    # until they expire (see architecture doc, open question #3).
    validate_transition(IntentState.USED, IntentState.USED)


def test_cannot_skip_states():
    with pytest.raises(InvalidTransitionError):
        validate_transition(IntentState.DRAFT, IntentState.USED)
    with pytest.raises(InvalidTransitionError):
        validate_transition(IntentState.DRAFT, IntentState.DESTROYED)


def test_cannot_go_backwards():
    with pytest.raises(InvalidTransitionError):
        validate_transition(IntentState.APPROVED, IntentState.DRAFT)
    with pytest.raises(InvalidTransitionError):
        validate_transition(IntentState.EXPIRED, IntentState.APPROVED)


def test_destroyed_is_terminal():
    assert allowed_next_states(IntentState.DESTROYED) == set()
    with pytest.raises(InvalidTransitionError):
        validate_transition(IntentState.DESTROYED, IntentState.DRAFT)


def test_allowed_next_states_matches_transition_validation():
    for state in IntentState:
        for target in allowed_next_states(state):
            validate_transition(state, target)  # should not raise
