import pytest

from quantum.bb84 import (
    DEFAULT_QBER_ABORT_THRESHOLD,
    QISKIT_AVAILABLE,
    simulate_bb84,
)
from quantum.service import QuantumKeyExchangeService

pytestmark = pytest.mark.skipif(
    not QISKIT_AVAILABLE,
    reason="qiskit / qiskit-aer not installed — install backend/requirements.txt to run these",
)


def test_no_eavesdropper_gives_low_qber():
    result = simulate_bb84(n_qubits=256, eavesdrop_prob=0.0)
    assert not result.session_aborted
    assert result.qber < 0.05  # only statistical sampling noise expected
    assert result.sifted_bits > 0
    assert len(result.quantum_key_hex) == 64  # sha256 hex digest


def test_full_eavesdropper_raises_qber_and_aborts():
    result = simulate_bb84(n_qubits=256, eavesdrop_prob=1.0)
    # Intercept-resend on every qubit introduces ~25% QBER on average.
    assert result.qber > DEFAULT_QBER_ABORT_THRESHOLD
    assert result.session_aborted


def test_invalid_eavesdrop_prob_rejected():
    with pytest.raises(ValueError):
        simulate_bb84(n_qubits=16, eavesdrop_prob=1.5)


def test_invalid_n_qubits_rejected():
    with pytest.raises(ValueError):
        simulate_bb84(n_qubits=0)


def test_service_generates_key_and_respects_defaults():
    service = QuantumKeyExchangeService(n_qubits=64)
    result = service.generate_shared_key()
    assert result.backend == "qiskit-aer"


def test_key_bytes_property_round_trips_hex():
    result = simulate_bb84(n_qubits=64)
    assert result.key_bytes.hex() == result.quantum_key_hex
