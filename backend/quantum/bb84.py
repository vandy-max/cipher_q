"""
BB84 quantum key distribution — real per-qubit Qiskit circuits.

Adapted from the reference project's `quantum_bb84.py`. The physics and
protocol logic are unchanged (they were already correct): each bit goes
through an actual 1-qubit circuit on Qiskit Aer, not a vectorized
classical stand-in. What changed vs. the reference is packaging only —
typed dataclass result instead of a raw dict, module-level constants
exposed for the policy/config layer, and no coupling to anything else
in this codebase.

This module MUST remain independent: it must never import from
`intent`, `crypto`, `policy`, `audit`, or `database`. Its only output
is a shared secret (`quantum_key_hex`) plus protocol telemetry (QBER,
sifted bit count, abort flag). What happens to that secret afterward
(HKDF binding to an intent, etc.) is entirely the concern of `crypto/`.

BB84 basis convention:
    basis 0 = rectilinear / computational (Z) basis -> {|0>, |1>}
    basis 1 = diagonal (X) basis                     -> {|+>, |->}

Per-qubit protocol:
    1. Alice picks a random bit and a random basis.
       - bit=1 -> apply X gate (|0> -> |1>)
       - basis=X -> apply H gate to rotate into the diagonal basis
    2. (Optional) Eve intercepts: measures in her own random basis,
       collapsing the qubit, then re-prepares and forwards a fresh
       qubit encoding what she measured. This is the real physical
       mechanism (wavefunction collapse / no-cloning) that introduces
       detectable errors when Eve's basis disagrees with Alice's — not
       injected classical noise.
    3. Bob picks a random basis; if it's the X basis he applies H
       before measuring in the computational basis.
    4. Bob's measured bit is read out of the circuit.

After all qubits: Alice and Bob publicly compare bases (sifting), keep
only bits where bases matched, then sacrifice a public sample of the
sifted key to estimate the Quantum Bit Error Rate (QBER). QBER above
the abort threshold indicates eavesdropping and the key is discarded.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

import numpy as np

try:
    from qiskit import QuantumCircuit
    from qiskit_aer import AerSimulator

    QISKIT_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without qiskit installed
    QISKIT_AVAILABLE = False

BASIS_Z = 0  # rectilinear / computational
BASIS_X = 1  # diagonal / Hadamard

DEFAULT_N_QUBITS = 256
DEFAULT_QBER_ABORT_THRESHOLD = 0.11  # 11%, standard BB84 abort threshold

_simulator = AerSimulator() if QISKIT_AVAILABLE else None


def _require_qiskit() -> None:
    if not QISKIT_AVAILABLE:
        raise RuntimeError(
            "qiskit / qiskit-aer are not installed. Run: "
            "pip install qiskit qiskit-aer   (see backend/requirements.txt)"
        )


@dataclass(frozen=True)
class BB84Result:
    """Outcome of one full BB84 key-exchange session."""

    quantum_key_hex: str
    qber: float
    sifted_bits: int
    session_aborted: bool
    circuits_run: int
    backend: str

    @property
    def key_bytes(self) -> bytes:
        """Raw shared-secret bytes. Never persist this — it is the
        quantum-derived key material that `crypto/` must run through
        HKDF before it is ever used for AES."""
        return bytes.fromhex(self.quantum_key_hex)


def build_bb84_circuit(alice_bit: int, alice_basis: int, bob_basis: int) -> "QuantumCircuit":
    """Build the 1-qubit circuit for one BB84 round. Exposed separately
    so it can be drawn/inspected (e.g. for the frontend's BB84
    Simulation page)."""
    _require_qiskit()
    qc = QuantumCircuit(1, 1, name="bb84_round")

    if alice_bit == 1:
        qc.x(0)
    if alice_basis == BASIS_X:
        qc.h(0)

    qc.barrier()

    if bob_basis == BASIS_X:
        qc.h(0)
    qc.measure(0, 0)
    return qc


def run_single_qubit(alice_bit: int, alice_basis: int, bob_basis: int) -> int:
    """Execute the 1-qubit circuit on Qiskit Aer and return the
    measured classical bit."""
    _require_qiskit()
    qc = build_bb84_circuit(alice_bit, alice_basis, bob_basis)
    result = _simulator.run(qc, shots=1, memory=True).result()
    return int(result.get_memory(qc)[0])


def simulate_bb84(
    n_qubits: int = DEFAULT_N_QUBITS,
    eavesdrop_prob: float = 0.0,
    qber_abort_threshold: float = DEFAULT_QBER_ABORT_THRESHOLD,
) -> BB84Result:
    """Run a full BB84 key exchange, one real qubit circuit at a time.

    `eavesdrop_prob`: probability [0, 1] that Eve intercepts any given
    qubit (intercept-resend attack). 0.0 = no eavesdropper.
    """
    _require_qiskit()
    if not 0.0 <= eavesdrop_prob <= 1.0:
        raise ValueError("eavesdrop_prob must be between 0.0 and 1.0")
    if n_qubits < 1:
        raise ValueError("n_qubits must be at least 1")

    rng = np.random.default_rng()

    alice_bits = rng.integers(0, 2, n_qubits)
    alice_bases = rng.integers(0, 2, n_qubits)
    bob_bases = rng.integers(0, 2, n_qubits)
    eve_intercepts = (
        rng.random(n_qubits) < eavesdrop_prob
        if eavesdrop_prob > 0
        else np.zeros(n_qubits, dtype=bool)
    )

    bob_bits = np.zeros(n_qubits, dtype=int)
    circuits_run = 0

    for i in range(n_qubits):
        a_bit, a_basis, b_basis = (
            int(alice_bits[i]),
            int(alice_bases[i]),
            int(bob_bases[i]),
        )

        if eve_intercepts[i]:
            # Eve measures in her own random basis (collapses the
            # qubit), then re-prepares and forwards what she saw. If
            # her basis disagrees with Alice's, this physically
            # randomizes the bit Bob sees whenever his basis matches
            # Alice's — a real consequence of quantum measurement, not
            # injected noise.
            eve_basis = int(rng.integers(0, 2))
            eve_bit = run_single_qubit(a_bit, a_basis, eve_basis)
            circuits_run += 1
            bob_bit = run_single_qubit(eve_bit, eve_basis, b_basis)
            circuits_run += 1
        else:
            bob_bit = run_single_qubit(a_bit, a_basis, b_basis)
            circuits_run += 1

        bob_bits[i] = bob_bit

    # -- Sifting: keep only rounds where Alice's and Bob's bases matched --
    matching = alice_bases == bob_bases
    sifted_alice = alice_bits[matching]
    sifted_bob = bob_bits[matching]

    if len(sifted_alice) == 0:
        return BB84Result(
            quantum_key_hex="",
            qber=1.0,
            sifted_bits=0,
            session_aborted=True,
            circuits_run=circuits_run,
            backend="qiskit-aer",
        )

    # -- Public QBER estimate: sacrifice ~20% of the sifted key --
    n_check = max(1, len(sifted_alice) // 5)
    check_idx = rng.choice(len(sifted_alice), size=n_check, replace=False)
    errors = int(np.sum(sifted_alice[check_idx] != sifted_bob[check_idx]))
    qber = errors / n_check

    remaining_mask = np.ones(len(sifted_alice), dtype=bool)
    remaining_mask[check_idx] = False
    final_key_bits = sifted_alice[remaining_mask]

    aborted = qber > qber_abort_threshold
    key_bytes = np.packbits(final_key_bits).tobytes() if len(final_key_bits) else b""
    # Stretch the raw sifted bits into a 256-bit key. This is *not* the
    # HKDF step required before AES use — it only turns variable-length
    # sifted bits into a fixed-length shared secret. `crypto/` is
    # responsible for running this through HKDF bound to an intent hash
    # before it is ever used to encrypt anything.
    key_hex = hashlib.sha256(key_bytes + secrets.token_bytes(8)).hexdigest()

    return BB84Result(
        quantum_key_hex=key_hex,
        qber=round(qber, 4),
        sifted_bits=int(len(final_key_bits)),
        session_aborted=bool(aborted),
        circuits_run=circuits_run,
        backend="qiskit-aer",
    )


def quantum_backend_info() -> dict:
    """Diagnostic info proving a real Qiskit backend is wired up —
    used by GET /api/quantum/info."""
    if not QISKIT_AVAILABLE:
        return {"qiskit_available": False}
    import qiskit

    sample = build_bb84_circuit(alice_bit=1, alice_basis=BASIS_X, bob_basis=BASIS_X)
    return {
        "qiskit_available": True,
        "qiskit_version": qiskit.__version__,
        "simulator": getattr(_simulator, "name", str(_simulator)),
        "sample_circuit_diagram": str(sample.draw(output="text")),
    }
