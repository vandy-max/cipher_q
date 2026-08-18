# Intent-Bound Quantum Cryptography (IBQC)
## Architecture & Design Document — Pre-Implementation Review

**Status:** Draft for approval. No implementation code has been written. This document analyzes the reference project, defines what will be reused vs. redesigned and why, and specifies the new system's architecture in enough detail to build from.

---

## 1. Reference Project Analysis

The reference repo (`vandy-max/QuantumCrypto` → `intent-bound-quantum-encryption/`) is a working single-service prototype:

- **Backend:** Flask + SQLite, single `app.py` (~550 lines), JWT auth (PBKDF2-HMAC-SHA256 password hashing), a real Qiskit/Aer BB84 implementation (`quantum_bb84.py`), AES-256-GCM encrypt/decrypt, a flat security-event log, and a weighted risk-score function.
- **Frontend:** React + Vite, 7 pages (Landing, Auth, Dashboard, Encrypt, Decrypt, Face, Security), face-api.js running client-side for expression detection, an "Aurora" light theme (Indigo/Violet/Mint palette, Outfit + JetBrains Mono fonts).

### 1.1 What the reference project actually binds into the key

```python
def derive_key(quantum_key_hex, intent_hash, emotion):
    material = f"{quantum_key_hex}:{intent_hash}:{emotion}".encode()
    return hashlib.sha256(material).digest()
```

Three things stand out, and they directly explain why this needs a redesign rather than an extension:

1. **"Intent" is a single free-text `purpose` string**, hashed as `SHA256(purpose|receiver_id|device_id|session_id)` — a flat string concatenation, not a canonical structured descriptor. No versioning, no lifecycle, no policy, no extensibility.
2. **"Emotion" (face expression: neutral/happy/sad/angry/...) is a first-class input to key derivation.** This is precisely the "detecting human intent/emotion" pattern your spec explicitly rules out. It's also a security smell independent of that: an 8-way classifier output with a confidence threshold of 0.30 is now part of a cryptographic key.
3. **The quantum key is used directly** (stretched via one SHA-256 call) rather than passed through a proper KDF with domain separation from the intent material.

None of this is a criticism of the reference project on its own terms — it does what its README says it does, honestly, including admitting the BB84 QBER/eavesdrop simulation couldn't be verified with real installed packages. It's just not the artifact this new project is trying to build. Full comparison in §7.

### 1.2 What's genuinely reusable

| Reference asset | Reuse decision | Why |
|---|---|---|
| `quantum_bb84.py` — real per-qubit Qiskit circuits, sifting, QBER, Eve intercept-resend | **Reuse as-is, relocate into `quantum/` module, keep independent** | This is exactly the BB84 module your spec asks for: real circuits (not vectorized fakery), correct sifting/QBER logic, honest about install requirements. No reason to rewrite physics that's already correct. |
| JWT auth pattern (PBKDF2-HMAC-SHA256, `sub` cast to string per RFC 7519, Bearer middleware) | **Reuse the pattern, reimplement for FastAPI** | The logic is sound; only the framework binding (Flask decorator → FastAPI dependency) changes. |
| face-api.js client-side detection pipeline (TinyFaceDetector + models loaded from `/public/models`) | **Reuse the detection mechanism only — identity/liveness signal, not expression-as-intent** | Your spec says face auth should verify identity and produce a confidence score, nothing more. The reference's model-loading and browser-side inference plumbing is reusable; the "which emotions are allowed" gate is not. |
| `react-webcam` capture flow, `FacePage.jsx` UX shape | **Reuse as UI inspiration** | Camera permission handling, capture-then-detect flow is standard and fine to mirror. |
| Aurora light theme (CSS variables, `GlowCard`/`StatusBadge`/`Navbar` components) | **Reuse as visual starting point, extend with new pages** | It's a coherent, non-generic design system already; rebuilding it from scratch would waste effort for no research value. |
| `recharts` for dashboard visualization | **Reuse (already in new stack)** | Fits the risk-distribution / QBER-trend charts needed for the new Security/Policy dashboards. |
| CORS-preflight handling pattern, hex-encoding of ciphertext/nonce/tag over JSON | **Reuse the wire-format convention** | Simple, works, no reason to invent a different encoding. |

### 1.3 What's redesigned and why

| Reference approach | Problem | New approach |
|---|---|---|
| `intent = purpose` (string) | Not a structured, verifiable descriptor; no sender/device/session/validity fields beyond ad hoc string concat | Full CID object (§3) with 13 defined fields |
| `intent_hash = SHA256("purpose\|receiver_id\|device_id\|session_id")` | Field order is baked into the hash; no key sorting, no type normalization, no handling of optional fields → same intent can hash differently depending on how it's assembled | Deterministic canonical-JSON serializer + SHA-256 (§4) |
| Intents stored as one mutable row per `session_id`, no history | Spec requires immutable versioning (v1, v2, v3…) with author/reason/timestamp per version | Append-only `intent_versions` table, `intents` row points at current version (§9) |
| No explicit lifecycle — an intent just exists or doesn't | Spec requires Draft → Approved → Used → Expired → Archived → Destroyed with logged transitions | Explicit state machine enforced server-side, transition log feeds audit chain (§6) |
| `derive_key = SHA256(quantum_key + intent_hash + emotion)` | Emotion in the key; SHA-256 concatenation is not a KDF (no domain separation, no salt) | `HKDF-SHA256(IKM=quantum_key, salt=session_id, info=intent_hash \|\| purpose_tag)` → intent-bound AES key (§5) |
| No policy engine — decrypt succeeds iff `intent_hash` string-matches | Spec requires a policy engine (device, session timeout, validity window, resource/role matching) that runs **before** key derivation | Dedicated `policy/` module evaluating rules against the recreated CID prior to any HKDF call (§8) |
| Risk score folds in `emotion_valid` as a factor | Emotion shouldn't feed either the key or, arguably, risk in this framing — but risk *can* legitimately use face-auth confidence (identity), just not expression | Risk engine keeps QBER, failed logins, device mismatch, session expiry, rapid access; replaces "emotion validity" with "face-auth confidence score" (§10) |
| Flat `security_logs` table, no tamper evidence | Spec requires a hash-chained, tamper-evident audit log | Each audit row stores `prev_log_hash` + `current_log_hash = SHA256(prev_hash \|\| entry_fields)` (§11) |
| SQLite, single file | Spec requires PostgreSQL, normalized schema, Alembic migrations | Full relational schema (§9), SQLAlchemy models, Alembic |
| Flask, single `app.py`, no DI, business logic inside routes | Spec explicitly forbids business logic in routes, requires SOLID/DI/clean modules | FastAPI with a service-layer per module, routes are thin controllers (§2) |
| `localStorage` for JWT | Not addressed by spec either way, but worth flagging | Keep for prototype simplicity (documented as a security assumption, §13), unless you'd prefer httpOnly cookies |

---

## 2. Clean Architecture — Module Layout

```
backend/
  authentication/     # user model, password hashing, JWT issuance/verification, face-auth service
  intent/              # CID schema, canonicalizer, versioning, lifecycle state machine
  quantum/              # quantum_bb84.py (adapted), backend-info diagnostics — stays isolated, no imports from other modules
  crypto/               # HKDF derivation, AES-256-GCM encrypt/decrypt, key material never persisted
  policy/               # rule definitions + policy evaluation engine, risk engine
  audit/                # hash-chained audit log service
  database/             # SQLAlchemy models, session management, Alembic migrations
  api/                  # FastAPI routers — thin, call into services only, no business logic
  tests/                # unit + integration tests per module

frontend/
  src/
    pages/              # Login, Dashboard, CreateIntent, IntentHistory, BB84Simulation,
                         # Encryption, Decryption, AuditLogs, PolicyManagement, Visualization
    components/
    hooks/
    services/           # api.js-style client, one function per endpoint
    styles/
```

**Dependency rule:** `quantum/` has zero dependencies on any other backend module (matches your "should remain independent" requirement). `crypto/` depends on `intent/` (for the hash) and `quantum/` (for the raw key) but not on `policy/` or `audit/`. `api/` is the only layer allowed to depend on everything. `policy/` and `audit/` are called by `api/` around the `crypto/` calls, never by `crypto/` itself — this keeps the encryption primitive testable in isolation from policy decisions.

---

## 3. Cryptographic Intent Descriptor (CID) — Schema

```python
class CID(BaseModel):
    sender: str
    receiver: str
    purpose: str
    resource: str
    operation: Literal["encrypt", "decrypt", "read", "write", "share", ...]  # extensible
    device_id: str
    session_id: str
    valid_from: datetime
    valid_until: datetime
    classification: str | None = None
    department: str | None = None
    project: str | None = None
    metadata: dict[str, Any] | None = None   # extensibility escape hatch
```

`metadata` is the extension point the spec asks for — new fields go there without breaking the canonicalization/hash contract for existing CIDs.

---

## 4. Intent Canonicalization

Deterministic serializer, independent of field insertion order or client formatting differences:

1. Convert the CID to a plain dict, dropping keys whose value is `None` (optional fields absent ≠ optional fields set to null — both should canonicalize identically).
2. Recursively sort all object keys lexicographically (handles nested `metadata`).
3. Normalize value types: datetimes → ISO-8601 UTC with fixed precision (seconds, no trailing zeros ambiguity); strings → NFC Unicode normalization, no trimming surprises (trimming happens *before* canonicalization, at input validation).
4. Serialize with `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=True)` — no whitespace, no locale-dependent formatting.
5. `Intent Hash = SHA256(canonical_bytes)`.

This directly fixes the reference project's `f"{purpose}|{receiver_id}|{device_id}|{session_id}"` approach, where field order is implicitly part of the hash and optional fields have nowhere to go.

---

## 5. HKDF Layer

```
IKM   = quantum_shared_key_bytes          (from BB84, never used directly)
salt  = session_id (bytes)                 (binds derivation to this session)
info  = b"IBQC-v1|" + intent_hash + b"|" + operation.encode()
OKM   = HKDF-SHA256(IKM, salt, info, length=32)   # intent-bound AES-256 key
```

- Using `intent_hash` inside `info` (not `salt`) is deliberate: HKDF's `info` parameter is designed for context/application binding, while `salt` is meant to be per-instance randomness. `session_id` as salt plus `intent_hash` as info together mean **the same quantum key, reused for a different intent or a different session, produces an unrelated AES key** — this is the core research claim made concrete.
- Raw quantum key and derived AES key are both held only in memory for the duration of the request; neither is persisted (matches your "never store the raw encryption key" and "never use the raw quantum key for encryption" requirements).

---

## 6. Intent Lifecycle (state machine)

```
Draft → Approved → Used → Expired → Archived → Destroyed
```

Enforced transition rules (only forward, with two exceptions):
- `Draft → Approved`: requires policy pre-check to pass (structural validation, valid_from < valid_until, required fields present).
- `Approved → Used`: set on first successful decrypt against this intent's hash (an intent can be `Used` multiple times if the policy allows reuse within its validity window — configurable).
- `Approved/Used → Expired`: automatic, triggered when `now > valid_until` (checked lazily on access, plus an optional background sweep).
- `Expired → Archived`: manual or scheduled housekeeping.
- `Archived → Destroyed`: manual, irreversible — the intent version row is retained for audit but marked destroyed; **the CID's `metadata`/PII-bearing fields, if any, can be scrubbed at this point** while the hash and version history remain.

Every transition writes one audit-log entry (§11) with the intent hash, from-state, to-state, actor, and reason.

---

## 7. Reference vs. New: Side-by-Side

| Property | Reference project | New project |
|---|---|---|
| Intent representation | Free-text `purpose` string | Structured 13-field CID |
| Intent hash | `SHA256("a\|b\|c\|d")`, order-dependent | Canonical-JSON SHA-256, order-independent |
| Intent history | None (overwrite) | Immutable versions (v1, v2, …) |
| Intent lifecycle | None | 6-state machine, logged transitions |
| Key derivation | `SHA256(qkey + intent_hash + emotion)` | `HKDF-SHA256(IKM=qkey, salt=session_id, info=intent_hash+op)` |
| Emotion in crypto path | Yes (expression gates key derivation) | No — face auth produces identity confidence only, feeds risk engine, never the key |
| Policy enforcement | None (decrypt = hash string match) | Dedicated policy engine runs pre-derivation |
| Risk output | Score + 3-tier label | Same 3-tier model, kept, minus the emotion factor |
| Audit log | Flat table, no integrity guarantee | Hash-chained, tamper-evident |
| Database | SQLite, 4 tables | PostgreSQL, normalized ~8+ tables, Alembic-managed |
| Backend framework | Flask, logic in routes | FastAPI, layered services, DI, routes are thin |
| BB84 | Real Qiskit circuits (kept) | Same, relocated + kept independent |

---

## 8. Policy Engine

Runs **before** HKDF derivation, against the *recreated* CID at decrypt time (and against the *original* CID at encrypt time for authoring-time validation). Policy is a list of rule objects, each independently pass/fail:

- `AllowedOperationRule` — `cid.operation` in the resource's allowed-operations set
- `AllowedDeviceRule` — `cid.device_id` in an allow-list (or matches the device that encrypted, depending on policy mode)
- `SessionTimeoutRule` — `now - cid.valid_from < max_session_duration`
- `ValidityPeriodRule` — `cid.valid_from <= now <= cid.valid_until`
- `ResourceMatchingRule` — `cid.resource` matches the resource being acted on
- `RoleMatchingRule` — requesting user's role satisfies the operation's required role

All rules must pass to proceed to HKDF. Any single failure is logged to the audit chain with which rule failed and short-circuits to a `403`-style rejection — this is the mechanism that makes "purpose changed", "device changed", "expired intent" etc. (your demonstration scenarios) fail *before* any cryptographic operation runs, not just because the AES tag happens not to verify. (Note: because the intent hash is also baked into the HKDF `info`, a changed CID would fail decryption anyway even if a policy check were skipped — policy and canonical-hash verification are two independent, reinforcing controls, which is worth stating explicitly in the threat model.)

---

## 9. Database Schema (PostgreSQL, normalized)

```
users                  (id, username, email, password_hash, salt, role, created_at)
face_auth_logs         (id, user_id, confidence_score, verified, device_id, created_at)
sessions                (id, user_id, device_id, issued_at, expires_at, revoked)
intents                 (id, current_version_id, canonical_hash, lifecycle_state,
                          created_by, created_at)
intent_versions          (id, intent_id, version_number, cid_json, canonical_hash,
                          author, reason, created_at)
policies                 (id, name, rule_type, config_json, active, created_at)
encryption_records        (id, ciphertext, nonce, auth_tag, intent_hash, intent_version_id,
                            created_by, created_at)
audit_logs                (id, timestamp, user_id, action, intent_hash, result,
                            prev_log_hash, current_log_hash)
risk_assessments           (id, user_id, session_id, score, level, factors_json, created_at)
```

`encryption_records` stores ciphertext/nonce/tag/intent_hash/timestamp only — never a key, matching your requirement. `intent_versions` is append-only; `intents.current_version_id` is the only mutable pointer.

---

## 10. Risk Engine

Keeps the reference project's weighted-factor approach (it's a reasonable, explainable model for a prototype) but removes emotion-as-key-factor and reframes face auth correctly:

| Factor | Reference | New |
|---|---|---|
| QBER | ✓ kept | ✓ kept |
| Failed logins | ✓ kept | ✓ kept |
| "emotion_valid" | face expression allowed/blocked | **removed from risk; replaced by** `face_confidence_low` (identity-verification confidence below threshold) |
| Session expired | ✓ kept | ✓ kept |
| Device mismatch | ✓ kept | ✓ kept |
| Rapid access attempts | ✓ kept | ✓ kept |
| Policy failures | not present | **added** — a failed policy rule contributes to risk even in cases where you want to *warn* rather than hard-block |

Output stays 3-tier (Low/Medium/High) with the mapping your spec defines: Low → proceed to decrypt, Medium → require face re-verification, High → reject. This is a clean place to plug in the reused face-auth *identity* check as the medium-risk step-up, without it ever having touched the key.

---

## 11. Audit Module (tamper-evident)

```
current_log_hash = SHA256(prev_log_hash || timestamp || user_id || action || intent_hash || result)
```

Each row stores both hashes. Verifying integrity is a single linear walk recomputing the chain; any modified historical row breaks the chain from that point forward, which is exactly what your "Tampered Audit Log" demonstration scenario needs to show.

---

## 12. Face Authentication — Boundary

Reused: face-api.js model loading, `react-webcam` capture, TinyFaceDetector pipeline.
**Not reused:** expression classification as an access gate.

New contract: the face-auth service returns `{verified: bool, confidence: float, device_id, timestamp}` — identity/liveness only. This feeds `risk_assessments` and can be the step-up check for Medium risk. It never appears in `info` or `salt` for HKDF, and never appears in the CID. This is the one place where the reference project's actual behavior conflicts with an explicit instruction in your brief ("This is not about detecting human intentions or emotions"), so I've called it out rather than quietly dropping it — flag if you actually want an emotion-adjacent signal kept somewhere non-cryptographic (e.g., purely for the demo narrative), otherwise it's cut entirely.

---

## 13. Threat Model (mapping, to be expanded in final docs)

| Threat | Mitigation |
|---|---|
| Replay attack | `session_id` bound into HKDF salt + policy `SessionTimeoutRule`; reused ciphertext against a new session fails key derivation |
| Session hijacking | JWT short TTL, `device_id` in CID + `AllowedDeviceRule`, session table with revocation |
| Key misuse | No raw quantum key or derived AES key ever persisted; HKDF `info` binds key to one specific intent+operation |
| Device substitution | `AllowedDeviceRule`, device_id embedded in canonical hash |
| Intent tampering | Any CID field change alters the canonical hash → HKDF `info` differs → AES-GCM auth tag fails to verify; independently, policy re-evaluation also fails |
| Unauthorized decryption | Policy engine (role/resource matching) runs pre-derivation; AES-GCM provides authenticated encryption as a second layer |
| Insider misuse | Tamper-evident audit chain, immutable intent versioning (can't quietly edit an approved intent) |

---

## 14. Security Assumptions (to document explicitly in final deliverable)

- BB84 is simulated on Qiskit Aer, not run over a real quantum channel — this is a research prototype demonstrating the *binding architecture*, not a QKD hardware deployment.
- JWT stored in `localStorage` on the frontend (reference project's approach, carried forward for prototype simplicity) — a production system would use httpOnly cookies; worth a line in the docs as a known limitation.
- Single-server trust boundary: policy engine, HKDF, and AES all execute server-side; the browser is untrusted for anything except face-capture pixels and CID field entry.
- PostgreSQL and the audit chain assume the DB itself isn't compromised at the storage layer (hash-chain protects against *application-level* tampering/edits, not a DBA rewriting history with recomputed hashes — call this out as an explicit non-goal unless you want log anchoring/external notarization added).

---

## 15. Open Questions Before Implementation

1. **Face-auth boundary (§12):** confirm cutting expression-as-signal entirely, vs. keeping it only for demo narrative/UI flavor with zero cryptographic or risk-engine weight.
2. **HKDF `info` binding:** intent_hash + operation as shown, or would you also want `device_id` folded into `info` directly (redundant with the policy check, but adds defense-in-depth at the crypto layer itself)?
3. **Intent reuse policy:** should an `Approved` intent be usable for multiple encrypt/decrypt calls within its validity window, or strictly single-use (`Approved → Used` is terminal)? Affects the lifecycle state machine and a demonstration scenario.
4. **JWT storage:** keep `localStorage` (reference project's approach) or move to httpOnly cookies for the new build?
5. Anything in the module list, DB schema, or endpoint set above you want changed before I start on the backend skeleton?

---

**Next step, on your approval:** scaffold `backend/` module structure, SQLAlchemy models + first Alembic migration, and the `intent/` canonicalizer with unit tests (this is the piece everything else depends on) — before touching `quantum/`, `crypto/`, or the frontend.
