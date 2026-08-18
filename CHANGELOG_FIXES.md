# CipherQ — Full Project Audit & Bug-Fix Pass

This pass tested every layer of the app the way a real deployment would
exercise it — not just the bundled `pytest` suite (which calls services
and routers directly), but a real, live FastAPI app receiving real HTTP
requests, with real request/response validation and the real
Mongo-datetime round-trip behavior. Two reusable smoke-test scripts were
added at `backend/scripts/e2e_smoke_core.py` and
`backend/scripts/e2e_smoke_revocation_and_audit.py` — run them any time
after future changes to catch this whole class of bug immediately, e.g.:

```bash
cd backend
python3 scripts/e2e_smoke_core.py
python3 scripts/e2e_smoke_revocation_and_audit.py
```

(They use `mongomock` as an in-memory MongoDB stand-in — no real
`mongod` required — but reproduce MongoDB's actual BSON datetime
truncation behavior, which is what surfaced two of the bugs below.)

## Bugs found and fixed

All 160 tests in `backend/tests/` were passing *before* this pass. Every
bug below is real and was invisible to that suite because it only
exercises the service/router layer directly, not the full HTTP +
dependency-injection + database round-trip.

### 1. The live server could not start at all
`api/routers/monitoring.py`'s `stop_monitoring` route declared
`status_code=204` without also setting `response_class=Response,
response_model=None` — the same pattern already used correctly in
`face.py` and `policies.py` for their own 204 routes. FastAPI raises at
import time on a 204 route with an implicit non-`None` response model,
so **the app has never actually booted** in this codebase. This alone
would have produced an immediate, unconditional crash the instant
anyone tried to run it — no request even needed to reach it.

**Fix:** `api/routers/monitoring.py` — added the same
`response_class=Response, response_model=None` used elsewhere.

### 2. Session-expiry checks crashed with `TypeError`
`authorization/sessions.py::is_session_valid` compared a
timezone-*aware* `datetime.now(timezone.utc)` against `expires_at` read
back from MongoDB, which round-trips as timezone-*naive*. Comparing
aware and naive datetimes raises `TypeError` in Python. This crashed
`/api/intent/validate` and any monitoring/session-expiry check the
moment a session record had actually been through the database.

The codebase already has this exact fix pattern in three other places
(`audit/hash_chain.py`, `intent/canonicalizer.py`, `intent/schema.py`)
— this one call site was missed.

**Fix:** `api/repositories.py::_to_session_state` now normalizes
`expires_at` back to UTC-aware at the point it's read from Mongo (the
single, correct place to fix it — every other reader of `SessionState`
benefits). `authorization/sessions.py::is_session_valid` also got a
defensive normalization as a second line of defense.

### 3. Decrypting anything you just encrypted always failed
This is the most serious bug: **the primary encrypt → decrypt round
trip never worked**, for any record, ever. `authorization/state.py`'s
crypto-binding hash includes the intent's lifecycle state, and the
system's own documented design has a successful encryption
automatically transition the intent `APPROVED → USED` as a side
effect. So the hash computed at encrypt time (lifecycle = `approved`)
could never match the hash recomputed at decrypt time (lifecycle =
`used`), and every decrypt failed with an "authorization state
mismatch" error — even decrypting the exact ciphertext you'd just
produced, seconds earlier, in the same session.

**Fix:** `authorization/state.py` now binds an *authorization class*
into the hash instead of the raw lifecycle value — both `APPROVED` and
`USED` are "still authorized, unrevoked" states (this is already the
system's own `CRYPTO_ELIGIBLE_STATES` set; anything outside it is
rejected before a hash is even built), so they now hash identically.
Every other invalidation path — device revocation, session revocation,
policy changes, session re-authorization — is carried by its own
separate field in the same hash and is completely unaffected; nothing
about the system's actual security properties changed, only the false
rejection of the expected, legitimate case.

### 4. Audit-chain integrity check false-positived as COMPROMISED
The tamper-evident audit hash chain reported `COMPROMISED` on a
perfectly untouched chain, before any tampering had occurred — which
would make the audit dashboard look broken from the very first
recorded event. Root cause: MongoDB's BSON datetime type only stores
millisecond precision, silently truncating the bottom 3 digits of a
Python `datetime`'s microseconds on every round trip.
`AuditLogService.record()` computed each entry's hash using the
full-microsecond-precision timestamp *before* it was ever written to
the database; `verify_integrity()` later recomputes the same hash from
the truncated, read-back timestamp — a different value, so the digests
never matched.

**Fix:** `audit/service.py::record()` now truncates the timestamp to
millisecond precision *before* hashing, so the hashed value and the
value that ends up persisted/re-read are bit-identical. (One existing
unit test asserted timestamp equality down to the microsecond; it's
been adjusted to allow up to 1ms of the now-intentional floor-rounding,
since that's a real, permanent property of the fix rather than a test
bug.)

### 5. Stray junk directory in the frontend source tree
`frontend/src/{components,hooks,pages,services,styles}` — a literal,
empty directory left over from an unexpanded shell brace-glob
(`mkdir -p src/{a,b,c}` run under a shell without brace expansion).
Harmless to the build, but removed for cleanliness.

## Verified working end-to-end (via the new smoke scripts + full stack)

- Register / login / bad-password rejection
- Face enrollment, status, verification
- BB84 quantum key generation
- Device/session establishment, status, revoke/unrevoke
- Intent validation (pre-create and against a created intent)
- Full lifecycle: Draft → Approved → Used, including rejecting
  encryption attempts against non-Approved intents (409, not a crash)
- Continuous-authorization state endpoint
- Continuous monitoring: start, heartbeat, status, events, stop
- **Full encrypt → decrypt round trip succeeds** (previously always
  broken — see bug #3)
- Risk assessment endpoint, low- and high-risk inputs
- Device revocation blocking subsequent intent approval
- Session revocation blocking subsequent encryption
- Policy CRUD (create/list/update/delete, 404 on stale reference)
- Audit log listing and hash-chain verification
- **Audit tamper detection**: a genuinely tampered entry is correctly
  reported `COMPROMISED` with the first invalid index — and a clean
  chain no longer false-positives (see bug #4)
- **Full revocation demonstration**: repeated face-verification
  failures escalate risk (`medium` → `high`) and produce the documented
  warning messages ("reauthentication required"), session revocation
  is reflected immediately in the next monitoring heartbeat, and
  crypto operations are correctly blocked afterward
- Auth failure paths: missing/garbage bearer tokens → 401, not 500
- 160/160 existing unit tests still pass

## Frontend

- `npm install && npm run build` completes cleanly (only a benign
  "chunk larger than 500kB" advisory, not an error)
- `frontend/src/services/api.js` was checked field-by-field against
  every backend request/response schema exercised above — all request
  bodies, field names, and status-code expectations match exactly
- Spot-checked `Dashboard.jsx`, `AuditLogsPage.jsx`,
  `MonitoringContext.jsx`, `EncryptionPage.jsx` for response-shape
  assumptions and error handling; all API calls are wrapped in
  try/catch or `.catch()`, and error rendering (`Alert`) already
  guards against empty/undefined messages

## Scope note

This pass focused on making the existing Phase 1–4 implementation
correct and crash-free end-to-end, per the request to eliminate
internal server errors and disconnects. It did not build the
additional Phase 5 UI surfaces described in the attached brief (a
dedicated admin/security-analyst dashboard view, an explicit
DRAFT→...→DESTROYED lifecycle diagram component, a standalone
revocation-demonstration screen) — the underlying data and endpoints
for all of those already exist and work correctly (see above), but the
dedicated UI screens themselves are still to be built. Happy to build
those out next if wanted.

## Known pre-existing flake (not fixed, not introduced by this pass)

`tests/test_quantum.py::test_full_eavesdropper_raises_qber_and_aborts`
uses an unseeded random BB84 simulation and asserts the resulting QBER
exceeds the abort threshold. Because eavesdropping is modeled
probabilistically, this occasionally (rarely) comes in under threshold
by chance and fails — reproduced as a pass on 3/3 immediate re-runs.
This is pre-existing randomness in `quantum/bb84.py` (which this pass
deliberately did not touch, per the standing "never touch BB84"
constraint) rather than a real bug; if it matters, the fix would be to
seed the simulation's RNG per test run.

