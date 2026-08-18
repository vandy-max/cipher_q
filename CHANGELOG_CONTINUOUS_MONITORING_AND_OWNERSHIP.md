# CipherQ — Continuous Biometric Monitoring + Generalized Ownership

Scope: exactly the two items requested. Nothing else was redesigned;
existing RBAC, intent lifecycle, cryptography (BB84/HKDF/AES-256-GCM),
risk engine, audit chain, and APIs are unchanged except where noted.

## 1. True continuous biometric monitoring (previously reused login confidence)

**Root cause confirmed:** `frontend/src/context/MonitoringContext.jsx`
never reopened the camera after login — it cached the confidence value
from the initial `/api/face/verify` call and replayed it on every
heartbeat. The backend heartbeat logic itself was already correct
(it re-evaluates whatever telemetry it's given); the gap was entirely
that the frontend was never generating fresh telemetry to give it.

**Fixed:**
- `frontend/src/context/MonitoringContext.jsx` — rewritten. Mounts a
  hidden `react-webcam` stream only while a monitoring session is
  active (never in the background), and on a configurable interval
  (`VITE_MONITORING_INTERVAL_MS`, default 8000ms):
  1. captures a fresh frame,
  2. runs `detectFaceLite` (presence) + `assessQuality` (liveness/
     quality proxy) — both already existed, used elsewhere for
     enrollment/verification UX,
  3. if a face is present, extracts a fresh 128-d descriptor and calls
     the existing `/api/face/verify` endpoint (server-side comparison
     against the caller's own enrolled descriptor — never a cached
     value),
  4. sends only derived telemetry (`face_present`, `face_match_confidence`,
     `liveness`, `camera_available`) to `/api/monitoring/heartbeat` —
     never raw video/frames.
  - Camera permission denial / device loss surfaces as `cameraState:
    'unavailable'`, fed into the heartbeat as `camera_available: false`
    rather than silently reporting success.
  - Repeated heartbeat failures (network/backend unreachable) surface
    as `connectionState: 'lost'` after 2 consecutive misses, instead
    of indefinitely showing the last-known `ACTIVE` badge.
  - `simulateFaceFailure()` is kept, explicitly as a demo/test override
    layered on top of the real loop (see the already-labelled "(demo)"
    button in the UI) — it forces one tick's outcome; it never
    replaces the camera-driven path.
- `frontend/src/services/api.js` — `monitoringHeartbeat()` now also
  sends `camera_available`.
- `frontend/src/components/monitoring/MonitoringBadge.jsx` — now shows
  Identity Check (`IDENTITY CONFIRMED` / `IDENTITY MISMATCH` / `NO FACE
  DETECTED` / `LIVENESS UNCERTAIN` / `CAMERA UNAVAILABLE`), Camera
  state, and Connection state (LIVE / LOST), in addition to the
  existing Face/Liveness/Risk/Authorization rows.

**Backend additions (state was already re-evaluated correctly; these
make the per-tick identity result explicit rather than implicit):**
- `backend/monitoring/state.py` — new `IdentityCheckState` enum
  (`IDENTITY_CONFIRMED`, `IDENTITY_MISMATCH`, `NO_FACE`,
  `LIVENESS_UNCERTAIN`, `CAMERA_UNAVAILABLE`) and a pure
  `derive_identity_state(...)` function; added `identity_state` field
  to `MonitoringSnapshot`.
- `backend/monitoring/service.py` — `heartbeat()` accepts
  `camera_available`; `_evaluate()` computes `identity_state` from the
  same facts that decide pass/fail, and appends an explicit warning on
  mismatch/camera-unavailable rather than staying silent.
- `backend/api/schemas.py` / `backend/api/routers/monitoring.py` —
  `camera_available` accepted on `/monitoring/heartbeat`,
  `identity_state` returned on every snapshot response.

## 2. Generalized, domain-neutral ownership model

**Audit result:** the ownership *architecture* (`require_owner_or_admin`,
device/session owner claims in `api/routers/authorization.py`) was
already principal/resource-based and domain-neutral. The only
banking-specific hardcoding found anywhere in the codebase was two
role identifiers.

**Fixed:**
- `backend/api/rbac.py` — `BANK_EMPLOYEE` → `STANDARD_USER`,
  `BRANCH_MANAGER` → `UNIT_MANAGER`. Privilege levels and every other
  role (`SECURITY_ANALYST`, `DATABASE_ADMIN`, `SYSTEM_ADMIN`, `AUDITOR`)
  unchanged. `DEFAULT_SELF_REGISTER_ROLE` updated to match.
- `backend/tests/test_rbac_and_ownership.py` — role strings updated to
  match (mechanical rename only).

**Real gap found and fixed — monitoring-start ownership (Part 14):**
`POST /api/monitoring/start` accepted `device_id`/`session_id` from the
request body and created a monitoring session **without verifying the
caller owned either one**. Fixed in
`backend/api/routers/monitoring.py`: before creating a monitoring
session it now requires (a) the session to exist and be owned by the
caller (or an admin role), and (b) the device_id in the request to
match the device that session was actually authorized for, and (c) if
the device has any other recorded owner, that the caller is that owner
or an admin. Checked and rejected *before* any monitoring record is
created or mutated — not discovered afterward.

## Tests executed

All run for real in this environment (`pytest` + two live-HTTP smoke
scripts against `mongomock`; a full Vite production build). Nothing
was skipped, commented out, or mocked away to force a pass.

- `pytest` (backend, full suite): **245 passed**, 0 failed, 0 skipped
  (was 230 before this pass; 15 new tests added: 9 identity-state unit
  tests in `test_monitoring.py`, 6 ownership tests in
  `test_rbac_and_ownership.py`, incl. the specific "User B cannot start
  monitoring using User A's device/session" case from the spec).
- `scripts/e2e_smoke_core.py` — full live-HTTP workflow incl.
  monitoring start/heartbeat/status/events/stop: **ALL CHECKS PASSED**.
- `scripts/e2e_smoke_revocation_and_audit.py` — degraded-face
  heartbeats escalating WARNING → REAUTH_REQUIRED, session revoke,
  audit-tamper detection: **ALL CHECKS PASSED** (output shows the new
  `"detected face does not match enrolled identity"` warning firing
  correctly on live heartbeats).
- `npm run build` (frontend, Vite production build): **succeeded**,
  no new errors introduced (pre-existing chunk-size warning from
  face-api.js is unrelated to this change).

## Not verifiable in this environment (be aware before you rely on them)

- No real webcam/browser to click through Camera permission →
  ACTIVE → WARNING → REAUTH_REQUIRED → REVOKED end-to-end visually.
  The logic is unit- and smoke-tested; a manual pass in an actual
  browser with a real camera is still worth doing before a demo.
- No deployment target (Render/Vercel/MongoDB Atlas) reachable from
  this sandbox — Part 21 (deployment verification) was not performed.
  Local run instructions are unchanged from the existing project
  README/docs.
- Attack-scenario matrix (Part 20) beyond what the existing test suite
  already covers (revoked device/session, expired session, wrong
  role, tampered audit chain — all exercised above) was not run as a
  separate dedicated pass.

## Files changed

```
backend/api/rbac.py
backend/api/routers/monitoring.py
backend/api/schemas.py
backend/monitoring/service.py
backend/monitoring/state.py
backend/tests/test_monitoring.py
backend/tests/test_rbac_and_ownership.py
frontend/.env.example
frontend/src/components/monitoring/MonitoringBadge.jsx
frontend/src/context/MonitoringContext.jsx
frontend/src/services/api.js
```
