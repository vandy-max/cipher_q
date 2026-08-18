# Intent-Bound Quantum Cryptography (IBQC)

A research-quality prototype demonstrating that secure key establishment
alone is insufficient: encryption keys derived from a BB84 quantum
channel are cryptographically bound to a **Cryptographic Intent
Descriptor (CID)** — a structured, deterministic, verifiable
authorization context — so that decryption succeeds only when the
approved operational context matches the original authorization.

See `docs/architecture-design-document.md` for the full design
rationale, including a detailed comparison against the reference
project this repo was inspired by (what was reused, what was
redesigned, and why).

## Status

This is being built incrementally, module by module, in dependency
order. Current state:

- [x] `intent/` — CID schema, canonicalizer, lifecycle state machine, versioning (with unit tests)
- [x] `database/` — MongoDB (PyMongo) document repositories
- [x] `quantum/` — BB84 simulation (adapted from reference project, kept independent)
- [x] `crypto/` — HKDF + AES-256-GCM, `EncryptionService` enforcing the intent-binding claim
- [x] `policy/` — rule engine (6 rules) + risk engine (Low/Medium/High -> action)
- [x] `audit/` — hash-chained, tamper-evident audit log
- [x] `authentication/` — JWT + password hashing + face-auth (identity verification via descriptor distance, never expression)
- [x] `api/` — FastAPI routers: `/api/auth`, `/api/face`, `/api/intent`, `/api/encrypt`, `/api/decrypt`, `/api/audit`, `/api/policies`, `/api/quantum`, `/api/risk`
- [x] `frontend/` — React + Vite + Tailwind. 11 pages: Landing, Login/Register, Dashboard, Create Intent, Intent History, BB84 Simulation, Encrypt, Decrypt, Audit Logs, Policy Management, Visualization
- [ ] Demonstration-scenario integration tests / seed data
- [ ] Final docs pass (sequence/ER diagrams, deployment guide)
## Accounts & roles

The platform has three privilege tiers, defined in `backend/api/rbac.py`:

| Role | How it's created | What it can do |
|---|---|---|
| `USER_LEVEL_1` | Self-registration (default) | Create/submit intents; only ever sees and acts on their **own** records. Cannot approve any intent, including their own. No audit-log read access. |
| `USER_LEVEL_2` | Self-registration (opt-in) | Everything Level 1 can do, plus: sees **all** users' intents, can approve other users' intents (not their own), and can read the audit log. |
| `ADMIN` | Never self-registered — see below | Everything Level 2 can do, plus: bypasses ownership checks anywhere in the app, can approve their own intents, manages user roles (`PUT /api/users/{id}/role`), full audit access. |

### Signing up as a user

`POST /api/auth/register` (and the Register form in the UI) lets the
caller pick their starting tier via an optional `role` field:

```json
{ "username": "...", "email": "...", "password": "...", "role": "USER_LEVEL_2" }
```

- `role` is optional — omit it and the account defaults to `USER_LEVEL_1`.
- The only accepted values are `"USER_LEVEL_1"` and `"USER_LEVEL_2"`. Anything
  else (including `"ADMIN"`) is rejected outright by the request schema —
  self-service admin is not possible through this or any other endpoint.
- An existing `ADMIN` can still change a user's tier after the fact via
  `PUT /api/users/{id}/role`.

### Getting an admin account

Admin is deliberately **not** reachable through the API. The only way to
create one is the out-of-band bootstrap script:

```bash
cd backend
python3 scripts/seed_admin.py
# or with your own credentials:
python3 scripts/seed_admin.py --admin-username myadmin --admin-password "S0meStr0ngP@ss!"
# or a random one-time password, printed once and never stored:
python3 scripts/seed_admin.py --random-admin-password
```

This also seeds a `demo_user` (`USER_LEVEL_1`) unless you pass
`--no-demo-user`. Default bootstrap credentials (change immediately outside
a local demo):

| Field | Value |
|---|---|
| Username | `admin` |
| Password | `AdminSetup#2026` |
| Email | `admin@cipherq.local` |

The script is safe to re-run — it never overwrites an existing user's
password or role.
## Backend setup

This sandbox has no network access, so the code below has been
syntax-checked (`py_compile`) but not executed against real
dependencies. Run it locally:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# run the intent-module unit tests
pytest

# point at a running MongoDB instance (defaults shown below)
export MONGODB_URI="mongodb://localhost:27017"
export MONGODB_DATABASE="ibqc"

# run the API server
export JWT_SECRET="change-me"
uvicorn api.main:app --reload --port 8000
# interactive API docs at http://localhost:8000/docs
```

## Frontend setup

```bash
cd frontend
npm install
npm run dev
# opens on http://localhost:5173, proxies /api to the backend
```

face-api.js identity-verification models are already included under
`public/models/` (detector + landmarks + recognition — deliberately
*not* the expression model, since this project never classifies
expression). If you swap in a different model set, keep those three.

## Repository layout

```
backend/
  authentication/   # JWT + face-auth (identity/liveness only, no expression signal)
  intent/            # CID schema, canonicalizer, lifecycle, versioning
  quantum/           # BB84 simulation — intentionally independent of every other module
  crypto/            # HKDF derivation + AES-256-GCM, no key ever persisted
  policy/            # policy engine (runs before key derivation) + risk engine
  audit/             # hash-chained, tamper-evident audit log
  database/          # MongoDB (PyMongo) client, document repositories
  api/               # FastAPI routers — thin, no business logic
  tests/
frontend/
  src/
    pages/           # Login, Dashboard, CreateIntent, IntentHistory, BB84Simulation,
                      # Encryption, Decryption, AuditLogs, PolicyManagement, Visualization
docs/
  architecture-design-document.md
```
