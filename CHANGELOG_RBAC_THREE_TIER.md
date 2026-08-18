# CipherQ — RBAC Consolidation to Three-Tier Role Model

Targeted change for one requirement from the security-hardening pass:
*"final roles are ADMIN, USER_LEVEL_2, USER_LEVEL_1."*

## Before

`backend/api/rbac.py` defined five roles with privilege levels 1–5:
`STANDARD_USER (1)`, `AUDITOR (2)`, `UNIT_MANAGER (3)`,
`SECURITY_ANALYST (3)`, `DATABASE_ADMIN (4)`, `SYSTEM_ADMIN (5)`.
`ADMIN_ROLES` (used to gate policy management and device/session
revocation) was `{SYSTEM_ADMIN, SECURITY_ANALYST}`. A separate,
broader set in `api/routers/audit.py` (`SYSTEM_ADMIN,
SECURITY_ANALYST, DATABASE_ADMIN, AUDITOR`) gated audit-log reads.

## After

Three roles: `ADMIN`, `USER_LEVEL_2`, `USER_LEVEL_1`, with mapping
chosen to preserve every existing role's current capability set
exactly (no privilege silently expanded or narrowed beyond the
unavoidable consequence of merging distinct old roles into one new
tier):

| Old role            | New role       |
|----------------------|----------------|
| `SYSTEM_ADMIN`        | `ADMIN`        |
| `SECURITY_ANALYST`    | `ADMIN`        |
| `DATABASE_ADMIN`      | `USER_LEVEL_2` |
| `UNIT_MANAGER`        | `USER_LEVEL_2` |
| `AUDITOR`             | `USER_LEVEL_2` |
| `STANDARD_USER`       | `USER_LEVEL_1` |

This mapping was derived directly from the pre-existing `ADMIN_ROLES`
set (`SYSTEM_ADMIN`+`SECURITY_ANALYST` — unchanged membership, just
renamed to `ADMIN`) and the pre-existing audit-read set, which
collapses cleanly to `{ADMIN, USER_LEVEL_2}` under this mapping with
no member gaining or losing audit-read access.

**One real, unavoidable behavior change:** the old model had
`UNIT_MANAGER` specifically *excluded* from audit-log read access
while `AUDITOR`/`DATABASE_ADMIN` (nominally lower- or higher-privilege)
were included — a fine-grained distinction that only existed because
they were five separate roles. Collapsing to three tiers necessarily
merges `UNIT_MANAGER` into the same `USER_LEVEL_2` bucket as
`AUDITOR`/`DATABASE_ADMIN`, so it now shares their audit-read access.
This is the direct, intended effect of the "exactly three roles"
requirement, not an oversight.

## Files changed

- `backend/api/rbac.py` — role constants, `ROLE_DEFAULT_PRIVILEGE`, `ADMIN_ROLES`, `SUPER_ADMIN_ROLES`, `DEFAULT_SELF_REGISTER_ROLE`
- `backend/api/routers/policies.py` — `require_roles("SYSTEM_ADMIN", "SECURITY_ANALYST")` → `require_roles("ADMIN")`
- `backend/api/routers/authorization.py` — same, plus docstring updates
- `backend/api/routers/audit.py` — `_AUDIT_READ_ROLES` → `("ADMIN", "USER_LEVEL_2")`
- `backend/scripts/e2e_smoke_core.py`, `backend/scripts/e2e_smoke_revocation_and_audit.py` — demo admin role strings
- `backend/scripts/migrate_roles_to_three_tier.py` — **new**: one-time data migration for existing `users` documents (see below — code-only renaming does not affect already-registered accounts)
- `backend/tests/test_rbac_and_ownership.py` — role strings updated; two role-parametrized tests consolidated (5→3 roles means some previously-distinct parametrize cases became duplicates of each other); one test (`test_unit_manager_cannot_read_audit_logs`) removed because its premise — a role excluded from audit-read while nominally-similar roles are included — no longer exists once those roles merge into one

No frontend changes were needed: the UI renders `user.role` directly
from whatever the API returns (`Topbar.jsx`, `ProfilePage.jsx`,
`SettingsPage.jsx`) with no hardcoded role list.

## Migration for existing data

A user's role is baked into their JWT at login by reading
`users.role` from the database (`authentication/service.py`), so
renaming the constants in code has **no effect on already-registered
accounts** until their stored `role` value is also updated — run:

```bash
cd backend
python3 scripts/migrate_roles_to_three_tier.py            # dry run
python3 scripts/migrate_roles_to_three_tier.py --apply     # writes the change
```

New registrations are unaffected and already get `USER_LEVEL_1`
automatically (`DEFAULT_SELF_REGISTER_ROLE`).

## Verification

Full backend suite: `259 passed` (down from 264 after the previous
policy-enforcement change, entirely explained by the 5 tests removed/
consolidated above — no unexpected failures). `python -c "import
api.main"` confirms the app still boots. Migration script smoke-tested
against an in-memory `mongomock` database with one document per old
role plus one already-migrated and one unrecognized role, confirming
correct remapping and that unrecognized values are left untouched
rather than guessed at.
