"""
One-time data migration: remaps every existing `users` document's
`role` field from the old five-role model
(STANDARD_USER/UNIT_MANAGER/SECURITY_ANALYST/DATABASE_ADMIN/
SYSTEM_ADMIN/AUDITOR) to the new three-tier model
(ADMIN/USER_LEVEL_2/USER_LEVEL_1) defined in `api/rbac.py`.

Why this is needed: a user's role is baked into their JWT at login
time by reading `users.role` straight out of the database (see
`authentication/service.py`), so renaming the role constants in code
alone does not affect any already-registered account — those users
would silently fall back to being treated as an unrecognized role
(effectively zero privilege) on their next login unless their stored
`role` value is updated too. New registrations already get the new
names automatically the moment `api/rbac.py` was updated, since
`DEFAULT_SELF_REGISTER_ROLE` now points at `USER_LEVEL_1`.

Mapping (chosen to exactly preserve which users are currently treated
as "admin" for authorization/policy management, per the pre-existing
`ADMIN_ROLES = {SYSTEM_ADMIN, SECURITY_ANALYST}` set in
`api/rbac.py`'s prior version — see `CHANGELOG_RBAC_THREE_TIER.md`):

    SYSTEM_ADMIN     -> ADMIN
    SECURITY_ANALYST -> ADMIN
    DATABASE_ADMIN   -> USER_LEVEL_2
    UNIT_MANAGER     -> USER_LEVEL_2
    AUDITOR          -> USER_LEVEL_2
    STANDARD_USER    -> USER_LEVEL_1

Usage:
    cd backend
    python3 scripts/migrate_roles_to_three_tier.py            # dry run, prints what would change
    python3 scripts/migrate_roles_to_three_tier.py --apply     # actually writes the changes

Safe to run more than once: any document whose `role` is already one
of the three new names, or any unrecognized value, is left untouched
and reported separately.
"""
from __future__ import annotations

import argparse
import sys

from database.models import USERS_COLLECTION
from database.session import db

_ROLE_MAP = {
    "SYSTEM_ADMIN": "ADMIN",
    "SECURITY_ANALYST": "ADMIN",
    "DATABASE_ADMIN": "USER_LEVEL_2",
    "UNIT_MANAGER": "USER_LEVEL_2",
    "AUDITOR": "USER_LEVEL_2",
    "STANDARD_USER": "USER_LEVEL_1",
}

_NEW_ROLE_NAMES = {"ADMIN", "USER_LEVEL_2", "USER_LEVEL_1"}


def migrate(apply: bool) -> int:
    """Returns the number of documents that were (or, in dry-run mode,
    would be) updated."""
    users = db[USERS_COLLECTION]
    updated = 0
    unrecognized: list[tuple[int, str]] = []

    for doc in users.find({}):
        current_role = doc.get("role")
        if current_role in _NEW_ROLE_NAMES:
            continue
        new_role = _ROLE_MAP.get(current_role)
        if new_role is None:
            unrecognized.append((doc["_id"], current_role))
            continue

        verb = "would remap" if not apply else "remapping"
        print(f"user _id={doc['_id']} username={doc.get('username')!r}: "
              f"{verb} role {current_role!r} -> {new_role!r}")
        if apply:
            users.update_one({"_id": doc["_id"]}, {"$set": {"role": new_role}})
        updated += 1

    if unrecognized:
        print("\nSkipped documents with an unrecognized role (left untouched):")
        for user_id, role in unrecognized:
            print(f"  user _id={user_id}: role={role!r}")

    return updated


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply", action="store_true",
        help="actually write the changes (default: dry run, prints only)",
    )
    args = parser.parse_args()

    count = migrate(apply=args.apply)
    if args.apply:
        print(f"\nDone — {count} user document(s) updated.")
    else:
        print(f"\nDry run — {count} user document(s) would be updated. Re-run with --apply to write.")
    sys.exit(0)


if __name__ == "__main__":
    main()
