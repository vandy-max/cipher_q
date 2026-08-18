"""
Development-only seed script: creates the FIRST admin account (and,
optionally, a plain demo user) directly in the database.

Why this exists at all: by design, there is NO public API endpoint that
lets anyone grant themselves — or anyone else — an elevated role.
`POST /api/auth/register` always creates a `USER_LEVEL_1` account (see
`api/routers/auth.py`), and `PUT /api/users/{id}/role` (admin-only user
management) requires an existing ADMIN's token to call. That's correct
separation-of-duties behavior, but it means a brand-new, empty database
has no admin to bootstrap from. This script is the documented,
out-of-band way to create that first admin — the same pattern the
`scripts/e2e_smoke_*.py` tests already use (`_make_admin()`), just
promoted to a real, reusable, CLI-driven tool instead of test-only
inline code.

This is NOT wired into any HTTP route, and it is NOT run automatically
on startup. It must be invoked explicitly, on a machine that already
has direct database access — the same trust boundary a real ops/DBA
action would require. It is safe to re-run: it will not overwrite an
existing user's password or role.

Usage (from backend/):
    python3 scripts/seed_admin.py
    python3 scripts/seed_admin.py --admin-username myadmin --admin-password "S0meStr0ngP@ss!"
    python3 scripts/seed_admin.py --no-demo-user     # skip creating the demo USER_LEVEL_1 account

Face authentication is unaffected either way: whoever logs in with
these credentials still has to separately enroll + verify their face
(`POST /api/face/enroll`, `POST /api/face/verify`) like any other
account — role has nothing to do with the face-auth requirement.

SECURITY NOTE: change the seeded admin password immediately in any
environment beyond a local demo. This script exists to solve the
"first admin" bootstrap problem, not to be a permanent credential.
"""
from __future__ import annotations

import argparse
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from authentication.password import generate_salt, hash_password  # noqa: E402
from database.session import db  # noqa: E402

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "AdminSetup#2026"
DEFAULT_ADMIN_EMAIL = "admin@cipherq.local"

DEFAULT_USER_USERNAME = "demo_user"
DEFAULT_USER_PASSWORD = "DemoUser#2026"
DEFAULT_USER_EMAIL = "demo_user@cipherq.local"


def _next_id(counter_name: str) -> int:
    doc = db["counters"].find_one_and_update(
        {"_id": counter_name}, {"$inc": {"seq": 1}}, upsert=True, return_document=True
    )
    return doc["seq"]


def _seed_user(username: str, email: str, password: str, role: str) -> str:
    existing = db["users"].find_one({"username": username})
    if existing is not None:
        return f"'{username}' already exists (role={existing.get('role')}) — left untouched"

    salt = generate_salt()
    password_hash = hash_password(password, salt)
    db["users"].insert_one(
        {
            "_id": _next_id("users"),
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "salt": salt,
            "role": role,
            "face_descriptor": None,
        }
    )
    return f"created '{username}' with role={role}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin-username", default=DEFAULT_ADMIN_USERNAME)
    parser.add_argument("--admin-password", default=DEFAULT_ADMIN_PASSWORD)
    parser.add_argument("--admin-email", default=DEFAULT_ADMIN_EMAIL)
    parser.add_argument("--user-username", default=DEFAULT_USER_USERNAME)
    parser.add_argument("--user-password", default=DEFAULT_USER_PASSWORD)
    parser.add_argument("--user-email", default=DEFAULT_USER_EMAIL)
    parser.add_argument(
        "--no-demo-user", action="store_true", help="only seed the admin, skip the demo USER_LEVEL_1 account"
    )
    parser.add_argument(
        "--random-admin-password",
        action="store_true",
        help="ignore --admin-password and generate a random one (printed once, not stored anywhere)",
    )
    args = parser.parse_args()

    admin_password = args.admin_password
    if args.random_admin_password:
        admin_password = secrets.token_urlsafe(16)

    print(_seed_user(args.admin_username, args.admin_email, admin_password, role="ADMIN"))
    if not args.no_demo_user:
        print(_seed_user(args.user_username, args.user_email, args.user_password, role="USER_LEVEL_1"))

    print()
    print("Login with these via POST /api/auth/login. Change the admin password")
    print("immediately in any environment beyond a local demo.")
    print(f"  admin username: {args.admin_username}")
    print(f"  admin password: {admin_password}")
    if not args.no_demo_user:
        print(f"  demo user username: {args.user_username}")
        print(f"  demo user password: {args.user_password}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
