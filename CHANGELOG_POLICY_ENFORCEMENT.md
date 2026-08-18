# CipherQ — Runtime Policy Enforcement Fix

Targeted fix for one requirement from the security-hardening pass:
*"persisted policies must actually affect runtime authorization."*

## The bug

The `policies` collection, `PolicyRepository`, `POST/PUT/DELETE
/api/policies`, and the Policy Management page in the frontend were
all fully implemented — an admin could create, edit, and delete
policy rows. But every place a `PolicyEngine` was constructed
(`api/dependencies.py:get_policy_engine`,
`authorization/service.py`, `intent/validation.py`) built it with no
arguments, and every place a `PolicyContext` was built passed only
`now` and `requesting_user_role` — every allow-list field
(`allowed_devices`, `allowed_operations`, `allowed_resources`,
`required_role_for_operation`) defaulted to `None`, meaning
"unrestricted." **Saved policies had zero effect on any real
encrypt/decrypt/authorize call.** The rule classes in `policy/rules.py`
were themselves correct and already read from `PolicyContext` — they
just never received the persisted configuration.

## The fix

New file `backend/policy/config.py`: a pure function,
`policy_context_overrides(policies)`, that maps active `Policy` rows
(keyed by the six existing `rule_type` values the frontend already
offers — `allowed_operation`, `allowed_device`, `session_timeout`,
`validity_period`, `resource_matching`, `role_matching`) onto the
`PolicyContext` keyword overrides those rule classes already consume.
Inactive rows and unrecognized `rule_type`s are skipped.

`AuthorizationService` and `IntentValidationService` each gained one
new **optional** constructor parameter, `policy_config_repository`.
When provided, they fetch policies and apply the overrides before
building `PolicyContext`; when omitted (every pre-existing test and
call site), behavior is byte-for-byte identical to before. Wired in
production via a new `get_policy_config_repository` FastAPI dependency
in `api/dependencies.py`, injected into `get_authorization_service`
and `get_intent_validation_service`.

`PolicyEngine` itself, `policy/rules.py`'s rule classes, and
`default_rules()` were **not** changed — the six rules still always
run (defense-in-depth, per the existing design); only the context they
evaluate against now reflects what's actually stored in the database.

## Files touched

- `backend/policy/config.py` — new
- `backend/authorization/service.py` — optional `policy_config_repository` param, `PolicyContext` now built from it when present
- `backend/intent/validation.py` — same
- `backend/api/dependencies.py` — new `get_policy_config_repository` dependency, wired into the two service factories
- `backend/tests/test_policy_config.py` — new
- `backend/tests/test_authorization.py` — added persisted-policy enforcement tests
- `backend/tests/test_intent_validation.py` — added persisted-policy enforcement tests

## Verification

Full backend suite: `264 passed` (up from the pre-existing count, all
prior tests still green — the new parameter's default preserves
exact prior behavior for every caller that doesn't pass it).
`python -c "import api.main"` confirms the app still boots cleanly.

## Known pre-existing issue noticed, not fixed (out of scope)

`policy/engine.py`, `intent/validation.py`, and `authorization/service.py`
have a latent circular-import dependency
(`policy.engine → intent.schema → intent.validation →
authorization.devices → authorization.service → policy.engine`) that
only surfaces if a test or script imports `policy` (or runs
`tests/test_policy.py`) as the very first import in the process —
reproducible on the unmodified codebase, unrelated to this change.
The standard `pytest` invocation (alphabetical collection, `tests/`
directory) and the real app (`api.main`) both avoid triggering it, so
nothing here is broken in practice, but it's worth a dedicated fix in
a future pass since any new module that imports `policy` first will
hit it.
