# Personal preferences

IAM owns one effective set of personal account preferences per authenticated
user. Studio owns presentation. This is separate from machine-local Electron
configuration, GlobalConfig, OrganizationConfig and organization policy.

## API

`GET /me/preferences` returns `{ "timezone": null }` for a user without a saved
choice. Null means follow the current client/device time zone. It is a real
default, not missing provisioning. A saved IANA zone is returned verbatim.

`PATCH /me/preferences` accepts only `timezone` (IANA name/UTC or null). Omitted
fields remain unchanged; null resets to the device default. Unknown fields,
numeric values, abbreviations such as CST/EST/IST, and unknown zones return
422. Python zoneinfo validates against the runtime's IANA time-zone database.
The deployment must provide that standard database.

Both endpoints use `get_current_user`, derive ownership from `sub`, reject
unauthenticated callers via the existing IAM dependency, and return 404 if the
principal's User row is absent. The client supplies no user or organization ID.
Responses use `Cache-Control: no-store`. No credentials or arbitrary JSON
metadata can be stored through this API.

`users.preferred_timezone` is a nullable VARCHAR(100), introduced by additive
migration `0030_user_timezone`. No new service, table, or user provisioning
step is required. ORM updates touch only this column, preserving unrelated
identity fields. Concurrent changes to the same field use existing transaction
semantics (last committed change wins); no ETag or offline sync is claimed.

## Deployment and verification

Run the migration using the existing deployment procedure before starting the
new IAM build, then deploy Studio. Do not rely on `create_all()` to alter an
existing table. Downgrading removes only this preference column and its values.
Tests cover canonical defaults, validated updates, reset, partial/no-op updates,
cross-user isolation, independent-session reads and additive upgrade/downgrade
on a disposable database. Existing migration-chain tests cover SQLite/MySQL.
