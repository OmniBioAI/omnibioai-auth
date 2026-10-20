# Designated Admin MFA recovery

Replacing an unknown authenticator is a local operator action that requires a
separate, short-lived Ed25519-signed approval from an active Platform Owner.
The approval action must be `admin_mfa_recovery`, its expected state must be
`unknown_authenticator_enrollment`, and it must explicitly set
`allow_mfa_reset: true`. The normal password-recovery approval action cannot
authorize this operation.

The privileged runtime must mount the pinned Owner public key at
`/run/secrets/auth-recovery-approval-public-key.pem` as a root-owned,
read-only file. The approval file identifies the target by stable Auth user ID
and exact email, the operator OS login, Owner user ID, ticket, identity
verification reference, and an expiry no more than 30 minutes after issuance.
It is one-time-use.

An approved operator runs:

```text
python -m app.cli.recover_admin_mfa --user-id 1 --approval-file /protected/path/approval.json
```

The command requires a TTY and exact confirmation in the form
`RECOVER-MFA 1 admin@omnibioai.org <ticket>`. It resets only MFA, disables the
old devices, invalidates unused recovery codes, revokes active sessions, and
records a signed audit event in the same transaction. It preserves the user
ID, email, password hash, roles, memberships, licenses, and existing audit
history. The Admin must authenticate with the existing password and complete
email MFA after reset; if email MFA is unavailable, login fails closed. They
can then enroll a replacement Google Authenticator device through the normal
authenticated enrollment endpoint.
