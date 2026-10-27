# Consumer OAuth account linking

Google, GitHub, and Microsoft identities are keyed by provider plus provider
subject. Email is used only for initial account discovery after the provider
has vouched for it:

- Google requires `email_verified=true`.
- GitHub private-email discovery accepts only a verified `/user/emails` row.
- Microsoft never uses `preferred_username`. It requires the `email` claim and
  either the consumer tenant or `xms_edov=true` in the token response's ID
  token.

An existing password account is never linked from email alone. The callback
returns a short-lived link token and `/auth/link/confirm` requires the current
password.

An active, non-privileged passwordless account is different. Such accounts are
created by license provisioning or a prior OAuth flow and cannot complete a
password challenge. A provider-verified email match therefore links the new
provider and signs the user in. Disabled-password markers are not passwordless
accounts and are never auto-linked.

Global `admin` and `platform_admin` accounts are also never auto-linked. If a
privileged account has no supported password and no already-linked provider,
an operator must use the signed Platform Owner credential-recovery workflow to
establish a password, then repeat OAuth sign-in and confirm the link. This is an
intentional high-assurance path, not a dead end in the OAuth callback.

Unknown emails never create an active account unless a live, non-revoked,
non-expired license is addressed to that email. Organization SSO enforcement
is evaluated before linked-account sign-in or email-based linking.
