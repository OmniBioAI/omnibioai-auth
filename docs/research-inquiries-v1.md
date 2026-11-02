# Research inquiries v1: architecture and operations

## Status, architecture, and ownership

This feature extends the existing Auth service; it does not add a microservice. Auth owns MySQL persistence, Redis abuse controls, notifications, and the `manage_all_orgs` boundary. The API Gateway owns the one public relay. The landing page remains plain HTML and vanilla JavaScript.

```text
research-collaborations.html
  -> Gateway POST|OPTIONS /api/v1/research-inquiries
  -> Auth POST /api/v1/research-inquiries
  -> Redis rate limit -> MySQL commit -> independent notification attempt

Authorized administrator
  -> Auth /api/v1/admin/research-inquiries*
  -> active JWT + manage_all_orgs
```

Local implementation and disposable integration verification are complete. Remote staging and production are not verified or authorized. Owners must designate staging, administrative ownership, an approved notification recipient, exact CORS origins, and trusted-proxy CIDRs. The proposed 730-day retention period is not approved; no deletion job is active.

## Public contract and canonical schema

`POST /api/v1/research-inquiries` requires `application/json`, UTF-8, and at most 16,384 bytes. Unknown fields are rejected. Text is conservatively normalized, length bounded, and rejected for unsupported control characters or obvious credentials/tokens.

| Field | Required | Limit / values |
|---|---:|---|
| `full_name` | yes | 1–120 |
| `institutional_email` | yes | 3–254; institutional domain |
| `institution` | yes | 1–200 |
| `department` | yes | 1–160 |
| `country` | yes | 1–100 |
| `research_interest` | yes | `biomedical_literature_ai`, `genomics_precision_medicine`, `cancer_research`, `multi_omics`, `biomedical_ai_evaluation`, `scientific_workflows`, `biomedical_knowledge_graphs`, `other` |
| `proposed_collaboration` | yes | 1–4,000 |
| `potential_datasets` | no | 0–2,500 |
| `institutional_website` | no | 0–500; public HTTP(S), no credentials/private literal IP |
| `additional_information` | no | 0–2,500 |
| `consent` | yes | literal JSON boolean `true` |
| `company_fax` | no | honeypot, 0–100 |

Success is `201 {"status":"received","inquiry_id":"<server UUID>","submitted_at":"<server UTC>"}` only after MySQL commits. Failures include 400 malformed/invalid-UTF-8 JSON, 403 origin, 409 same-day duplicate, 413 size, 415 media, 422 validation, 429 throttling, and safe 503 unavailability. Honeypot data is discarded with 204 and no receipt. Gateway response validation prevents redirects, malformed receipts, or internal 5xx details from becoming success.

No public list, detail, lookup, update, or retry route exists.

## Migration and persistence

The qualified single-head graph tail is:

```text
0036_mfa_enrollment_sessions
 -> 0037_license_generation_idem
 -> 0038_encrypt_license_replay
 -> 0039_version_license_key_peppers
 -> 0040_research_inquiries
 -> 0041_validate_inquiry_schema (head)
```

0037–0039 are license migrations. 0040 creates `research_inquiries`. Forward-only 0041 validates license/research schema and repairs only a missing research index after interrupted creation; it refuses incompatible lookalike schemas. Do not rewrite shared history.

The table stores inquiry UUID, contact/institution fields, controlled interest, collaboration/resource/additional text, consent/submission timestamps, processing/notification states, delivery metadata, HMAC duplicate fingerprint, and created/updated timestamps. It has a primary key, unique fingerprint, two status CHECK constraints, and submitted/processing/notification indexes. It has no foreign keys.

MySQL 8.0.46 qualification covered clean upgrade, an existing 0036 schema with license data, exact model parity, index recovery, CHECK enforcement, concurrent duplicates, concurrent delivery attempts, runtime startup, and HTTP commit. MySQL 8.0.16+ is required. 0041 downgrade is a no-op; 0040 drops only an empty table and refuses populated-data downgrade. After first use, preserve the table and correct forward.

## Duplicate, rate-limit, proxy, and CORS controls

The HMAC fingerprint covers all normalized material fields plus UTC date; honeypot/consent are excluded. The database unique constraint handles concurrent matches. This is same-day duplicate suppression, not global idempotency: changed fields or a later UTC day create another fingerprint.

The default limit is 5 requests per 600 seconds per resolved client IP using the existing atomic Redis primitive. If Redis is unavailable, existing bounded per-process fallback applies: degraded across replicas, but not fail-open. Gateway trusts `CF-Connecting-IP` only from configured ingress peers; Auth applies the same rule to the Gateway peer. Arbitrary forwarding headers are ignored. Both services run Uvicorn with `--no-proxy-headers`. Never trust `0.0.0.0/0` or `::/0`. CORS origins are explicit; enabled intake rejects wildcard configuration.

## Notifications

Persistence and delivery are independent. `pending` means not completed; `not_configured` means recipient absent or provider idempotency unapproved; `sent` means a validated receipt was stored; `failed` means delivery failed. None can undo a committed 201.

`RESEARCH_INQUIRY_NOTIFICATION_TO` must be owner approved; code has no fallback address. Notifications contain only inquiry ID and category. Full data stays behind administration. The stable key is `research-inquiry:<id>:admin`. Set `RESEARCH_INQUIRY_NOTIFICATION_IDEMPOTENCY_CONFIRMED=true` only after the provider guarantees deduplication for the entire retry lifetime. Retries use a MySQL row lock, default maximum 5, signed audit event, and refuse already-sent rows. Real delivery is unverified until approved staging configuration is exercised.

## Administrative review

These Auth routes require active `manage_all_orgs` authorization:

- `GET /api/v1/admin/research-inquiries?limit=50&offset=0&status=new`
- `GET /api/v1/admin/research-inquiries/{uuid}`
- `PATCH /api/v1/admin/research-inquiries/{uuid}` with `new|in_review|contacted|closed|spam`
- `POST /api/v1/admin/research-inquiries/{uuid}/notifications/retry`

Responses use `Cache-Control: no-store` and omit the fingerprint. Mutations create signed audit events transactionally. No review UI was added. Pending a reviewed Control Center proxy/page, use Auth administration only over its approved internal administrative network. Do not expose Auth publicly. Assign an administrative owner before production.

## Environment configuration

Auth:

```text
RESEARCH_INQUIRY_ENABLED=true
RESEARCH_INQUIRY_HMAC_KEY=<secret, >=32 bytes>
RESEARCH_INQUIRY_RATE_LIMIT=5
RESEARCH_INQUIRY_RATE_WINDOW_SECONDS=600
RESEARCH_INQUIRY_TRUSTED_PROXIES=<exact Gateway CIDRs>
RESEARCH_INQUIRY_NOTIFICATION_TO=<approved recipient or blank>
RESEARCH_INQUIRY_NOTIFICATION_IDEMPOTENCY_CONFIRMED=false
RESEARCH_INQUIRY_NOTIFICATION_MAX_ATTEMPTS=5
RESEARCH_INQUIRY_RETENTION_DAYS=730
EMAIL_SERVICE_SEND_URL=<approved existing provider>
EMAIL_SERVICE_TOKEN=<secret store>
EMAIL_FROM_ADDRESS=<approved sender>
CORS_ALLOWED_ORIGINS=<exact landing origins>
```

`RESEARCH_INQUIRY_RETENTION_DAYS` does not activate deletion.

Gateway:

```text
RESEARCH_INQUIRY_BACKEND_URL=<existing internal Auth base URL>
RESEARCH_INQUIRY_TRUSTED_PROXIES=<exact approved ingress CIDRs>
```

Plain HTML rendering:

```text
VITE_RESEARCH_INQUIRY_URL=<approved API origin>/api/v1/research-inquiries
node html-tools/render-research-page.mjs <new-output-file>
```

The standalone renderer makes Vite unnecessary. It accepts only the exact route, HTTPS except loopback, and no credentials/query/fragment; it writes only a new output path. Never put secrets in `VITE_` variables.

## Staging runbook

No remote target was designated or changed. Use reviewed candidate image digests and existing deployment conventions; disposable local names are not deployment identifiers.

1. Record commits, image digests, manifest diff, backup reference, current revision, origins, proxy CIDRs, and rollback owner.
2. Confirm MySQL 8.0.16+, expected predecessor, and backup. Run `alembic current`, `alembic upgrade head`, confirm 0041, then inspect columns/indexes/CHECKs.
3. Configure through the existing secret mechanism. Leave recipient blank and provider confirmation false until approved.
4. Add ingress only for `POST|OPTIONS /api/v1/research-inquiries`; keep Auth private, reject other methods/siblings, cap body at 16 KiB, and do not broaden middleware exemptions.
5. Run Auth/Gateway with `--no-proxy-headers`. Verify health, metrics, MySQL, Redis, and alerts for persistence failure, Redis degradation, notification failure/exhaustion, 5xx, and service health.
6. Render a staging-only HTML artifact and submit `OmniBioAI Research Inquiry Staging Verification` with synthetic data.
7. Correlate browser receipt, Gateway trace, MySQL UUID/status, authorized review, signed status audit, notification outcome, Redis limit, duplicate, CORS, unauthorized denial, and safe logs.
8. Record regressions/security smoke evidence before production review.

The inspected ingress allowlist does not expose the route. DNS, Cloudflare, tunnels, firewall, ingress, remote databases, and production were not changed.

## Privacy, retention, monitoring, and rollback

The page warns against PHI, patient identifiers, medical records, credentials/tokens, confidential datasets, and restricted research data. Pattern rejection is defense in depth, not classification. No HIPAA claim is made. Logs, audit metadata, notification content, and metrics must omit form content and identifiers; anonymous trace IDs are server generated. Supplied URLs are never fetched, so the field has no SSRF path.

Proposed policy: retain at most 730 days unless documented legal hold/governed transfer applies; review closed/spam quarterly; cover replicas and normal backup expiry. Automated deletion remains disabled until period, backup handling, deletion authority, and evidence are approved. Correction/deletion uses an owner-approved data process; no destructive public/admin endpoint exists.

Rollback:

- Disable new intake, render an unconfigured page, and remove only the exact Gateway public route.
- Before submissions, downgrade through 0041/0040 may remove the empty table.
- After submissions, never force downgrade: retain data, roll application images back, then correct forward.
- Restore Redis rather than weakening limits. For delivery issues, use status/error categories without copying inquiry content; never reset `sent` or change/reuse provider keys.
- Database restore requires explicit approval and reconciliation with post-backup notifications.
- Production requires successful staging, security review, approved notification/retention/admin owners, validated rollback, and explicit deployment approval.
