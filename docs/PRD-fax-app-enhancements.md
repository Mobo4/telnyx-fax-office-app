# PRD: Eyecare Fax Office App (Telnyx)

## Version
- Date: 2026-02-20
- Scope: Send reliability, confirmation UX, multi-file handling, login page polish, history retention, auth hardening, deployment guidance, D1 persistence.
- Scope: security hardening (webhook verification, signed media delivery, login throttling, queue recovery, durable sessions).
- Scope (v2 branch extension): tenant-scoped commercial controls (audit trail, plan limits, idempotent send, billing/mfa admin APIs) on `codex/v2-commercial`.
- Scope (2026-02-23): Google OAuth login option with tenant-scoped shared account membership.

## Product Goal
Provide a secure browser-based fax system for Eyecare Care of Orange County with reliable outbound sending, clear confirmation feedback, and admin-controlled settings.

## Office Defaults
- Office name: `Eyecare Care of Orange County`
- Office fax: `+17145580642` (display as `714-558-0642`)
- Office email: `eyecarecenteroc@gmail.com`

## Target Users
- Admin users: configure Telnyx/app settings and users.
- Standard users: send faxes, manage contacts, monitor sent/received history.

## Core User Stories
1. As a user, I can log in from a clean centered login page with clear branding.
2. As a user, I can enter one or multiple recipient numbers quickly, including local 10-digit US format.
3. As a user, I can attach multiple files, see exactly what is queued, and remove any file before sending.
4. As a user, I receive a clear popup confirmation when the fax API confirms queueing.
5. As a user, I can verify confirmation info is visible in Sent History.
6. As an admin, I can manage Telnyx and office defaults securely.
7. As staff, I can rely on always-on inbound handling and have inbound email as backup.
8. As admin, I can access recent history quickly while retaining older records.
9. As office staff, I can sign in with my own Google account under the same tenant account.

## Functional Requirements

### Authentication and Role Security
- Login required before app usage.
- Role support: `admin`, `user`.
- Settings and user management visible only to admin.
- Admin routes return `403` for non-admin users.
- User storage must survive schema drift (array/map migration), with bcrypt-hash compatibility for old credentials.
- Optional Cloudflare D1 persistence for user accounts when running on ephemeral hosts.
- Optional Google Sign-In per tenant (`local` and `google` auth providers supported).
- Admin can create Google users by Google email (with optional custom username) under the tenant.
- Google callback may auto-create tenant users (configurable).
- Logged-in users can link their existing account to Google via explicit `Link Google Login` flow.
- Add login throttling per IP and temporary lockouts per username.
- Add durable session store (D1-backed where configured) for restart-safe auth sessions.
- Reject unknown/non-provisioned tenant IDs at login and protected API routes.
- Tenant provisioning must be explicit (admin API), never implicit from request headers/body.
- Add durable session store with fallback priority:
  - D1-backed where configured
  - local file store (`DATA_DIR/sessions_local.json`) when D1 is not configured
  - in-memory only if local session store is explicitly disabled

### Send Fax Workflow
- Recipient input accepts:
  - 10-digit US (`7145580642`) -> normalized to E.164 `+17145580642`.
  - 11-digit US starting with `1` -> normalized to E.164.
  - Direct E.164 (`+17145551234`, international supported).
- Recipient display format:
  - US numbers shown as `714-558-0642` in field and chips.
- Recipient UX:
  - Multi-recipient via comma/newline.
  - Auto-comma insertion after complete number.
  - Address Book selection and name autocomplete.
- Send pre-checks:
  - At least one valid recipient.
  - At least one attachment.
  - Attachment type must be PDF/TIFF.
  - Maximum attachments per fax send: `5`.
  - Maximum per-file size: `50MB`.
  - Maximum total attachment size: `50MB`.
- Upload/send behavior:
  - Selected files upload on Send click.
  - Send uses exactly currently selected files.
  - If upload result count mismatches selected count, fail with explicit error.

### Confirmation UX
- On successful API queue response, show modal popup with:
  - queued count
  - failed count
  - fax IDs
  - count of records present in local Sent History table
- Keep standard inline status message as secondary feedback.
- On confirmation modal `OK`, reset compose form for next fax job.
- Busy retry policy:
  - If provider failure reason is busy, retry automatically up to 3 times at 10-minute intervals (configurable).
  - If retries exhausted or non-busy terminal failure occurs, send owner alert email with user-friendly and support diagnostics.

### Fax History
- Sent/Received tabs remain.
- File links visible in each row.
- Confirmation modal points users to Sent History entries.
- Default history fetch returns latest 50 records for performance.
- Older records are archived for retention and can be retrieved by admin.
- History endpoint must not hang UI when Telnyx API is slow/unreachable.
- On sync failure, history still loads from local/archived data with warning message.
- Failed outbound rows include a `Retry` button next to `Poll`.
- Retry must queue a new outbound fax using stored recipient/media context and return the new fax ID.
- Retry must fail safely with actionable error if original uploaded files are no longer available.

### Contacts and Address Book
- Contact CRUD + CSV import.
- Tag support and frequent contacts (top 5).
- Hard cap: `3000` contacts.

### Backend Validation
- `/api/uploads/batch` enforces max 5 files.
- `/api/faxes` validates media URLs as public `https://` links (no silent filtering).
- Errors are explicit and user-readable.
- Uploaded files are not directly public static assets; use signed expiring media links.
- Telnyx webhook payloads should be signature-verified when key is configured.
- `/api/faxes/:id/refresh` only refreshes fax IDs already owned by active tenant.
- `/api/faxes/:id/retry` only retries failed outbound faxes owned by active tenant.
- Tenant settings are isolated in tenant-scoped config storage (no global key bleed).

### Deployment and Availability
- Production requires a public HTTPS host for webhook and document retrieval.
- Supported now: Render Node service (current live baseline).
- Optional migration path: Cloudflare (Workers/Containers) after compatibility testing.
- Billing runs in free mode by default (`BILLING_MODE=free`); paid lifecycle is deferred but API shape remains.
- Inbound flow must run on non-sleeping service tier to avoid missed/delayed webhook processing.
- Telnyx inbound email recipient remains enabled as backup.
- For Render persistence, data should be stored on mounted disk path (default `/var/data/telnyx-fax-office-app`).
- Alternative persistence path: Cloudflare D1 for users, settings, contacts, fax history, and bulk job snapshots on free/ephemeral hosts.
- Session durability path: D1 sessions table (when D1 enabled) instead of memory-only sessions.
- Queue durability path: startup/interval bulk worker processing to recover queued jobs.

## Non-Functional Requirements
- Clear error messages for blocked send conditions.
- No hidden upload popups before login.
- Mobile-responsive basic layout.
- Maintainable docs for AI/engineer handoff.
- Telnyx request timeout applied to avoid indefinite request hangs (default 5s).

## Acceptance Criteria
- Login card is centered and branded.
- Users can add attachments incrementally and remove each with `x`.
- Attachments render in a list below file picker.
- System blocks send if >5 files or size limits exceeded.
- Send success opens confirmation modal and includes fax IDs.
- Compose form resets only after confirmation modal OK click.
- Sent History shows queued records after successful send.
- Sent history shows latest 50 records by default.
- Older records remain retained in archive store.
- History still renders when Telnyx sync is down, with non-blocking warning.
- Non-admin users cannot open/settings panel or call admin settings endpoints.
- Server rejects non-HTTPS media URLs with explicit error.
- PRD and knowledge docs include hosting decision and backup inbound path.
- Webhook route rejects invalid signatures when verification is enabled.
- Unknown tenant login attempts are rejected (no auto-provision side effect).
- `/api/admin/tenants` is available for explicit tenant provisioning by default-tenant admin.
- Media URLs used for faxing are signed and expire.
- Repeated failed login attempts trigger throttling/lockout responses.
- Queued bulk jobs are resumed by background worker after restart.
- Sessions persist across restart when D1 is configured or when local file session store is enabled.
- Login page shows Google Sign-In only when feature is enabled/configured.
- Google users cannot access admin settings unless role is `admin`.
- Non-admin users cannot access settings even if authenticated via Google.
- Existing local accounts can link Google identity and keep the same username/role.
- Retrying a failed fax from history queues a new fax ID and records retry lineage (`retry_of_fax_id`).

## Gaps Reviewed and Resolved
- Gap: send failures were not obvious enough.
  - Resolution: confirmation modal + clearer validation messages.
- Gap: multi-file workflow lacked queue visibility/removal UX.
  - Resolution: selected-file list with remove action and size/count validation.
- Gap: backend silently dropped non-HTTPS media URLs.
  - Resolution: explicit backend media URL validation error.
- Gap: frontend/backend file count mismatch (UX wanted 5).
  - Resolution: frontend + backend aligned to 5 files.

## QA Checklist
- [x] `node --check /Users/alex/Documents/Projects/Telnyx/server.js`
- [x] `node --check /Users/alex/Documents/Projects/Telnyx/public/app.js`
- [x] Verify send form attachment list add/remove behavior.
- [x] Verify send confirmation modal opens on successful queue response.
- [x] Verify file count and size errors block sending.

## Remaining Risks
- Telnyx requires publicly reachable HTTPS documents; localhost-hosted files will not be reachable externally.
- End-to-end send verification still depends on real Telnyx credentials/network and destination fax behavior.
- Free/idle hosting plans can impact inbound webhook timing and reliability.
- Render free sleep can still interrupt webhook availability unless plan/keepalive is configured.
