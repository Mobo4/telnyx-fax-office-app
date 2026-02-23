# Knowledge Base: Telnyx Fax Office App

## Purpose
Operational reference for architecture, workflow behavior, limits, and known edge cases so another engineer/AI can continue without re-discovery.

## Related Planning Docs
- `/Users/alex/Documents/Projects/Telnyx/docs/PRD-fax-app-enhancements.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/PRD-google-authentication.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/TASK-LIST.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/PRD-security-hardening-wave1.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/TASK-LIST-security-hardening-wave1.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/PRD-commercial-saas-hipaa.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/TASK-LIST-commercial-saas-hipaa.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/VERSIONING-AND-BRANCHING.md`
- `/Users/alex/Documents/Projects/Telnyx/db/migrations/001_commercial_core.sql`
- `/Users/alex/Documents/Projects/Telnyx/infra/docker-compose.commercial.yml`

## Stack
- Backend: Node.js + Express (`/Users/alex/Documents/Projects/Telnyx/server.js`)
- Frontend: vanilla JS (`/Users/alex/Documents/Projects/Telnyx/public/app.js`)
- UI: static HTML/CSS (`/Users/alex/Documents/Projects/Telnyx/public/index.html`, `/Users/alex/Documents/Projects/Telnyx/public/styles.css`)
- Persistence: JSON files in `/Users/alex/Documents/Projects/Telnyx/data`

## Core Capabilities
- Role-based login (`admin`, `user`).
- Optional Google OAuth login (`google`) plus local login (`local`).
- Optional Cloudflare D1-backed persistence for users + app stores.
- Optional Cloudflare D1-backed session storage.
- Outbound fax send to one or many recipients.
- Sent and Received history tabs with file links.
- Address Book with search, tags, CSV import, frequent contacts.
- Bulk fax by tag filters.
- Optional HIPAA cover page.
- Optional outbound copy email.
- Post-send form reset after confirmation modal OK.
- Admin settings hard-gated to admin role in UI and API (`403` on admin routes for non-admin).
- Login throttling and account lockout after repeated failures.
- Signed expiring media links for outbound fax document retrieval.
- Background worker loop for queued bulk fax recovery.
- Optional webhook signature verification for Telnyx events.
- v2 commercial branch adds tenant-aware request scoping (`X-Tenant-Id`), immutable audit logs, billing/plan admin APIs, and idempotent outbound send.
- v2 now requires explicit tenant provisioning; unknown tenant IDs are rejected instead of auto-created.

## API Surface (primary)
- Auth: `/api/auth/login`, `/api/auth/logout`, `/api/auth/me`
- Google auth: `/api/auth/google/config`, `/api/auth/google/start`, `/api/auth/google/callback`
- Send/history: `/api/faxes`, `/api/faxes/:id/refresh`
- Uploads: `/api/uploads/batch`
- Contacts: `/api/contacts`, `/api/contacts/import`, `/api/contacts/tags`, `/api/contacts/frequent`
- Bulk: `/api/faxes/bulk`, `/api/faxes/bulk-jobs`
- Admin: `/api/admin/settings`, `/api/admin/telnyx/fax-application`, `/api/admin/users`
- Archive: `/api/faxes/archive` (admin-only)
- Health: `/api/health` (includes hosting/storage diagnostics)
- Media: `/media/:filename?exp=...&sig=...` (signed public fetch URL for Telnyx media retrieval)
- v2 commercial admin APIs:
  - `/api/admin/audit-events`
  - `/api/admin/billing`
  - `/api/admin/tenant`
  - `/api/admin/tenants`
  - `/api/admin/users/:username/mfa`

## Send Workflow (current)
1. User fills recipients.
2. User selects up to 5 files (PDF/TIFF).
3. Frontend validates recipients + files.
4. Frontend uploads selected files to `/api/uploads/batch`.
5. Frontend sends `/api/faxes` with `to_numbers` and uploaded `media_urls`.
6. Backend queues one fax per recipient.
7. Frontend reloads history and opens confirmation modal with queue details.
8. Send form is cleared only when user confirms (OK) on the queue confirmation popup.

## Recipient Behavior
- Input accepts:
  - `7145580642` (normalized to `+17145580642`)
  - `17145580642` (normalized to `+17145580642`)
  - `+17145580642`
- US numbers display as `714-558-0642`.
- Multiple numbers supported via comma/newline.
- Input auto-adds comma after complete number.

## Attachment Behavior
- Max files per send: `5`.
- Max per-file size: `50MB`.
- Max total selected size: `50MB`.
- Allowed types: `.pdf`, `.tif`, `.tiff`.
- Files are kept in client-side queue list with remove (`x`) controls.
- Send uses the current queue, not stale selections.

## Backend Validation Notes
- `/api/uploads/batch` enforces max files and per-file limit.
- `/api/faxes` now rejects invalid/non-HTTPS media URLs explicitly.
- No silent media URL dropping.
- Telnyx API calls are timeout-bounded (`TELNYX_HTTP_TIMEOUT_MS`, default 5000ms) to avoid hanging history UI.
- `/api/faxes` now includes `sync_warning` when Telnyx sync fails, while still returning local/archived history.
- Login attempts are throttled by IP and temporarily lock per username after repeated failures.
- Webhook route can enforce signature verification via Telnyx public key.

## Data Files
- `/Users/alex/Documents/Projects/Telnyx/data/faxes.json`
- `/Users/alex/Documents/Projects/Telnyx/data/faxes_archive.json`
- `/Users/alex/Documents/Projects/Telnyx/data/contacts.json`
- `/Users/alex/Documents/Projects/Telnyx/data/bulk_jobs.json`
- `/Users/alex/Documents/Projects/Telnyx/data/config.json`
- `/Users/alex/Documents/Projects/Telnyx/data/users.json`

## User Persistence Modes
- Default: local JSON user store (`data/users.json`).
- Optional D1 mode: enabled when all are present:
  - `CLOUDFLARE_ACCOUNT_ID`
  - `CLOUDFLARE_D1_DATABASE_ID`
  - either `CLOUDFLARE_API_TOKEN` or (`CLOUDFLARE_API_KEY` + `CLOUDFLARE_EMAIL`)
- In D1 mode, startup ensures table exists and syncs local users to D1 once.
- Health endpoint reports `"d1_users_enabled": true|false`.

## App Store Persistence Modes
- Default: local JSON stores.
- Optional D1 app-store snapshot mode (same `CLOUDFLARE_*` env vars as user mode).
- Synced stores:
  - `config.json`
  - `contacts.json`
  - `faxes.json`
  - `faxes_archive.json`
  - `bulk_jobs.json`
- Startup behavior:
  - if D1 snapshot exists -> hydrate local file from D1
  - if no D1 snapshot -> seed D1 from local file
- Runtime behavior:
  - local file remains primary runtime store
  - writes are queued and synced to D1 in background
- Health endpoint reports `"d1_app_stores_enabled": true|false`.

## Session Persistence Modes
- Default: local file session store (`data/sessions_local.json`).
- Optional D1 mode: enabled when `CLOUDFLARE_*` D1 env vars are present.
- D1 session table: `sessions` with expiration timestamps.
- Optional in-memory mode only when `LOCAL_SESSION_STORE_ENABLED=false`.
- Health endpoint reports `session_store_mode` as `d1`, `local_file`, or `memory`.

## v2 Tenant Context (commercial alpha)
- Active tenant resolved in this order:
  1. session user tenant
  2. `X-Tenant-Id` header
  3. request body/query `tenant_id`
  4. `DEFAULT_TENANT_ID`
- Protected `/api/*` routes require session tenant == active tenant.
- Default tenant remains backward compatible (`default`) to avoid breaking v1 operations.
- Unknown tenants are denied at login and protected API routes (`404`) until explicitly provisioned.
- Explicit tenant provisioning endpoint:
  - `POST /api/admin/tenants` (default tenant admin only).

## v2 Idempotency and Audit
- `POST /api/faxes` supports `Idempotency-Key`.
- Cached responses are tenant+method+path scoped with TTL (`IDEMPOTENCY_TTL_SECONDS`).
- Security/ops events recorded in `/Users/alex/Documents/Projects/Telnyx/data/audit_events.json`.

## Billing Mode
- `BILLING_MODE=free` is default and currently recommended for office deployment.
- In free mode:
  - plan limits resolve to `free` profile
  - `PATCH /api/admin/billing` is intentionally blocked
  - billing endpoints remain in place for future Stripe cutover
- `BILLING_MODE=paid` unlocks paid plan mutation API paths without changing endpoint contracts.

## Auth/User Persistence Notes
- User store is normalized on read/write (supports legacy `items` map or array layouts).
- If no admin exists, bootstrap admin is re-created automatically.
- Legacy plaintext user passwords (if present from old builds) are accepted once, then auto-migrated to bcrypt hash on login.
- User records now carry `auth_provider`, `email`, and optional `google_sub` for identity linking.
- Password resets are limited to `local` users; Google-provider users authenticate through OAuth.
- Google user lookup is tenant-scoped and matches by `google_sub`, email, or generated username.

## History Retention Behavior
- `/api/faxes` returns most-recent rows (default `50`, max `100`) and syncs latest records from Telnyx before responding.
- Local active history keeps latest `50` rows for fast UI loading.
- Older rows are rotated into `/Users/alex/Documents/Projects/Telnyx/data/faxes_archive.json`.
- Archived rows can be fetched with `/api/faxes/archive` (admin-only).
- History response merges active + archive, de-dupes by fax ID, and returns latest 50 for UI.

## Hosting and Network Model
- Telnyx requires public HTTPS access to:
  - webhook endpoint
  - uploaded media URLs used in outbound sends
- Current production path: Render web service (working and already integrated).
- Cloudflare is an alternative, but migration is required if moving from Express server to Workers runtime.
- Cloudflare Containers can run containerized apps and can remove need for Render once migrated and validated.
- Tailscale is optional only for self-hosted private-server patterns; it is not required for public webhook deployments on Render/Cloudflare.
- On Render, app defaults data path to `/var/data/telnyx-fax-office-app` when `/var/data` is available.

## Known Environment Caveats
- If app runs only on `http://localhost`, Telnyx cannot fetch upload files, so real outbound fax sends fail.
- Inbound reliability requires always-on hosting. Free sleep/idle plans can delay or miss time-sensitive webhook delivery.
- Keep inbound fax email recipient configured in Telnyx as backup while webhook flow is being monitored.
- Render free sleep cannot be fully fixed in app code; use non-sleeping plan or external keepalive pings to `/api/health`.
- D1 persistence keeps users across restarts, but does not prevent free-tier sleep delays for inbound webhooks.
- If webhook signature validation is enabled without a valid public key, inbound webhook updates will fail with `401`.

## Gaps / Next Hardening
- Add automated integration tests for send success/failure paths.
- Add explicit banner when app is running on localhost warning about public URL reachability.
- Add retry controls for failed recipients from results payload.
- Replace file-based storage with multi-tenant DB + queue worker architecture for commercial scale.
- Add immutable audit trail, billing, and enterprise auth (SSO/MFA) for commercial readiness.
