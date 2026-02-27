# Change Log

## 2026-02-27 (email gateway PRD wave)
### Completed
- Added dedicated planning document:
  - `/Users/alex/Documents/Projects/Telnyx/docs/PRD-email-fax-gateway.md`
- Defined product and technical design for:
  - fax-to-email hardening and notifications
  - email-to-fax gateway ingestion, parsing, allowlist controls, and auditability
- Added implementation tasks for phased delivery to ongoing task list.
- Updated knowledge base to reflect current state:
  - inbound fax email exists via Telnyx setting
  - full email-to-fax remains planned.

## 2026-02-27 (pricing incentives + admin usage dashboard wave)
### Completed
- Updated public pricing model to create clear upgrade incentives:
  - higher included pages on higher tiers
  - lower overage per-page rates on higher tiers
- Updated public marketing/signup UX:
  - explicit page-count billing policy section
  - clearer payment continuation copy in signup modal
  - required billing acknowledgement checkbox before signup submission
- Added tenant usage metering store:
  - `/Users/alex/Documents/Projects/Telnyx/data/usage_metrics.json`
- Added usage metering logic:
  - outbound usage counted on delivered webhook
  - inbound usage counted on received/delivered webhook
  - page count from webhook when present, fallback to media-based estimate
- Added admin metrics endpoint:
  - `GET /api/admin/dashboard`
  - returns current/prior month usage, plan policy, and fax status summary
- Extended billing API payload:
  - `pricing_policy`
  - `usage_current_month`
- Added admin dashboard UI card with usage/overage/ops metrics.
- Added billing card overage estimate field.

## 2026-02-27 (stabilization verification wave)
### Completed
- Ran local and live smoke validation for:
  - route split (`/` marketing, `/app` workspace)
  - public signup endpoint
  - role enforcement (`user` denied on admin settings API)
- Confirmed paid-mode signup behavior on Render:
  - newly signed up tenants are intentionally suspended until Stripe webhook activation.
- Confirmed login page renders without pre-login upload popup.
- Confirmed no known npm production dependency vulnerabilities (`npm audit --omit=dev` clean).

## 2026-02-27 (public marketing + self-signup wave)
### Completed
- Added route split:
  - `/` public marketing website
  - `/app` fax application workspace
- Added new public signup endpoint:
  - `POST /api/public/signup`
  - creates tenant + first admin user
  - in paid mode, returns Stripe checkout URL for subscription activation
- Updated Google auth post-login redirects to `/app`.
- Added new marketing assets:
  - `/Users/alex/Documents/Projects/Telnyx/public/index.html` (public landing page)
  - `/Users/alex/Documents/Projects/Telnyx/public/marketing.css`
  - `/Users/alex/Documents/Projects/Telnyx/public/marketing.js`
- Added tenant auth fallback behavior:
  - when D1 user mode is enabled, non-default tenants use local user store instead of hard fail
  - enables non-default tenant login/signup continuity without breaking default tenant D1 users

## 2026-02-27 (stripe subscription + cancel portal wave)
### Completed
- Added Stripe billing runtime support (paid mode):
  - env-driven plan-to-price mapping (`starter`, `pro`, `enterprise`)
  - tenant billing store fields for Stripe customer/subscription linkage
- Added admin billing APIs:
  - `POST /api/admin/billing/checkout-session`
  - `POST /api/admin/billing/portal-session`
- Added Stripe webhook endpoint:
  - `POST /api/webhooks/stripe`
  - validates Stripe signature with `STRIPE_WEBHOOK_SECRET`
  - syncs checkout/subscription lifecycle into tenant billing status and plan
- Added admin Billing card in UI:
  - current plan/status/customer/subscription visibility
  - `Start / Upgrade Subscription` (Stripe Checkout)
  - `Manage / Cancel in Stripe` (Stripe Customer Portal)
- Added health diagnostics:
  - `commercial.stripe_enabled`
  - `commercial.stripe_webhook_configured`
- Updated configuration docs and `.env.example` for Stripe keys, price IDs, and optional redirect URLs.

## 2026-02-27 (manual failed-fax retry action)
### Completed
- Added manual retry endpoint for failed outbound faxes:
  - `POST /api/faxes/:id/retry`
- Retry endpoint behavior:
  - validates tenant ownership, outbound direction, and failed status
  - reuses stored media URLs and recipient
  - remints fresh signed URLs for local `/media/...` files
  - returns new queued fax ID and stores retry lineage (`retry_of_fax_id`, `last_manual_retry_fax_id`)
  - returns explicit actionable error when original uploaded files are no longer available
- Updated Fax History UI action column:
  - failed outbound rows now show `Retry` next to `Poll`
  - button queues retry via API and refreshes history on success

## 2026-02-27 (busy retry + failure alert wave)
### Completed
- Added webhook-driven failure reason classification for outbound fax failures:
  - busy
  - no_answer
  - invalid_number
  - rejected
  - unreachable
  - account_or_limits
  - signaling_or_media
  - canceled
- Added busy-line auto-redial workflow:
  - retries queued in `data/fax_retry_queue.json`
  - default policy: 3 retries at 10-minute intervals (configurable via env)
- Added busy retry worker loop with safe terminal handling.
- Added terminal failure alert email with:
  - human-readable explanation
  - support troubleshooting details and raw failure code/category
- Added new environment controls:
  - `BUSY_RETRY_ENABLED`
  - `BUSY_RETRY_MAX_ATTEMPTS`
  - `BUSY_RETRY_INTERVAL_MS`
  - `BUSY_RETRY_POLL_MS`
  - `FAX_FAILURE_ALERT_EMAIL`
- Updated send-form validation message to explicitly include international E.164 input examples.

## 2026-02-27 (google account-linking wave)
### Completed
- Added authenticated Google account linking endpoint:
  - `GET /api/auth/google/link/start`
- Extended OAuth callback to support two modes:
  - `login`: standard Google login / auto-provision behavior
  - `link`: link Google identity to the currently authenticated account
- Added conflict protection when a Google account is already linked to a different user.
- Added in-app session action button:
  - `Link Google Login` (shows linked state when complete)
- Preserved local username/password login so linked users can still authenticate locally.
- Updated continuity docs for linking behavior and API route.

## 2026-02-23 (google shared-account auth wave)
### Completed
- Added optional Google OAuth login endpoints:
  - `GET /api/auth/google/config`
  - `GET /api/auth/google/start`
  - `GET /api/auth/google/callback`
- Added OAuth state+nonce protection and callback expiration guard.
- Added tenant-scoped Google user linking/provisioning:
  - match by `google_sub`, email, or generated username
  - auto-create Google users on first login when enabled
- Added auth-provider aware user model fields:
  - `auth_provider`
  - `email`
  - `google_sub`
- Extended D1 users table compatibility:
  - automatic column add for existing deployments
  - indexes for provider/email/google_sub lookups
- Updated login UI with `Sign In With Google` button and tenant-aware availability checks.
- Updated admin User Management to create both:
  - local users (`username/password`)
  - google users (`google_email`, optional username)
- Enforced password reset route for local-provider users only.
- Added Google auth settings to `.env.example` and updated docs:
  - `/Users/alex/Documents/Projects/Telnyx/README.md`
  - `/Users/alex/Documents/Projects/Telnyx/docs/PRD-fax-app-enhancements.md`
  - `/Users/alex/Documents/Projects/Telnyx/docs/PRD-google-authentication.md`
  - `/Users/alex/Documents/Projects/Telnyx/docs/KNOWLEDGE-BASE.md`
  - `/Users/alex/Documents/Projects/Telnyx/docs/TASK-LIST.md`

## 2026-02-23 (v2-commercial compliance hardening wave)
### Completed
- Removed implicit tenant auto-provisioning from request flow.
  - Unknown tenant IDs no longer create records when calling `/api/health` or other routes.
  - Unknown tenants now return `404` on login/protected API access.
- Added explicit tenant provisioning API:
  - `GET /api/admin/tenants`
  - `POST /api/admin/tenants` (default-tenant admin only).
- Fixed tenant resolution precedence to always honor session tenant first, preventing body/header tenant override for authenticated users.
- Refactored config persistence to tenant-scoped map only:
  - no top-level config key mirroring
  - no cross-tenant config inheritance bleed.
- Hardened fax refresh endpoint:
  - `POST /api/faxes/:id/refresh` now requires fax record ownership in active tenant before provider poll.
- Added free-mode billing toggle:
  - `BILLING_MODE=free` default
  - billing APIs remain present for future Stripe work
  - paid plan mutation is blocked in free mode.
- Added `BILLING_MODE` to `.env.example` and health/commercial diagnostics.
- Updated continuity docs:
  - `/Users/alex/Documents/Projects/Telnyx/README.md`
  - `/Users/alex/Documents/Projects/Telnyx/docs/PRD-fax-app-enhancements.md`
  - `/Users/alex/Documents/Projects/Telnyx/docs/PRD-commercial-saas-hipaa.md`
  - `/Users/alex/Documents/Projects/Telnyx/docs/KNOWLEDGE-BASE.md`
  - `/Users/alex/Documents/Projects/Telnyx/docs/TASK-LIST.md`
  - `/Users/alex/Documents/Projects/Telnyx/docs/TASK-LIST-commercial-saas-hipaa.md`

### Validation
- `node --check /Users/alex/Documents/Projects/Telnyx/server.js`
- `node --check /Users/alex/Documents/Projects/Telnyx/public/app.js`
- Smoke checks:
  - unknown tenant no longer auto-creates via `/api/health`
  - unknown tenant login returns `404`
  - explicit tenant provisioning works via `/api/admin/tenants`
  - free billing mode reports `plan=free` and blocks billing patch
  - config writes are tenant-scoped (no top-level `telnyx_api_key` persisted)
  - refreshing unknown fax ID returns tenant-safe `404`.

## 2026-02-23 (v2-commercial implementation wave)
### Completed
- Implemented tenant-aware API context (`X-Tenant-Id` + session tenant binding) on `codex/v2-commercial`.
- Added immutable audit log pipeline and admin query endpoint:
  - `GET /api/admin/audit-events`
- Added idempotent send support for `POST /api/faxes` using `Idempotency-Key`.
- Added commercial plan enforcement for:
  - max users per tenant
  - max contacts per tenant
  - max recipients per send
- Added commercial billing admin APIs:
  - `GET /api/admin/billing`
  - `PATCH /api/admin/billing`
  - `GET /api/admin/tenant`
- Added admin MFA toggle endpoint:
  - `PATCH /api/admin/users/:username/mfa`
- Added tenant-aware config/settings persistence and tenant-scoped history/contact filtering.
- Added v2 UI tenant login field and tenant header propagation for browser requests.
- Added new commercial environment variables in `.env.example`.

### Validation
- `node --check /Users/alex/Documents/Projects/Telnyx/server.js`
- `node --check /Users/alex/Documents/Projects/Telnyx/public/app.js`
- API smoke test passed for login, tenant mismatch protection, user create, MFA toggle, billing update, contacts, and audit reads.

## 2026-02-23 (v2-commercial branch)
### Completed
- Created commercial infrastructure scaffold:
  - `/Users/alex/Documents/Projects/Telnyx/infra/docker-compose.commercial.yml` (Postgres + Redis).
- Added initial commercial SQL migration:
  - `/Users/alex/Documents/Projects/Telnyx/db/migrations/001_commercial_core.sql`
  - includes multi-tenant tables, audit events, idempotency keys, and billing customer baseline.
- Bumped package version on commercial branch to `2.0.0-alpha.1`.

### Files Changed
- `/Users/alex/Documents/Projects/Telnyx/infra/docker-compose.commercial.yml`
- `/Users/alex/Documents/Projects/Telnyx/db/migrations/001_commercial_core.sql`
- `/Users/alex/Documents/Projects/Telnyx/docs/TASK-LIST-commercial-saas-hipaa.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/CHANGE-LOG.md`
- `/Users/alex/Documents/Projects/Telnyx/package.json`
- `/Users/alex/Documents/Projects/Telnyx/package-lock.json`

## 2026-02-23
### Completed
- Added formal versioning/branching policy for stable (`1.x`) and commercial (`2.x`) lines.
- Created and pushed rollback branches:
  - `codex/v1-known-good` (commit `0261446`)
  - `codex/v1-stable`
  - `codex/v2-commercial`
- Created and pushed rollback tag: `v1.2.0-known-good`.
- Bumped stable package version to `1.3.0`.

### Files Changed
- `/Users/alex/Documents/Projects/Telnyx/package.json`
- `/Users/alex/Documents/Projects/Telnyx/package-lock.json`
- `/Users/alex/Documents/Projects/Telnyx/README.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/VERSIONING-AND-BRANCHING.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/CHANGE-LOG.md`

## 2026-02-22
### Completed
- Added commercial product PRD with multi-tenant SaaS architecture, HIPAA-ready controls, scalability targets, billing, and enterprise auth scope.
- Added dedicated commercialization task list with phased P0/P1 delivery gates and HIPAA program checklist.
- Updated knowledge base links and next-hardening notes for commercial execution continuity.

### Files Changed
- `/Users/alex/Documents/Projects/Telnyx/docs/PRD-commercial-saas-hipaa.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/TASK-LIST-commercial-saas-hipaa.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/KNOWLEDGE-BASE.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/TASK-LIST.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/CHANGE-LOG.md`

## 2026-02-22
### Completed
- Added local file-backed session store fallback (`data/sessions_local.json`) when D1 is not enabled.
- Added `LOCAL_SESSION_STORE_ENABLED` environment flag (default `true`) to control non-D1 session persistence behavior.
- Added `session_store_mode` to `/api/health` diagnostics.
- Added startup log output for active session store mode (`d1`, `local file`, or `in-memory`).
- Updated docs to reflect session persistence fallback behavior and operational mode selection.

### Files Changed
- `/Users/alex/Documents/Projects/Telnyx/server.js`
- `/Users/alex/Documents/Projects/Telnyx/.env.example`
- `/Users/alex/Documents/Projects/Telnyx/README.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/PRD-fax-app-enhancements.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/KNOWLEDGE-BASE.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/TASK-LIST.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/CHANGE-LOG.md`

## 2026-02-20
### Completed
- Removed upload modal and moved upload to inline Send Fax form.
- Added send-time upload behavior (files upload when Send is clicked).
- Added multi-recipient fax queueing in backend (`to_numbers`) with per-recipient results.
- Added Address Book picker button beside recipient field.
- Added frequent-contact tracking in contact records (`usage_count`, `last_used_at`).
- Added API endpoint for top frequent contacts and frontend quick chips.
- Added contact storage cap enforcement (3000) for manual create and CSV import.
- Added admin settings gear toggle flow in session area.
- Moved settings access to floating bottom-left gear button.
- Reworked Address Book to popup selector with search, top-5, and OK confirm action.
- Added contact-name autocomplete in Send Fax workflow.
- Added frontend validation for empty recipient and invalid E.164 format.
- Moved primary Send Fax button directly below Address Book button.
- Moved contact create/import/manage UI into Address Book modal and removed standalone section.
- Moved Bulk Fax By Tags into Address Book modal as a dedicated tab.
- Changed Send Fax workflow to PDF/TIFF file attachments only (no user-entered media URL field).
- Added recipient auto-normalization: `7145580642` now sends as `+17145580642`.
- Added recipient display formatting in send field/chips (US format `714-558-0642`).
- Added automatic comma insertion after a complete recipient number for faster multi-recipient entry.
- Hardened send flow to upload the files currently selected in the file picker at click time.
- Added selected-files queue UI with remove (`x`) controls and running size/count summary.
- Added send attachment guards: max 5 files, allowed type checks, per-file and total-size validation.
- Added send confirmation modal showing queued/failed counts, fax IDs, and history-record verification count.
- Centered and polished login page with fax-machine branding.
- Aligned backend `/api/uploads/batch` max file count with UX requirement (5 files).
- Replaced silent media URL filtering in `/api/faxes` with explicit invalid-URL errors.
- Redesigned dashboard CSS with improved typography/colors/layout.
- Updated README and PRD to reflect new workflow.
- Added user-store normalization/migration guard so legacy user JSON layouts continue to work.
- Added legacy password compatibility path (auto-upgrade to bcrypt hash on successful login).
- Hardened admin settings access checks for non-admin sessions.
- Added Telnyx fetch timeout (`TELNYX_HTTP_TIMEOUT_MS`, default 5000ms) to prevent `/api/faxes` hangs.
- Updated `/api/faxes` to return local+archive merged history with non-blocking `sync_warning`.
- Added Render runtime diagnostics in `/api/health` and startup warnings for non-persistent data dir.
- Added Render startup warning about free-tier sleep impact on inbound webhook reliability.
- Added optional Cloudflare D1-backed user persistence (`CLOUDFLARE_*` env support).
- Added D1 startup bootstrap: users table creation, local-user sync, and admin-user ensure.
- Updated auth/user routes to use async store wrappers that target D1 when enabled.
- Added `/api/health` flag `d1_users_enabled` for deployment verification.
- Added D1 app-store snapshot persistence for `config`, `contacts`, `faxes`, `faxes_archive`, and `bulk_jobs`.
- Added startup hydration/seed logic for app stores (D1 <-> local JSON sync).
- Added `/api/health` flag `d1_app_stores_enabled` for app-store persistence verification.
- Added optional webhook signature validation for Telnyx webhooks (`TELNYX_WEBHOOK_PUBLIC_KEY`).
- Added signed/expiring media URL delivery endpoint (`/media/:filename`) and moved uploads outside public static root.
- Added auth brute-force protections (IP-based login throttling + username lockout window).
- Added background bulk worker polling/recovery loop for queued jobs.
- Added optional D1-backed session store (`sessions` table) for durable auth sessions.
- Added detailed hardening PRD: `/Users/alex/Documents/Projects/Telnyx/docs/PRD-security-hardening-wave1.md`.
- Added detailed hardening task list: `/Users/alex/Documents/Projects/Telnyx/docs/TASK-LIST-security-hardening-wave1.md`.
- Added parallel hardening skill set under `/Users/alex/Documents/Projects/Telnyx/skills/`.

### Files Changed
- `/Users/alex/Documents/Projects/Telnyx/server.js`
- `/Users/alex/Documents/Projects/Telnyx/public/index.html`
- `/Users/alex/Documents/Projects/Telnyx/public/app.js`
- `/Users/alex/Documents/Projects/Telnyx/public/styles.css`
- `/Users/alex/Documents/Projects/Telnyx/README.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/PRD-fax-app-enhancements.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/KNOWLEDGE-BASE.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/KNOWLEDGE-SEND-RELIABILITY.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/TASK-LIST.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/CHANGE-LOG.md`
- `/Users/alex/Documents/Projects/Telnyx/AGENTS.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/TASK-LIST.md`

### Handoff Notes
- Primary workflow now expects users to select files inline and click Send once.
- Backend supports up to 100 recipients per send request.
- Backend upload batch limit is now 5 files per send request.
- Frequent-contact chips depend on successful queue events.
- Recipient selection now supports manual numbers, autocomplete, and popup selection.
- Telnyx media URLs must be public HTTPS. Localhost file URLs are not fetchable by Telnyx.
