# Telnyx Office Fax App

Browser-based fax app for office use. It includes:

- Send fax from a simple web form
- Delivery verification (`delivered` / `failed`)
- Failure reason tracking
- Busy-line retry policy (up to 3 retries, 10-minute interval by default)
- Terminal failure alert email with human-readable + support diagnostics
- Webhook receiver for Telnyx fax events
- Manual fallback polling for any fax ID
- Login with role-based access (`admin` and `user`)
- Optional Google Sign-In (per tenant) in addition to local username/password
- Admin controls for user accounts and Telnyx fax app settings
- Admin billing panel with Stripe checkout and Stripe portal cancel/manage flow
- Admin dashboard with usage, overage estimate, and fax operations summary
- Email-to-fax gateway webhook (sender allowlist + message-id dedupe)
- Optional inbound fax notification emails
- Settings panel opened from a gear button (admin only)
- Inline file attach on Send Fax page (no popup)
- Per-user memory of the last media URL used
- Address Book button beside recipient field opens popup picker
- Multi-recipient send in one request
- Contact-name autocomplete on Send Fax form
- Top 5 frequently used contacts in Address Book popup
- Contact create/import/manage controls are inside Address Book popup
- Contact list with tags (up to 3000 contacts)
- CSV contact import
- Tag filters and bulk fax queue
- Outbound fax copy email toggle and default recipient in admin settings
- Main Send Fax page includes a per-fax "send email copy" checkbox
- Optional HIPAA cover page (default ON) with subject/message fields
- Office profile defaults (name, fax, email) shown on send page and editable by admin
- Fax history tabs for Sent and Received with clickable file links
- Tiered pricing policy with page-based allowances and overage rates

## 1. Requirements

- Node.js 18+
- Telnyx Fax Application
- Telnyx API V2 key
- Fax app `connection_id`
- A Telnyx fax number assigned to that fax app

## 2. Configure

Create a `.env` file from `.env.example`:

```bash
cp .env.example .env
```

Set:

- `TELNYX_API_KEY`
- `TELNYX_CONNECTION_ID`
- `TELNYX_FROM_NUMBER`
- `TELNYX_FAX_APPLICATION_ID`
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `SESSION_SECRET`
- `OUTBOUND_COPY_ENABLED` and `OUTBOUND_COPY_EMAIL`
- `OFFICE_NAME`, `OFFICE_FAX_NUMBER`, `OFFICE_EMAIL`
- SMTP variables (`SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`)
- Optional: `DATA_DIR` (path for persistent JSON data)
- Optional: `TELNYX_HTTP_TIMEOUT_MS` (default `5000`)
- Optional: `LOCAL_SESSION_STORE_ENABLED` (default `true`; uses `DATA_DIR/sessions_local.json` when D1 is not enabled)
- Fax retry/failure alerts:
  - `BUSY_RETRY_ENABLED` (default `true`)
  - `BUSY_RETRY_MAX_ATTEMPTS` (default `3`)
  - `BUSY_RETRY_INTERVAL_MS` (default `600000`)
  - `BUSY_RETRY_POLL_MS` (default `30000`)
  - `FAX_FAILURE_ALERT_EMAIL` (optional; falls back to `OUTBOUND_COPY_EMAIL`)
- Optional Google auth:
  - `GOOGLE_AUTH_ENABLED=true`
  - `GOOGLE_CLIENT_ID`
  - `GOOGLE_CLIENT_SECRET`
  - `GOOGLE_REDIRECT_URI` (optional override; default is `https://<host>/api/auth/google/callback`)
  - `GOOGLE_AUTH_AUTO_CREATE_USERS` (`true` to auto-create Google users on first login)
  - `GOOGLE_AUTH_DEFAULT_ROLE` (`user` or `admin` for auto-created Google users)
  - `GOOGLE_AUTH_ALLOWED_DOMAINS` (optional comma-separated email domains)
  - `GOOGLE_OAUTH_STATE_MAX_AGE_MS` (default `600000`)
- Email gateway:
  - `EMAIL_GATEWAY_WEBHOOK_TOKEN` (required; used by `/api/email/inbound` header `x-email-gateway-token`)
- Commercial mode:
  - `MULTI_TENANT_ENABLED` (default `true`)
  - `DEFAULT_TENANT_ID` (default `default`)
  - `COMMERCIAL_ENFORCEMENTS_ENABLED` (default `true`)
  - `IDEMPOTENCY_TTL_SECONDS` (default `86400`)
  - `BILLING_MODE` (`free` by default; set to `paid` to enable Stripe subscription lifecycle)
  - `STRIPE_SECRET_KEY`
  - `STRIPE_WEBHOOK_SECRET`
  - `STRIPE_DEFAULT_PLAN` (`starter`, `pro`, `enterprise`)
  - `STRIPE_PRICE_STARTER_MONTHLY`, `STRIPE_PRICE_PRO_MONTHLY`, `STRIPE_PRICE_ENTERPRISE_MONTHLY`
  - Optional URL overrides: `STRIPE_SUCCESS_URL`, `STRIPE_CANCEL_URL`, `STRIPE_PORTAL_RETURN_URL`
- Optional Cloudflare D1 persistence (users + settings/contacts/fax history snapshots):
  - `CLOUDFLARE_ACCOUNT_ID`
  - `CLOUDFLARE_D1_DATABASE_ID`
  - either `CLOUDFLARE_API_TOKEN` or (`CLOUDFLARE_API_KEY` + `CLOUDFLARE_EMAIL`)
- Security hardening:
  - `TELNYX_WEBHOOK_PUBLIC_KEY`
  - `WEBHOOK_SIGNATURE_REQUIRED`
  - `MEDIA_URL_SIGNING_SECRET`
  - `MEDIA_URL_TTL_SECONDS`
  - `UPLOAD_RETENTION_SECONDS`
  - `AUTH_RATE_WINDOW_MS`, `AUTH_RATE_MAX_ATTEMPTS_PER_IP`
  - `AUTH_LOCKOUT_THRESHOLD`, `AUTH_LOCKOUT_MS`
  - `BULK_WORKER_POLL_MS`

## 3. Run locally

```bash
npm install
npm start
```

Open:

- `http://localhost:10000` (public marketing + signup page)
- `http://localhost:10000/app` (fax app login/workspace)

## 4. Login and roles

Public signup:

- `POST /api/public/signup` creates:
  - tenant workspace
  - first admin user
  - optional Stripe checkout session URL (when paid billing mode is enabled)
- Marketing page signup modal calls this endpoint and redirects to Stripe checkout when required.

- `admin`:
  - Send/view faxes
  - Open settings from gear button
  - Manage app Telnyx credentials
  - Update Telnyx fax application settings
  - Manage outbound copy email settings
  - Manage office profile defaults and user accounts
  - Create/reset user accounts
  - Create Google-authenticated users by Google email
  - Start or upgrade Stripe subscription from Billing card
  - Open Stripe customer portal to manage/cancel subscription
- `user`:
  - Send/view faxes only
  - Upload files and reuse previous media URL

Google account sharing model:

- Multiple users can belong to the same tenant.
- Each user can sign in with their own Google account (when linked as a Google user in User Management, or when auto-create is enabled).
- Local username/password login remains available for local-provider users.

Tenant provisioning notes:

- Tenants are no longer auto-created from request headers/body.
- Login to an unknown tenant returns `404 Tenant is not provisioned`.
- Create tenants explicitly via admin API:
  - `POST /api/admin/tenants` (default tenant admin only)
  - `GET /api/admin/tenants`

### 4.1 Google Sign-In setup (optional)

1. In Google Cloud Console, create OAuth client credentials (Web application).
2. Add authorized redirect URI:
   - `https://<your-domain>/api/auth/google/callback`
3. Put `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in your `.env`.
4. Set `GOOGLE_AUTH_ENABLED=true`.
5. Restart app and confirm login page shows `Sign In With Google`.

## 5. Telnyx webhook URL

Point your Fax App webhook to:

- `https://<your-app-domain>/telnyx/webhook`

This app also accepts:

- `POST /api/webhooks/telnyx`
- `POST /api/email/inbound` (email-to-fax webhook)

For paid billing mode (`BILLING_MODE=paid`), Stripe webhook endpoint:

- `POST /api/webhooks/stripe`

Webhook hardening:

- Set `TELNYX_WEBHOOK_PUBLIC_KEY` to the signing key from Telnyx portal.
- Keep `WEBHOOK_SIGNATURE_REQUIRED=true` in production.
- Set and require `EMAIL_GATEWAY_WEBHOOK_TOKEN` for email webhook authentication.

### 5.1 Email-to-fax gateway format

- Subject must include destination:
  - `FAX TO: +17145551234`
  - multiple: `FAX TO: +17145551234,+17145557654`
- Optional body commands:
  - `COVER_SUBJECT: Referral Packet`
  - `COVER_MESSAGE: Please review attached records.`
  - `INCLUDE_COVER_PAGE: true|false`
- Attachments:
  - PDF/TIFF only, max 5 items

## 6. How verification works

1. App sends fax with `POST /v2/faxes`
2. Telnyx webhook events update status in local store
3. Final statuses are:
   - `delivered` = success
   - `failed` = denied/failed (with reason)
4. "Poll" button calls `GET /v2/faxes/{fax_id}` via backend fallback
5. If failure reason indicates busy line, app retries automatically (default: 3x every 10 min)
6. If still failed, app sends owner alert email with:
   - human summary
   - support-oriented failure details/code

## 6.1 Outbound copy email

1. Admin can set:
   - `Send outbound fax copy email` (on/off)
   - `Outbound Copy Email` (default `eyecarecenteroc@gmail.com`)
2. On each outbound fax queue event, app emails a copy notification.
3. If uploaded from this app, the uploaded PDF/TIFF is attached when possible.
4. SMTP must be configured for email sending.
5. On the main Send Fax form, users can toggle copy email per fax job.

## 7. Upload behavior

1. In the Send Fax section, attach one or multiple PDF/TIFF files directly.
2. When you click `Send Fax`, attached files are uploaded to `/api/uploads/batch`.
3. Uploaded files are stored outside the public web root.
4. The app generates signed expiring media URLs under `/media/:filename?...` for Telnyx retrieval.
5. The app sends using those signed URLs internally; users do not need to enter media URLs.
6. Old uploaded files are cleaned up automatically based on retention settings.
7. The first uploaded media URL is saved as your user's last URL.

## 7.2 Recipient behavior

1. Enter one or more destination numbers in `To (E.164)` separated by comma or new line.
2. Or type a contact name in `Find Contact By Name` and pick a suggestion.
3. Click `Address Book` to open popup picker:
   - search contacts
   - select from top 5 most used
   - press `OK - Add Selected Contacts`
4. A `Send Fax` button appears directly below the Address Book button.
4. Backend queues one Telnyx fax per recipient and returns queued/failed counts.

## 7.1 Cover page behavior

1. `Add HIPAA cover page` is enabled by default on Send Fax.
2. Subject and message are user-editable before sending.
3. Generated cover page uses office profile defaults:
   - office name
   - office fax
   - office email

## 8. Deploy on Render

1. Push this app to a GitHub repo.
2. Create a Render Web Service from that repo.
3. Build command: `npm install`
4. Start command: `npm start`
5. Add environment variables from `.env`.
6. Use generated URL as Telnyx webhook:
   - `https://<service>.onrender.com/telnyx/webhook`
7. For persistence (required for users/settings/history across restarts):
   - attach a Render Disk
   - mount path: `/var/data`
   - set `DATA_DIR=/var/data/telnyx-fax-office-app` (or allow app default)
8. For always-on inbound webhook reliability:
   - use a non-sleeping Render plan, or
   - configure external keepalive pings to `https://<service>.onrender.com/api/health`

## 8.1 Cloudflare D1 for free-friendly persistence

1. Create D1 database (example name): `refract-ing-fax-app`
2. Add env vars on Render service:
   - `CLOUDFLARE_ACCOUNT_ID`
   - `CLOUDFLARE_D1_DATABASE_ID`
   - `CLOUDFLARE_API_KEY` and `CLOUDFLARE_EMAIL` (or `CLOUDFLARE_API_TOKEN`)
3. Deploy latest commit.
4. Verify `GET /api/health` returns:
   - `"d1_users_enabled": true`
   - `"d1_app_stores_enabled": true`

When enabled, users plus app store snapshots (settings/contacts/fax history/bulk jobs) survive service restarts/deploys even without Render disk.
When D1 is not enabled, login sessions persist to local file storage by default (`DATA_DIR/sessions_local.json`).

## 9. Contacts, tags, and bulk fax

1. Add contacts manually in the Contacts section.
2. Import CSV with headers:
   - `name,fax_number,tags,email,notes`
3. Use tag filter to view a subset of contacts.
4. In **Bulk Fax By Tags**, choose:
   - media URL
   - tag match mode (`any` or `all`)
   - selected tags (or send all contacts)
5. Queue bulk job and monitor status table.
6. Contact storage enforces a 3000-contact cap.

CSV template:

- `/contact-import-template.csv`

## Commercial v2 alpha

- Tenant-aware login and API scoping (`X-Tenant-Id` header).
- Tenant-scoped users, contacts, fax history, and bulk jobs.
- Idempotent outbound fax queue endpoint via `Idempotency-Key` header on `POST /api/faxes`.
- Immutable audit event log:
  - `GET /api/admin/audit-events`
- Billing and plan controls:
  - `GET /api/admin/billing`
  - `PATCH /api/admin/billing`
  - `POST /api/admin/billing/checkout-session`
  - `POST /api/admin/billing/portal-session`
  - In `BILLING_MODE=free`, billing API remains available but paid plan updates are blocked.
- Admin tenant/user security controls:
  - `PATCH /api/admin/users/:username/mfa`
  - `GET /api/admin/tenant`
  - `GET /api/admin/tenants`
  - `POST /api/admin/tenants`

## Versioning

- Stable production line: `main` (`1.x`)
- Commercial major line: `codex/v2-commercial` (`2.x`)
- Known-good rollback tag: `v1.2.0-known-good`
- Branch/tag policy: `/Users/alex/Documents/Projects/Telnyx/docs/VERSIONING-AND-BRANCHING.md`

## Security

- Do not expose your Telnyx API key in frontend code.
- Rotate keys if shared in chat or logs.
- Change bootstrap admin password immediately after first login.
- Keep webhook signature validation enabled in production.
- Use scoped Cloudflare API tokens instead of global API keys.
- Login endpoints include IP throttling and temporary account lockout after repeated failures.
