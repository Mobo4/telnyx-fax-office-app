# PRD: Security and Reliability Hardening Wave 1

## Version
- Date: 2026-02-21
- Owner: Fax Platform
- Status: Implemented

## Objective
Ship the next 5 production hardening improvements for the office fax app:
1. Telnyx webhook signature verification
2. Secure media delivery (signed/expiring URLs, no public upload folder)
3. Login throttling and temporary account lockout
4. Durable bulk queue worker recovery loop
5. Durable session persistence (D1-backed)

## Business Outcomes
- Reduce risk of spoofed webhook events and status tampering.
- Reduce PHI exposure from publicly accessible fax documents.
- Reduce credential stuffing and brute-force risk.
- Increase bulk fax reliability after restart/deploy events.
- Keep authentication sessions stable across restarts on ephemeral hosts.

## In Scope
- Backend hardening in `server.js`
- Environment configuration updates (`.env.example`)
- Runtime health visibility (`/api/health`)
- Deployment/runtime documentation updates

## Out of Scope
- Full HIPAA compliance certification package
- End-to-end encryption at rest for uploaded files
- Multi-tenant RBAC partitioning
- Dedicated distributed queue infrastructure

## Architecture Decisions
- Use Telnyx Ed25519 signature headers for webhook verification when configured.
- Store uploaded files in `DATA_DIR/uploads` (not under web static root).
- Expose files only through signed URLs: `/media/:filename?exp=...&sig=...`.
- Use in-memory lockout/throttle counters for fast protection without DB dependency.
- Run periodic bulk queue recovery worker to process `queued` jobs continuously.
- Use D1 session table when D1 is configured; fallback to default memory store otherwise.

## Functional Requirements

### FR-1 Webhook Verification
- Verify `telnyx-signature-ed25519` + `telnyx-timestamp` using configured Telnyx public key.
- Reject invalid signatures with `401` when verification is enabled.
- Support toggle via env:
  - `WEBHOOK_SIGNATURE_REQUIRED`
  - `TELNYX_WEBHOOK_PUBLIC_KEY`
  - `WEBHOOK_MAX_AGE_SECONDS`

### FR-2 Secure Media Access
- Uploaded files must not be directly served from public static paths.
- Outbound fax media URLs must be signed and expiring.
- Add cleanup routine for expired/stale uploaded files.
- Env controls:
  - `MEDIA_URL_SIGNING_SECRET`
  - `MEDIA_URL_TTL_SECONDS`
  - `UPLOAD_RETENTION_SECONDS`

### FR-3 Auth Throttling
- Track failed logins by IP and username.
- Enforce per-IP rate limit window.
- Enforce temporary username lockout after threshold failures.
- Env controls:
  - `AUTH_RATE_WINDOW_MS`
  - `AUTH_RATE_MAX_ATTEMPTS_PER_IP`
  - `AUTH_LOCKOUT_THRESHOLD`
  - `AUTH_LOCKOUT_MS`

### FR-4 Bulk Recovery Worker
- Poll queue on interval and process any `queued` bulk jobs.
- Kick off a startup worker cycle after boot.
- Env control:
  - `BULK_WORKER_POLL_MS`

### FR-5 Durable Sessions
- Add D1 `sessions` table for session payload + expiry.
- Use D1 session store when D1 is configured.
- Fall back to default memory store when D1 is not configured.
- Env control:
  - `SESSION_MAX_AGE_MS`

## Non-Functional Requirements
- Backward-compatible startup in environments without D1.
- Avoid blocking normal fax queue flow when optional hardening controls are disabled.
- Keep health endpoint visibility for operations verification.
- Keep code syntax-valid and deployable to Render.

## Acceptance Criteria
- `/api/health` exposes:
  - `webhook_signature_required`
  - `webhook_public_key_configured`
  - `d1_users_enabled`
  - `d1_app_stores_enabled`
- Upload APIs return signed `/media/...` URLs.
- `/media/:filename` rejects invalid/expired signatures.
- Repeated failed login attempts produce `429` lockout/throttle behavior.
- Queued bulk jobs are processed by interval worker after restart.
- D1-enabled deployment keeps sessions working across restart.

## Risks and Mitigations
- Risk: Enabling webhook verification without valid key blocks inbound status updates.
  - Mitigation: explicit startup warning + env-based toggle.
- Risk: Signed media URLs expire before Telnyx fetch.
  - Mitigation: configurable TTL with safe default and retention cleanup window.
- Risk: In-memory lockout state resets on restart.
  - Mitigation: acceptable for wave 1; can move to persistent lockout store in wave 2.

## Parallel Agent Plan
- `Orchestrator Agent`
  - Coordinates sequencing, dependencies, and verification gates.
- `Subagent A: Webhook Signature Guard`
  - Implements and validates FR-1.
- `Subagent B: Media Access Guard`
  - Implements and validates FR-2.
- `Subagent C: Auth Lockout Guard`
  - Implements and validates FR-3.
- `Subagent D: Queue Recovery Guard`
  - Implements and validates FR-4.
- `Subagent E: Session Durability Guard`
  - Implements and validates FR-5.

## Rollout Steps
1. Merge and deploy hardening code.
2. Set production env values (especially webhook key + media signing secret).
3. Validate health endpoint flags.
4. Run smoke tests for login, upload, send, history refresh, and webhook ingestion.
