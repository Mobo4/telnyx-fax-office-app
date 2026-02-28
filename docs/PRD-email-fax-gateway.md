# PRD: Fax-to-Email and Email-to-Fax Gateway

## Version
- Date: 2026-02-27
- Status: Phase A/B baseline implemented; Phase C/D/E pending
- Scope: Add production-grade inbound fax delivery to email and outbound fax submission from email

## Implementation Status
- Implemented:
  - `POST /api/email/inbound` (token-gated)
  - sender allowlist enforcement (emails + domains)
  - subject parsing (`FAX TO:`), attachment intake, queue integration
  - message-id dedupe and replay-safe response
  - admin APIs for gateway config + request log
  - admin UI settings card for gateway controls
  - optional sender response email and inbound fax notification email
- Pending:
  - provider-native signature verification (Mailgun/SendGrid)
  - richer admin request log UI table
  - replay control endpoint and deeper compliance hardening

## Current State
- `Fax-to-email` is partially available today through Telnyx fax app setting `fax_email_recipient` (provider-side).
- `Email-to-fax` is not currently implemented in this app.
- Current app sends faxes from browser UI and tracks status/history.

## Product Goal
Allow office teams to work entirely by email when needed:
- receive faxes in email reliably with audit visibility in app
- send faxes by emailing documents to a controlled gateway address

## User Roles
- Admin:
  - configure gateway addresses, routing policy, allowlists, and security controls
  - view email-to-fax queue outcomes and failures
- Standard user:
  - send by email from approved mailbox
  - receive fax notifications and file links per policy

## Feature Set

### 1) Fax-to-Email (Inbound)
- Keep Telnyx inbound webhook as primary status/data source.
- On inbound fax completion:
  - deliver notification email to configured recipients
  - include sender/receiver/time/page count/status
  - include secure signed file links (or optional attachment mode)
- Allow multiple recipients with roles:
  - ops mailbox (default)
  - escalation mailbox
  - per-tenant distribution list

### 2) Email-to-Fax (Outbound by Email)
- Provision a tenant gateway address format:
  - `fax+<tenant>@refract.ing` or `tenant-id@fax.refract.ing`
- Parse inbound email into fax request:
  - destination fax number from subject line (required format)
  - optional cover subject/message from body header markers
  - attachments PDF/TIFF only
- Validate sender against policy:
  - strict allowlist (default)
  - optional verified-domain mode
- Queue through existing fax send pipeline.
- Reply email with queue confirmation and final delivery outcome.

## Email Command Format (Initial)
- Subject:
  - `FAX TO: +17145551234`
  - multiple recipients: `FAX TO: +17145551234,+17145557654`
- Body optional metadata:
  - `COVER_SUBJECT: Referral Packet`
  - `COVER_MESSAGE: Please review attached records.`
- Attachments:
  - up to 5 files, PDF/TIFF, existing app size limits apply

## Security and Compliance
- Enforce sender allowlist by default.
- Reject invalid format with human-readable rejection email.
- Store full audit event for each email request:
  - sender, message-id, parsed recipients, file summary, result
- Deduplicate by message-id to prevent resend on provider retries.
- Never expose Telnyx API key in client email flow.
- Preserve signed media URL model and retention policy.
- Add compliance controls:
  - BAA-aligned SMTP provider configuration requirements
  - minimum TLS transport policy
  - restricted PHI in error emails

## Architecture

### Inbound Email Provider
- Use one provider inbound webhook path (recommended):
  - Mailgun Routes or SendGrid Inbound Parse
- New endpoint:
  - `POST /api/email/inbound`
- Verification:
  - provider signature validation required in production

### Internal Processing
1. Receive inbound provider webhook.
2. Verify signature and parse message.
3. Normalize recipients (E.164).
4. Validate sender policy + attachment policy.
5. Save attachments to upload store and mint signed URLs.
6. Call existing fax send workflow (`/api/faxes` equivalent internal service).
7. Emit audit event and email response.

## Data Model Additions
- `data/email_gateway_config.json`
  - gateway address rules
  - allowed senders/domains
  - response email templates
- `data/email_requests.json`
  - message-id dedupe index
  - parse + validation outcome
  - mapped fax IDs
- Extend fax record metadata:
  - `source: ui | api | email_gateway`
  - `email_sender`
  - `email_message_id`

## Admin UI Additions
- New admin card: `Email Gateway`
  - enable/disable email-to-fax
  - set inbound gateway domain/address mode
  - manage allowed senders/domains
  - test parser with dry-run sample
- New history filter chip:
  - `Source: Email Gateway`

## API Endpoints
- `GET /api/admin/email-gateway` (admin)
- `PATCH /api/admin/email-gateway` (admin)
- `POST /api/email/inbound` (public provider webhook; signature required)
- `GET /api/admin/email-requests` (admin)
- `POST /api/admin/email-requests/:id/replay` (admin controlled retry)

## Usage and Billing Policy
- Page counting policy is identical to UI/API sends.
- Email-to-fax pages count as outbound pages for plan usage/overage.
- Fax-to-email inbound pages count as inbound pages.
- Rejection emails must disclose:
  - why the request was rejected
  - how pages are counted when accepted
  - overage policy reference link

## Failure Handling
- Parser errors:
  - respond with rejection reason and accepted formats.
- Attachment errors:
  - reject unsupported types or oversize payloads.
- Telnyx queue failure:
  - send failure response email with next steps.
- Busy/no-answer outcomes:
  - continue existing retry policy and terminal alert behavior.

## Non-Functional Requirements
- Idempotent email processing by provider message-id.
- Structured logging for support.
- End-to-end traceability from email request to fax outcome.
- No blocking effect on existing browser UI fax flow.

## Acceptance Criteria
- Admin can configure gateway and allowed senders in app.
- Authorized sender can email PDF/TIFF and queue fax successfully.
- Unauthorized sender is rejected and logged.
- Invalid destination format is rejected with clear guidance.
- Email-sourced fax appears in normal fax history with source marker.
- Usage dashboard includes email-sourced page counts.
- Duplicate provider webhook deliveries do not create duplicate faxes.

## Implementation Phases
1. Phase A: Provider webhook + signature verification + parsing dry run.
2. Phase B: Attachment intake + internal queue integration + audit trail.
3. Phase C: Admin gateway settings UI + email request history.
4. Phase D: Response emails + dedupe/replay controls + hardening.
5. Phase E: Compliance review and operational runbook.

## Open Decisions
- Pick inbound email provider (Mailgun vs SendGrid).
- Attach file to notification emails vs signed-link only default.
- Per-tenant custom gateway domain (later) vs shared domain (initial).
