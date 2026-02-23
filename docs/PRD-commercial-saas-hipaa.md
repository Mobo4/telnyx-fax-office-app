# PRD: Commercial Multi-Tenant Fax SaaS (HIPAA-Ready)

## Version
- Date: 2026-02-22
- Owner: Product + Engineering
- Status: Draft v1 for implementation

## Implementation Snapshot (v2 alpha)
- Branch: `codex/v2-commercial`
- Version: `2.0.0-alpha.1`
- Completed in current alpha:
  - Tenant-aware request scoping via `X-Tenant-Id` + session tenant binding
  - Immutable audit event logging APIs
  - Idempotent `POST /api/faxes` support
  - Plan-based enforcement for contacts/users/recipients
  - Billing admin APIs (plan/seats/status)
  - Admin MFA toggle API
- Still pending for production commercialization:
  - Full Postgres/Redis repository wiring
  - Stripe subscription lifecycle
  - Queue dead-letter and replay controls
  - Enterprise SSO

## 1. Product Vision
Build a commercially viable, browser-first fax platform for healthcare and professional offices with:
- Reliable outbound and inbound faxing via Telnyx
- Secure multi-user, multi-office operations
- Auditability, compliance controls, and strong admin governance
- Scalable architecture that supports growth from one office to thousands

This PRD is "HIPAA-ready by design." Final legal HIPAA compliance requires executed BAAs, organizational policies, workforce training, and external audits.

## 2. Commercial Goals
- SaaS-ready multi-tenant platform (not single-office only)
- Paid subscriptions with usage metering and invoicing
- Enterprise-grade security and role controls
- Operational reliability and observability suitable for paid SLAs
- Premium UX that is efficient for high-volume fax workflows

## 3. Non-Goals (Phase 1)
- Native desktop/mobile apps (web app first)
- AI document extraction/OCR workflows
- Global telecom abstraction beyond Telnyx

## 4. User Personas
- `Owner/Admin`: configures account, billing, users, numbers, settings.
- `Staff User`: sends faxes, uses address book, tracks status/history.
- `Compliance/Auditor`: reviews immutable logs and access history.
- `MSP/Partner Admin` (future): manages multiple client tenants.

## 5. UX and Design Standards (10x Quality Bar)
### Visual Direction
- Clean medical-office professionalism with clear hierarchy.
- Strong contrast, large click targets, and low cognitive load.
- Fast keyboard-first workflow for reception/front-desk users.

### Core UX Requirements
- Login page centered with branded identity and clear trust indicators.
- Send workflow on one screen: recipients, address book, attachments, cover options, send status.
- Confirmation modal after queue response with actionable next steps.
- No dead-end states; every error has explicit corrective guidance.
- Table views for Sent/Received with filters, search, export, and status badges.

### Design Review Gate
- A "Design QA Scorecard" must pass before release:
  - Task completion speed
  - Error recovery clarity
  - Accessibility (WCAG 2.1 AA baseline)
  - Mobile and desktop responsiveness
  - Visual consistency

## 6. Functional Scope
### 6.1 Authentication and Access Control
- Local username/password, plus optional SSO (Google/Microsoft/SAML) in paid tiers.
- MFA required for admins.
- Role model:
  - `owner_admin`
  - `admin`
  - `user`
  - `auditor` (read-only logs/history)
- Admin-only settings behind dedicated control.
- Session controls:
  - inactivity timeout
  - force logout all sessions
  - device/session list

### 6.2 Tenant and Workspace Model
- Multi-tenant isolation by `tenant_id`.
- Every record scoped to tenant:
  - users
  - contacts
  - faxes
  - settings
  - audit events
  - billing usage
- Strict server-side authorization checks on every API route.

### 6.3 Fax Sending
- Single and multi-recipient send.
- File upload (PDF/TIFF), max 5 files per job initially.
- Optional HIPAA cover page enabled by default.
- Queue confirmation with fax IDs and immediate history write.
- Outbound copy email summary (metadata only, no full fax attachment by default).

### 6.4 Inbound Fax
- Inbound webhook processing with signature verification.
- Inbound email backup recipient configurable.
- Received history tab with file links and statuses.

### 6.5 Address Book and Bulk Fax
- Contact cap: 3000 per tenant (configurable in higher tiers).
- Tagging and search.
- Top-5 frequent contacts on send screen.
- Bulk fax by tag in background job system with progress and failure logs.

### 6.6 Admin Settings
- Telnyx credentials/settings (server-side secret storage).
- Office profile defaults.
- Outbound copy defaults.
- User provisioning and password reset.
- Settings change audit log entries.

### 6.7 Billing and Subscriptions
- Stripe integration:
  - monthly/annual plans
  - seat-based options
  - usage metering (pages/faxes)
  - invoice history
- Plan-based limits enforced in API.

### 6.8 Audit and Compliance
- Immutable audit events for:
  - login/logout
  - failed logins
  - settings changes
  - user management actions
  - fax submit/status transitions
- Exportable audit trail by date range.

## 7. HIPAA-Ready Security Requirements
### Technical Safeguards
- Encryption in transit (TLS 1.2+).
- Encryption at rest for DB and stored media.
- Signed, expiring media URLs.
- Principle of least privilege for all credentials and service tokens.
- Secrets manager for API keys and SMTP credentials.
- Webhook signature verification and replay protection.
- Rate limiting and lockout protections on auth endpoints.

### Administrative/Operational Safeguards
- BAA support process for covered entities.
- Access review process and least privilege policy.
- Incident response runbook and breach notification process.
- Data retention and secure deletion policy.
- Backup and restore testing cadence.

### Compliance Note
- Product can be engineered for HIPAA readiness.
- Actual HIPAA compliance also depends on customer configuration, contracts, and org policy execution.

## 8. Scalability and Reliability Architecture
### Proposed Production Topology
- `Web/API`: stateless Node.js service behind load balancer.
- `Queue`: Redis/SQS/Cloud Tasks for send + webhook processing.
- `Worker`: async fax/bulk processing and retry pipeline.
- `DB`: Postgres (multi-tenant schema, row-level scoping).
- `Object Storage`: S3/R2 for fax media (encrypted).
- `Cache`: Redis for sessions/rate-limits/replay dedupe.
- `Observability`: structured logs, metrics, traces, alerting.

### Reliability Targets
- API availability target: 99.9% monthly.
- Queue durability: at-least-once processing with idempotency keys.
- Webhook idempotency: dedupe by event ID/signature/timestamp.
- Retry policy: exponential backoff + dead-letter queue.

### Performance Targets
- `POST /api/faxes` p95 < 1.5s (queue response, excluding telco completion).
- `GET /api/faxes?limit=50` p95 < 500ms with indexed queries.
- Support baseline 100 concurrent active users per tenant tier-1.

## 9. Data Model (High Level)
- `tenants`
- `users`
- `roles` and `user_roles`
- `contacts`
- `fax_jobs`
- `fax_recipients`
- `fax_events`
- `audit_events`
- `settings`
- `billing_subscriptions`
- `billing_usage_events`

All tables include:
- `tenant_id`
- `created_at`
- `updated_at`
- soft delete where applicable

## 10. API and Integration Requirements
- Public API keys per tenant with scopes.
- Webhooks for fax status callbacks to customer systems.
- Integration adapters:
  - Zapier/Make (phase 2)
  - GoHighLevel webhook mapping (phase 2)

## 11. Testing and Quality Gates
### Automated Tests
- Unit tests for normalization, validation, auth, and policy checks.
- Integration tests for send flow, webhook flow, history, settings RBAC.
- End-to-end browser tests for core office workflows.

### Load and Failure Testing
- Load tests for send/history endpoints.
- Chaos/failure tests for queue worker crashes and webhook retries.
- Disaster recovery drill with restore verification.

### Release Criteria
- All P0/P1 defects closed.
- Security scan and dependency check pass.
- Backup restore test pass.
- Audit trail and access-control tests pass.
- Billing limit enforcement tests pass.

## 12. Rollout Plan
### Phase 1 (Commercial Core)
- Multi-tenant DB migration.
- Queue/worker architecture.
- Audit log foundation.
- Stripe plans + usage metering.
- SSO/MFA for admins.

### Phase 2 (Enterprise Expansion)
- Advanced compliance controls and data retention tooling.
- Public API + webhook subscriptions.
- Extended reporting and analytics.
- Partner/MSP features.

## 13. Open Risks and Mitigations
- Risk: Single-process bottlenecks with current architecture.
  - Mitigation: move to stateless API + dedicated worker + managed queue.
- Risk: Compliance gaps in operations, not code.
  - Mitigation: compliance program checklist and owner assignment.
- Risk: Telco/provider outages.
  - Mitigation: retries, transparent status states, optional multi-provider abstraction later.

## 14. Definition of Done for "Commercial Ready"
- Multi-tenant isolation verified by tests and review.
- HIPAA-ready controls implemented and documented.
- Billing + plan enforcement live.
- Audit logs immutable and queryable.
- Queue-backed processing with retry/idempotency in production.
- Observability dashboards and on-call alerting in place.
- Security review completed and accepted.
