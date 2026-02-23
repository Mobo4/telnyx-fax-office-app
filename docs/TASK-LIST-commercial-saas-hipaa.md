# Task List: Commercial SaaS + HIPAA-Ready Buildout

## Progress Snapshot
- [x] Create commercial infrastructure scaffolding (`infra/docker-compose.commercial.yml`).
- [x] Add initial SQL migration for multi-tenant commercial core (`db/migrations/001_commercial_core.sql`).
- [x] Add app-level tenant-aware runtime in v2 branch (header/session scoped).
- [x] Add immutable audit event logging file pipeline.
- [x] Add idempotent send support for `POST /api/faxes` (`Idempotency-Key`).
- [x] Add plan-based limits for contacts/users/recipients per send.
- [x] Add admin billing endpoints for plan + seat management.
- [x] Add admin MFA toggle endpoint for user accounts.
- [x] Remove unauthenticated tenant auto-provisioning and require explicit tenant provisioning.
- [x] Add tenant provisioning admin API (`GET/POST /api/admin/tenants`) for controlled workspace creation.
- [x] Fix tenant config isolation (remove global config fallback bleed).
- [x] Add tenant ownership guard for `/api/faxes/:id/refresh`.
- [x] Add free billing mode (`BILLING_MODE=free`) while keeping paid API shape for future Stripe work.
- [ ] Wire app runtime to Postgres/Redis repositories in production mode.

## Phase 1: Foundation (P0)
- [ ] Implement multi-tenant schema in Postgres with strict tenant scoping.
- [ ] Replace JSON file stores with DB repositories for users/settings/contacts/faxes.
- [ ] Add managed queue + worker pipeline for fax processing.
- [ ] Add idempotency keys and dead-letter handling.
- [x] Add immutable audit_events pipeline for auth/settings/fax lifecycle.

## Phase 1: Security and Access (P0)
- [x] Add MFA for admin roles.
- [ ] Add SSO support (OIDC/SAML integration path).
- [ ] Add scoped API keys per tenant (server-side only).
- [ ] Add webhook replay protection cache and event dedupe.
- [ ] Add secret management integration (no plaintext env key sprawl).

## Phase 1: Billing (P0)
- [ ] Add Stripe subscription model (plan + seat + usage).
- [ ] Add usage event ingestion for fax/page metering.
- [x] Enforce plan limits in API (contacts/users/rate limits/history retention).
- [ ] Add billing portal and invoice history UI.

## Phase 1: Data and Storage (P0)
- [ ] Migrate media storage to encrypted object storage (S3/R2).
- [ ] Keep signed expiring media URL access controls.
- [ ] Implement retention policy scheduler and deletion logs.
- [ ] Implement backup + restore runbooks and validation jobs.

## Phase 1: UX and Commercial Polish (P1)
- [ ] Ship design QA scorecard and pass criteria.
- [ ] Add advanced history filters, saved views, export CSV.
- [ ] Add inline status timeline for each fax (queued/sending/delivered/failed).
- [ ] Add robust empty states and error recovery UX.

## Phase 1: Testing and SRE (P0)
- [ ] Add integration test suite for send/webhook/history/RBAC.
- [ ] Add end-to-end browser tests for core workflows.
- [ ] Add load tests for queue throughput and API latency SLO.
- [ ] Add dashboards for queue depth, send failures, webhook failures.
- [ ] Add paging alerts for reliability and security thresholds.

## HIPAA Program Checklist (Required for production contracts)
- [ ] Execute BAA process and legal templates.
- [ ] Publish security risk assessment and remediation log.
- [ ] Define workforce access policy and least-privilege SOP.
- [ ] Define breach response and customer notification SOP.
- [ ] Validate audit trail retention and export controls.

## Exit Gates
- [ ] Multi-tenant isolation test suite passes.
- [ ] Security controls pass internal review.
- [ ] Billing flow passes sandbox and live smoke tests.
- [ ] Queue reliability and recovery tests pass.
- [ ] Compliance checklist approved by legal/compliance owners.
