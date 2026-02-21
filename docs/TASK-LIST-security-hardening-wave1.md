# Task List: Security Hardening Wave 1

## Orchestrator
- [x] Define scope, acceptance criteria, and rollout gates.
- [x] Assign subagent responsibilities and parallel workstreams.
- [x] Merge outputs into unified deployable branch.

## Subagent A: Webhook Signature Guard
- [x] Add webhook signature verification helper.
- [x] Add timestamp freshness enforcement.
- [x] Add env toggles for signature behavior.
- [x] Update webhook route to enforce verification when enabled.

## Subagent B: Media Access Guard
- [x] Move uploads out of public static web root.
- [x] Add signed media URL generator and verifier.
- [x] Add `/media/:filename` secure retrieval route.
- [x] Add periodic cleanup for expired/stale uploads.

## Subagent C: Auth Lockout Guard
- [x] Add IP/window login throttling.
- [x] Add per-username temporary lockout.
- [x] Clear attempt counters on successful login.
- [x] Expose auth policy values via health endpoint.

## Subagent D: Queue Recovery Guard
- [x] Add interval-based bulk queue recovery loop.
- [x] Add startup kick to process queued jobs quickly.
- [x] Keep existing on-submit immediate queue trigger.

## Subagent E: Session Durability Guard
- [x] Add D1 sessions table bootstrap.
- [x] Implement D1 session store (`get/set/destroy/touch`).
- [x] Wire session middleware to D1 store when available.
- [x] Keep fallback behavior for non-D1 environments.

## Validation
- [x] `node --check server.js`
- [x] `node --check public/app.js`
- [x] Smoke test signed media URL behavior.
- [x] Smoke test login lockout behavior.
- [x] Smoke test D1-backed startup and auth login.

## Follow-ups (Wave 2)
- [ ] Add replay protection cache for webhook events.
- [ ] Add lockout persistence (D1/Redis) instead of in-memory counters.
- [ ] Add encrypted object storage for uploaded files (S3/R2).
- [ ] Add structured security audit trail (admin changes + auth events).
