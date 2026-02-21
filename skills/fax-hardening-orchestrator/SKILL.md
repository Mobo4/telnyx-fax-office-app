---
name: fax-hardening-orchestrator
description: Coordinate parallel hardening workstreams for webhook verification, secure media delivery, auth throttling, bulk worker recovery, and session durability in the Telnyx fax app.
---

# Fax Hardening Orchestrator

Use this skill when a request spans multiple security/reliability tracks and should be executed in parallel.

## Parallel Workstreams
- `fax-webhook-signature-guard`
- `fax-media-access-guard`
- `fax-auth-throttle-lockout`
- `fax-bulk-worker-recovery`
- `fax-d1-session-store`

## Workflow
1. Confirm acceptance criteria for each track.
2. Run file-read tasks in parallel.
3. Apply incremental patches per track.
4. Run validation (`node --check server.js`, `node --check public/app.js`).
5. Update continuity docs:
   - `/Users/alex/Documents/Projects/Telnyx/docs/PRD-fax-app-enhancements.md`
   - `/Users/alex/Documents/Projects/Telnyx/docs/KNOWLEDGE-BASE.md`
   - `/Users/alex/Documents/Projects/Telnyx/docs/TASK-LIST.md`
   - `/Users/alex/Documents/Projects/Telnyx/docs/CHANGE-LOG.md`

## Done Criteria
- All five hardening tracks implemented.
- Health endpoint reflects active hardening controls.
- Smoke tests pass for auth, upload/media, and webhook path.
