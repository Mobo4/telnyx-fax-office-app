---
name: fax-bulk-worker-recovery
description: Ensure queued bulk fax jobs recover after restart via periodic and startup processing.
---

# Fax Bulk Worker Recovery

## Scope
- Recover and process queued bulk jobs automatically after restart.
- Keep recurring processing loop while app is running.

## Steps
1. Add startup processing trigger.
2. Add interval-based queue worker.
3. Preserve existing in-request queue trigger.
4. Add logging for worker-cycle failures.

## Done Criteria
- Queued jobs are eventually processed without manual UI action.
