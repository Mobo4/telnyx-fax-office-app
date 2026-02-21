---
name: fax-d1-session-store
description: Add D1-backed session persistence to keep authentication sessions durable across restarts.
---

# Fax D1 Session Store

## Scope
- Create sessions table in D1.
- Implement express-session store methods.
- Use D1 store when D1 env is configured.

## Steps
1. Add D1 sessions table bootstrap.
2. Implement store `get/set/destroy/touch`.
3. Wire session middleware to use D1 store conditionally.
4. Keep memory-store fallback for non-D1 environments.

## Done Criteria
- Session cookies remain valid across app restarts in D1-enabled environments.
