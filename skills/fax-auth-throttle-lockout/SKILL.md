---
name: fax-auth-throttle-lockout
description: Add login throttling and temporary lockout controls to reduce brute-force risk.
---

# Fax Auth Throttle Lockout

## Scope
- Track failed login attempts by IP and username.
- Enforce per-IP request throttling.
- Enforce username lockout window after repeated failures.

## Steps
1. Add in-memory attempt trackers.
2. Gate login endpoint with protection checks.
3. Record failures and clear state on success.
4. Expose policy values in health endpoint.

## Done Criteria
- Repeated failures lead to `429` responses and lockout messaging.
