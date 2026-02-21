---
name: fax-webhook-signature-guard
description: Implement and validate Telnyx webhook signature verification and timestamp freshness checks.
---

# Fax Webhook Signature Guard

## Scope
- Verify Telnyx webhook signatures using `telnyx-signature-ed25519` and `telnyx-timestamp`.
- Enforce replay-window freshness checks.
- Gate behavior via env toggles.

## Steps
1. Capture raw request body for webhook verification.
2. Add signature validation helper.
3. Enforce verification in webhook route.
4. Add health flags for verification state.
5. Add startup warning when verification is disabled.

## Done Criteria
- Invalid signature requests are rejected when enforcement is enabled.
- Webhook path remains available for valid Telnyx events.
