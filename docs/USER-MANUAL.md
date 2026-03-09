# Refract Fax User Manual

## 1. What This System Does
Refract Fax is a browser-based fax platform for US fax workflows. It supports:
- Outbound fax sending with PDF/TIFF uploads
- Fax status tracking and retry
- Inbound fax history and webhook ingestion
- Role-based access controls
- Stripe billing and subscription management

## 2. Roles
- `admin`: full access to settings, users, billing, fax controls
- `user` (sender): can send faxes and use address book
- `viewer` (planned): read-only role for history/monitoring workflows

## 3. Login
1. Open `/app`.
2. Enter `Tenant ID` (workspace ID) and credentials.
3. Optional: use Google login when enabled by admin.

## 4. Send Fax (Main Workflow)
1. Go to `Send Fax`.
2. Enter recipient numbers in US format:
- `7145580642`
- `+17145580642`
3. Click `Address Book` to pick contacts (single or multiple).
4. Attach 1-5 PDF/TIFF files.
5. Optional: include cover page and message.
6. Click `Send Fax`.
7. Wait for queue confirmation modal.
8. Click `OK` to reset form for next job.

## 5. Fax History
- `Sent History`: outbound status, failures, retry/poll actions
- `Received History`: inbound fax records
- `Refresh List`: re-fetch latest records

## 6. Retry / Resend
1. In `Sent History`, find failed fax.
2. Use `Retry` to resend to same recipient.
3. System records the retry relation in history.

## 7. Address Book
1. Open `Address Book` from Send Fax area.
2. Add contacts with name, US fax number, tags.
3. Import CSV using provided template.
4. Use search/tags and top frequent contacts.
5. Select contacts and apply to recipient field.

## 8. Bulk Fax by Tags
1. Open `Address Book` -> `Bulk Fax` tab.
2. Provide media URL.
3. Select tags (or send all contacts).
4. Start bulk job.
5. Monitor job queue in bulk jobs table.

## 9. Admin Settings
Admin controls include:
- Telnyx connection/API fields
- Office profile values
- Outbound copy email behavior
- Telnyx fax app limits
- Email gateway controls
- User management
- Billing controls

## 10. Subscription and Billing Policy
- Auto-renew monthly by default
- Cancel within 2 days: eligible for refund + immediate cancellation
- Cancel after 2 days: active until period end, then no renewal
- Renew anytime with same account identity

## 11. US Number Policy
Outbound fax recipients are US-only.
Accepted:
- 10-digit US number
- +1 E.164 US number
Not accepted:
- international numbers

## 12. Security and Compliance Operations
- Do not share admin credentials.
- Use unique user accounts per staff member.
- Keep Google auth and MFA enabled where possible.
- Review audit and history regularly.
- Do not store PHI in unsecured exports.

## 13. Troubleshooting
- `Login required`: session expired; log in again.
- `Tenant mismatch`: wrong tenant ID for current session.
- `Invalid number`: use US 10-digit or +1 format.
- `Upload failed`: check file type/size and retry.
- `Subscription required`: renew plan before sending.
- `Sender not allowed` (email gateway): update allowlist in Email Gateway settings.

## 14. Admin Go-Live Checklist
1. Verify Telnyx API key, connection ID, from number.
2. Verify webhook endpoint and webhook token.
3. Verify Stripe keys and webhook secret.
4. Create at least one backup admin account.
5. Test outbound send, inbound receipt, and retry flow.
6. Validate billing cancel/renew behavior in Stripe.

