# Knowledge: Send Reliability Notes

## Scope
Focused notes for outbound fax reliability and confirmation UX.

## Current Guarantees
- Frontend validates recipient format before API call.
- Frontend validates attachment count/type/size before upload.
- Upload and send are chained in one submit flow.
- Success triggers a confirmation modal with fax IDs and history record count.
- Backend enforces max upload files and explicit media URL validation.

## Common Failure Modes
- No recipients selected.
- Invalid recipient number token.
- More than 5 attachments.
- Unsupported attachment type.
- Attachment too large or total selected size too large.
- Media URLs not public HTTPS.
- Telnyx API/network failure.

## Operator Playbook
1. Check inline send error.
2. If media URL error appears, verify HTTPS deployment/domain.
3. If Telnyx error appears, verify API key/connection/from number in admin settings.
4. Use Sent History + poll action to track status transitions.
