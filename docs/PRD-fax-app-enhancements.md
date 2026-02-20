# PRD: Eyecare Fax Office App (Telnyx)

## Version
- Date: 2026-02-20
- Scope: Send reliability, confirmation UX, multi-file handling, login page polish, continuity docs.

## Product Goal
Provide a secure browser-based fax system for Eyecare Care of Orange County with reliable outbound sending, clear confirmation feedback, and admin-controlled settings.

## Office Defaults
- Office name: `Eyecare Care of Orange County`
- Office fax: `+17145580642` (display as `714-558-0642`)
- Office email: `eyecarecenteroc@gmail.com`

## Target Users
- Admin users: configure Telnyx/app settings and users.
- Standard users: send faxes, manage contacts, monitor sent/received history.

## Core User Stories
1. As a user, I can log in from a clean centered login page with clear branding.
2. As a user, I can enter one or multiple recipient numbers quickly, including local 10-digit US format.
3. As a user, I can attach multiple files, see exactly what is queued, and remove any file before sending.
4. As a user, I receive a clear popup confirmation when the fax API confirms queueing.
5. As a user, I can verify confirmation info is visible in Sent History.
6. As an admin, I can manage Telnyx and office defaults securely.

## Functional Requirements

### Authentication and Role Security
- Login required before app usage.
- Role support: `admin`, `user`.
- Settings and user management visible only to admin.

### Send Fax Workflow
- Recipient input accepts:
  - 10-digit US (`7145580642`) -> normalized to E.164 `+17145580642`.
  - 11-digit US starting with `1` -> normalized to E.164.
  - Direct E.164 (`+17145551234`).
- Recipient display format:
  - US numbers shown as `714-558-0642` in field and chips.
- Recipient UX:
  - Multi-recipient via comma/newline.
  - Auto-comma insertion after complete number.
  - Address Book selection and name autocomplete.
- Send pre-checks:
  - At least one valid recipient.
  - At least one attachment.
  - Attachment type must be PDF/TIFF.
  - Maximum attachments per fax send: `5`.
  - Maximum per-file size: `50MB`.
  - Maximum total attachment size: `50MB`.
- Upload/send behavior:
  - Selected files upload on Send click.
  - Send uses exactly currently selected files.
  - If upload result count mismatches selected count, fail with explicit error.

### Confirmation UX
- On successful API queue response, show modal popup with:
  - queued count
  - failed count
  - fax IDs
  - count of records present in local Sent History table
- Keep standard inline status message as secondary feedback.

### Fax History
- Sent/Received tabs remain.
- File links visible in each row.
- Confirmation modal points users to Sent History entries.

### Contacts and Address Book
- Contact CRUD + CSV import.
- Tag support and frequent contacts (top 5).
- Hard cap: `3000` contacts.

### Backend Validation
- `/api/uploads/batch` enforces max 5 files.
- `/api/faxes` validates media URLs as public `https://` links (no silent filtering).
- Errors are explicit and user-readable.

## Non-Functional Requirements
- Clear error messages for blocked send conditions.
- No hidden upload popups before login.
- Mobile-responsive basic layout.
- Maintainable docs for AI/engineer handoff.

## Acceptance Criteria
- Login card is centered and branded.
- Users can add attachments incrementally and remove each with `x`.
- Attachments render in a list below file picker.
- System blocks send if >5 files or size limits exceeded.
- Send success opens confirmation modal and includes fax IDs.
- Sent History shows queued records after successful send.
- Server rejects non-HTTPS media URLs with explicit error.

## Gaps Reviewed and Resolved
- Gap: send failures were not obvious enough.
  - Resolution: confirmation modal + clearer validation messages.
- Gap: multi-file workflow lacked queue visibility/removal UX.
  - Resolution: selected-file list with remove action and size/count validation.
- Gap: backend silently dropped non-HTTPS media URLs.
  - Resolution: explicit backend media URL validation error.
- Gap: frontend/backend file count mismatch (UX wanted 5).
  - Resolution: frontend + backend aligned to 5 files.

## QA Checklist
- [x] `node --check /Users/alex/Documents/Projects/Telnyx/server.js`
- [x] `node --check /Users/alex/Documents/Projects/Telnyx/public/app.js`
- [x] Verify send form attachment list add/remove behavior.
- [x] Verify send confirmation modal opens on successful queue response.
- [x] Verify file count and size errors block sending.

## Remaining Risks
- Telnyx requires publicly reachable HTTPS documents; localhost-hosted files will not be reachable externally.
- End-to-end send verification still depends on real Telnyx credentials/network and destination fax behavior.
