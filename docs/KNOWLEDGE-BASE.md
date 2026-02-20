# Knowledge Base: Telnyx Fax Office App

## Purpose
Operational reference for architecture, workflow behavior, limits, and known edge cases so another engineer/AI can continue without re-discovery.

## Stack
- Backend: Node.js + Express (`/Users/alex/Documents/Projects/Telnyx/server.js`)
- Frontend: vanilla JS (`/Users/alex/Documents/Projects/Telnyx/public/app.js`)
- UI: static HTML/CSS (`/Users/alex/Documents/Projects/Telnyx/public/index.html`, `/Users/alex/Documents/Projects/Telnyx/public/styles.css`)
- Persistence: JSON files in `/Users/alex/Documents/Projects/Telnyx/data`

## Core Capabilities
- Role-based login (`admin`, `user`).
- Outbound fax send to one or many recipients.
- Sent and Received history tabs with file links.
- Address Book with search, tags, CSV import, frequent contacts.
- Bulk fax by tag filters.
- Optional HIPAA cover page.
- Optional outbound copy email.

## API Surface (primary)
- Auth: `/api/auth/login`, `/api/auth/logout`, `/api/auth/me`
- Send/history: `/api/faxes`, `/api/faxes/:id/refresh`
- Uploads: `/api/uploads/batch`
- Contacts: `/api/contacts`, `/api/contacts/import`, `/api/contacts/tags`, `/api/contacts/frequent`
- Bulk: `/api/faxes/bulk`, `/api/faxes/bulk-jobs`
- Admin: `/api/admin/settings`, `/api/admin/telnyx/fax-application`, `/api/admin/users`

## Send Workflow (current)
1. User fills recipients.
2. User selects up to 5 files (PDF/TIFF).
3. Frontend validates recipients + files.
4. Frontend uploads selected files to `/api/uploads/batch`.
5. Frontend sends `/api/faxes` with `to_numbers` and uploaded `media_urls`.
6. Backend queues one fax per recipient.
7. Frontend reloads history and opens confirmation modal with queue details.

## Recipient Behavior
- Input accepts:
  - `7145580642` (normalized to `+17145580642`)
  - `17145580642` (normalized to `+17145580642`)
  - `+17145580642`
- US numbers display as `714-558-0642`.
- Multiple numbers supported via comma/newline.
- Input auto-adds comma after complete number.

## Attachment Behavior
- Max files per send: `5`.
- Max per-file size: `50MB`.
- Max total selected size: `50MB`.
- Allowed types: `.pdf`, `.tif`, `.tiff`.
- Files are kept in client-side queue list with remove (`x`) controls.
- Send uses the current queue, not stale selections.

## Backend Validation Notes
- `/api/uploads/batch` enforces max files and per-file limit.
- `/api/faxes` now rejects invalid/non-HTTPS media URLs explicitly.
- No silent media URL dropping.

## Data Files
- `/Users/alex/Documents/Projects/Telnyx/data/faxes.json`
- `/Users/alex/Documents/Projects/Telnyx/data/contacts.json`
- `/Users/alex/Documents/Projects/Telnyx/data/bulk_jobs.json`
- `/Users/alex/Documents/Projects/Telnyx/data/config.json`
- `/Users/alex/Documents/Projects/Telnyx/data/users.json`

## Known Environment Caveat
- Telnyx must fetch documents from public HTTPS URLs.
- If app is run on `http://localhost`, uploaded document URLs are not publicly reachable by Telnyx.
- Recommended runtime: Render deployment using HTTPS domain.

## Gaps / Next Hardening
- Add automated integration tests for send success/failure paths.
- Add explicit banner when app is running on localhost warning about public URL reachability.
- Add retry controls for failed recipients from results payload.
