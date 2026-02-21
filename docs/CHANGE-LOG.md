# Change Log

## 2026-02-20
### Completed
- Removed upload modal and moved upload to inline Send Fax form.
- Added send-time upload behavior (files upload when Send is clicked).
- Added multi-recipient fax queueing in backend (`to_numbers`) with per-recipient results.
- Added Address Book picker button beside recipient field.
- Added frequent-contact tracking in contact records (`usage_count`, `last_used_at`).
- Added API endpoint for top frequent contacts and frontend quick chips.
- Added contact storage cap enforcement (3000) for manual create and CSV import.
- Added admin settings gear toggle flow in session area.
- Moved settings access to floating bottom-left gear button.
- Reworked Address Book to popup selector with search, top-5, and OK confirm action.
- Added contact-name autocomplete in Send Fax workflow.
- Added frontend validation for empty recipient and invalid E.164 format.
- Moved primary Send Fax button directly below Address Book button.
- Moved contact create/import/manage UI into Address Book modal and removed standalone section.
- Moved Bulk Fax By Tags into Address Book modal as a dedicated tab.
- Changed Send Fax workflow to PDF/TIFF file attachments only (no user-entered media URL field).
- Added recipient auto-normalization: `7145580642` now sends as `+17145580642`.
- Added recipient display formatting in send field/chips (US format `714-558-0642`).
- Added automatic comma insertion after a complete recipient number for faster multi-recipient entry.
- Hardened send flow to upload the files currently selected in the file picker at click time.
- Added selected-files queue UI with remove (`x`) controls and running size/count summary.
- Added send attachment guards: max 5 files, allowed type checks, per-file and total-size validation.
- Added send confirmation modal showing queued/failed counts, fax IDs, and history-record verification count.
- Centered and polished login page with fax-machine branding.
- Aligned backend `/api/uploads/batch` max file count with UX requirement (5 files).
- Replaced silent media URL filtering in `/api/faxes` with explicit invalid-URL errors.
- Redesigned dashboard CSS with improved typography/colors/layout.
- Updated README and PRD to reflect new workflow.
- Added user-store normalization/migration guard so legacy user JSON layouts continue to work.
- Added legacy password compatibility path (auto-upgrade to bcrypt hash on successful login).
- Hardened admin settings access checks for non-admin sessions.
- Added Telnyx fetch timeout (`TELNYX_HTTP_TIMEOUT_MS`, default 5000ms) to prevent `/api/faxes` hangs.
- Updated `/api/faxes` to return local+archive merged history with non-blocking `sync_warning`.
- Added Render runtime diagnostics in `/api/health` and startup warnings for non-persistent data dir.
- Added Render startup warning about free-tier sleep impact on inbound webhook reliability.
- Added optional Cloudflare D1-backed user persistence (`CLOUDFLARE_*` env support).
- Added D1 startup bootstrap: users table creation, local-user sync, and admin-user ensure.
- Updated auth/user routes to use async store wrappers that target D1 when enabled.
- Added `/api/health` flag `d1_users_enabled` for deployment verification.
- Added D1 app-store snapshot persistence for `config`, `contacts`, `faxes`, `faxes_archive`, and `bulk_jobs`.
- Added startup hydration/seed logic for app stores (D1 <-> local JSON sync).
- Added `/api/health` flag `d1_app_stores_enabled` for app-store persistence verification.

### Files Changed
- `/Users/alex/Documents/Projects/Telnyx/server.js`
- `/Users/alex/Documents/Projects/Telnyx/public/index.html`
- `/Users/alex/Documents/Projects/Telnyx/public/app.js`
- `/Users/alex/Documents/Projects/Telnyx/public/styles.css`
- `/Users/alex/Documents/Projects/Telnyx/README.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/PRD-fax-app-enhancements.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/KNOWLEDGE-BASE.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/KNOWLEDGE-SEND-RELIABILITY.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/TASK-LIST.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/CHANGE-LOG.md`
- `/Users/alex/Documents/Projects/Telnyx/AGENTS.md`
- `/Users/alex/Documents/Projects/Telnyx/docs/TASK-LIST.md`

### Handoff Notes
- Primary workflow now expects users to select files inline and click Send once.
- Backend supports up to 100 recipients per send request.
- Backend upload batch limit is now 5 files per send request.
- Frequent-contact chips depend on successful queue events.
- Recipient selection now supports manual numbers, autocomplete, and popup selection.
- Telnyx media URLs must be public HTTPS. Localhost file URLs are not fetchable by Telnyx.
