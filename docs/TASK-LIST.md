# Ongoing Task List

## Current Sprint
- [x] Remove upload popup and convert to inline upload on send form.
- [x] Add multi-recipient send support.
- [x] Add address book picker near recipient field.
- [x] Add top 5 frequent contact quick chips.
- [x] Enforce 3000 contact cap.
- [x] Add admin settings gear access pattern.
- [x] Improve dashboard/UI styling.
- [x] Move settings control to floating bottom-left gear.
- [x] Convert address book picker to popup with search + top-5 + OK.
- [x] Add contact-name autocomplete in Send Fax form.
- [x] Add explicit frontend errors for no recipient and invalid phone format.
- [x] Place main Send Fax button below Address Book button.
- [x] Move contact create/import/manage controls into Address Book modal.
- [x] Move Bulk Fax By Tags into Address Book modal as tab.
- [x] Update PRD and continuity docs.
- [x] Auto-normalize recipient phone input (10-digit US -> +1 E.164) and format display.
- [x] Auto-append comma separator after a complete recipient number entry.
- [x] Ensure selected files at submit time are uploaded before fax API call.
- [x] Add selected-file queue UI with per-file remove (`x`) control.
- [x] Enforce send attachment constraints (max 5 files, type checks, and size checks).
- [x] Add send confirmation popup with queue details and history-record verification count.
- [x] Center and polish login view with fax-machine branding.
- [x] Align backend batch upload limit to 5 files.
- [x] Replace silent media URL filtering with explicit backend validation errors.
- [x] Refresh PRD + knowledge documents with reliability specs and known gaps.
- [x] Harden admin-only settings access path (UI + API enforcement check).
- [x] Harden user store compatibility/migration for legacy schemas.
- [x] Add Telnyx request timeout to prevent fax-history hangs.
- [x] Merge active and archive stores for latest-50 history rendering.
- [x] Add Render data-path diagnostics and persistent-disk warning logs.

## Next Tasks
- [ ] Add automated tests for `/api/faxes` multi-recipient success/failure mixes.
- [ ] Add tests for contact cap during CSV import.
- [ ] Add localhost runtime banner explaining Telnyx public-HTTPS media requirement.
- [ ] Add per-user timezone setting for cover page timestamps.
- [ ] Add pagination for address book list when contact count approaches 3000.
- [ ] Add Render deployment guide with exact persistent disk + no-sleep plan checklist screenshots.
