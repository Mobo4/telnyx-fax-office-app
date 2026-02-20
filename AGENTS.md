# Project Agent Rules

These rules apply to future AI/dev updates in this repository.

## Product Rules
- Keep settings behind a floating bottom-left `⚙ Settings` control for admin users only.
- Keep upload as inline workflow in Send Fax (no pre-login popup modal).
- Preserve multi-recipient sending capability.
- Keep Address Book as popup selector opened from the button beside recipient input.
- Keep primary `Send Fax` button directly below the Address Book button.
- Keep contact-name autocomplete on the Send Fax form and auto-add selected contacts.
- Maintain contact cap at 3000 unless explicitly changed by owner.
- Maintain top 5 frequent contact behavior.

## Continuity Rules
- Update these files whenever behavior changes:
  - `/Users/alex/Documents/Projects/Telnyx/docs/PRD-fax-app-enhancements.md`
  - `/Users/alex/Documents/Projects/Telnyx/docs/KNOWLEDGE-BASE.md`
  - `/Users/alex/Documents/Projects/Telnyx/docs/TASK-LIST.md`
  - `/Users/alex/Documents/Projects/Telnyx/docs/CHANGE-LOG.md`
- Keep task checkboxes current and mark completed items.
- Add a change-log entry for each work session.
- Prefer minimal-risk incremental edits and run syntax checks before handoff.

## Coding Rules
- Preserve authentication requirement for `/api/*` routes except explicitly open routes.
- Never expose Telnyx API key client-side.
- Keep frontend and backend field names aligned (`to_numbers`, `media_urls`, cover options).
