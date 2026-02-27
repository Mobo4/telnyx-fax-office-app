# PRD: Google Authentication for Shared Tenant Accounts

## Version
- Date: 2026-02-23
- Status: Implemented on `codex/v2-commercial`

## Goal
Allow multiple office staff members to share the same tenant account using their own Google accounts, while preserving existing local username/password login.

## Problem
Current local login requires manual password distribution and rotation. Office teams need easier, safer sign-in where each user authenticates with their own Google account.

## Scope
- Add optional Google OAuth login button on login screen.
- Keep local login fully functional.
- Add provider-aware user management (`local`, `google`).
- Permit admin to create Google users by email (optional custom username).
- Support first-login auto-provisioning of Google users when enabled.
- Allow existing logged-in users to link Google identity to their current account.
- Enforce tenant scoping and role checks exactly as existing auth model.

## Non-Goals
- Full enterprise SAML/OIDC multi-provider SSO.
- SCIM provisioning.
- External identity admin console.

## Functional Requirements
1. Login page shows `Sign In With Google` only when Google auth is enabled.
2. Google sign-in flow uses OAuth Authorization Code with state + nonce checks.
3. Tenant routing is preserved in Google start/callback flow.
4. A Google user is matched by (in order): `google_sub`, then email, then generated username.
5. If no match and auto-create is enabled, create user with configured default role.
6. Admin User Management supports:
- `local` user create (`username + password + role`)
- `google` user create (`google_email + optional username + role`)
7. Google users cannot reset password through local password reset endpoint.
8. Existing admin-only settings access control remains unchanged.
9. Authenticated local users can link Google via explicit link flow and retain username/role.

## Security Requirements
- Keep Telnyx credentials server-side only.
- Enforce login throttling/lockout rules for local login.
- Validate Google token audience/issuer/expiry/email_verified/domain allowlist.
- Use short-lived OAuth state with expiration guard.
- Record auth success/failure events in audit log.

## Configuration Requirements
- `GOOGLE_AUTH_ENABLED`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URI` (optional)
- `GOOGLE_AUTH_AUTO_CREATE_USERS`
- `GOOGLE_AUTH_DEFAULT_ROLE`
- `GOOGLE_AUTH_ALLOWED_DOMAINS` (optional)
- `GOOGLE_OAUTH_STATE_MAX_AGE_MS`

## Acceptance Criteria
- Staff can log in with different Google accounts under same tenant.
- Local users still log in with username/password.
- Non-admin users (local or google) cannot access admin settings/API.
- Admin can create Google users in UI and those users can sign in via Google.
- Google login errors return users to login screen with readable message.
