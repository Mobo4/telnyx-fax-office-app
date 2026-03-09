# Deployment Guide: Vercel Marketing + Render Fax App/API

## Goal
Host public marketing/signup pages on Vercel while keeping the authenticated fax app and API on Render.

## Architecture
- Vercel:
  - Serves `/` marketing page and assets from `public/`.
- Render:
  - Serves `/app` authenticated workspace.
  - Serves `/api/*` endpoints and webhook handlers.
  - Keeps data/session/runtime behavior required by current backend design.

## 1) Render Environment (required)
Set these on the Render service:

- `PUBLIC_APP_BASE_URL=https://telnyx-fax-webhook.onrender.com`
- `PUBLIC_MARKETING_BASE_URL=https://<your-vercel-domain>`
- `PUBLIC_SIGNUP_CORS_ORIGINS=https://<your-vercel-domain>,https://www.<your-vercel-domain>`

Notes:
- `PUBLIC_SIGNUP_CORS_ORIGINS` is required for cross-origin `POST /api/public/signup`.
- Keep existing Stripe/Telnyx/Google env variables unchanged.

## 2) Marketing Runtime Config
Edit:
- `/Users/alex/Documents/Projects/Telnyx/public/marketing.config.js`

Set:

```js
window.__FAX_MARKETING_CONFIG = {
  apiBaseUrl: "https://telnyx-fax-webhook.onrender.com",
  appBaseUrl: "https://telnyx-fax-webhook.onrender.com"
};
```

## 3) Vercel Project Setup
1. Create a Vercel project from this repo.
2. Set Root Directory to `public`.
3. Build command: none (static).
4. Output directory: `.` (default for static root setup).
5. Deploy.

## 4) Google OAuth (if enabled)
Authorized redirect URI must stay on Render API callback:

- `https://telnyx-fax-webhook.onrender.com/api/auth/google/callback`

Do not set callback to Vercel for the current architecture.

## 5) Smoke Test Checklist
From the Vercel domain:
1. Open home page and verify Sign In links go to Render `/app`.
2. Open signup modal and submit test data.
3. Confirm signup POST returns success or Stripe checkout redirect.
4. Confirm Google signup button redirects to Render `/api/public/signup/google/start`.
5. Confirm login URL points to Render `/app?tenant_id=...`.

## 6) Failure Patterns
- `CORS blocked` on signup:
  - Check `PUBLIC_SIGNUP_CORS_ORIGINS`.
- Redirect back to wrong domain after signup:
  - Check `PUBLIC_APP_BASE_URL` and `PUBLIC_MARKETING_BASE_URL`.
- Google auth error redirect wrong host:
  - Check `PUBLIC_MARKETING_BASE_URL`.

## 7) Why not full Vercel backend now
Current backend depends on:
- long-running Node process,
- local/session file persistence,
- background retry and queue workers.

Those behaviors are not a direct fit for serverless-only runtime without deeper refactor.
