# GitHub Copilot instructions for this repository ⚡️

## Quick summary
- This is a small Node.js single-service app that demonstrates Google OAuth (Passport + PKCE).
- Key files: `google-login-app/server.js` (app entry & UI), `google-login-app/package.json` (run scripts), `google-login-app/README.md` (setup notes).
- No tests or CI configured; there are no existing `.github/*` agent instruction files to merge.

## Architecture & intent 🔧
- Single Express server that renders HTML from `server.js` (no separate frontend build pipeline).
- OAuth flow: uses `passport-google-oauth20` with a PKCE-like state value. PKCE helpers live in `server.js`:
  - `generateCodeVerifier()`, `generateCodeChallenge()`
  - `req.session.pkce = { codeVerifier, codeChallenge }`
  - `passport.authenticate('google', { state: codeChallenge })`
  - callback verifies `req.query.state === req.session.pkce.codeChallenge` and then deletes `req.session.pkce`
- Session handling: `express-session` stores session and Passport serializes the whole `profile` object into session via `serializeUser`/`deserializeUser`.

## Important environment variables & examples 🔐
- Required: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` (otherwise server exits).
- Optional but recommended: `SESSION_SECRET` (defaults to `change-this-in-production`), `PORT` (default 3000).
- Example `.env` (used by `dotenv` in `server.js`):

  GOOGLE_CLIENT_ID=your-google-client-id
  GOOGLE_CLIENT_SECRET=your-google-client-secret
  SESSION_SECRET=your-strong-secret
  PORT=3000

- Windows PowerShell quick run example:
  $env:GOOGLE_CLIENT_ID='xxx'; $env:GOOGLE_CLIENT_SECRET='yyy'; $env:SESSION_SECRET='s3cr3t'; npm start

## How to run & debug ▶️
- Install: `npm install` inside `google-login-app`
- Start: `npm start` (or `npm run dev`) — both run `node server.js` per `package.json`.
- Logs: `server.js` prints helpful startup messages and errors (e.g., missing env, port in use).
- Port conflict resolution (Windows):
  - `netstat -ano | findstr :3000` then `taskkill /PID <PID> /F` if needed.

## Project-specific patterns & conventions ✅
- Single-file server + embedded HTML via template literals in `server.js` — expect quick edits to UI directly in server file.
- Authentication trust model: entire Passport `profile` is stored in session. If expanding, replace with a DB-backed user store and store minimal session ID.
- Error handling: a generic Express error middleware logs and returns `500 Internal Server Error: <message>`.

## Security notes & production cautions ⚠️
- Session cookie currently sets `secure: false` for dev. Change to secure cookies and add HTTPS in production.
- Replace default `SESSION_SECRET` with a secure secret before deploying.
- Persistent user storage and proper session store (Redis, DB) are expected for production readiness.

## Where to add more work (useful hints for agents) 💡
- Add tests and `npm test` -> no tests exist now (`package.json` test is a placeholder).
- Split UI into templates or a small frontend if adding complexity (currently server-rendered HTML in `server.js`).
- Add CI pipeline and a `.github/workflows/*` to run lint/tests.

---

If any part of the code's intent or common workflow is unclear, tell me which area (examples: auth flow, session handling, or run/debug steps) and I'll expand the instructions or add examples. ✅