# MongoDB EJS Authentication and Sessions

A small Express and EJS learning app with MongoDB-backed sessions, bcrypt password hashing, registration, login, a protected dashboard, and logout.

## Requirements

- Node.js 22 or newer
- npm
- A local MongoDB server

## Configure and run

```powershell
Copy-Item .env.example .env
```

Generate a session secret with:

```powershell
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

Put the generated value in `SESSION_SECRET` in `.env`, then start the app:

```powershell
npm ci
npm run dev
```

The app listens on `http://127.0.0.1:1198` by default. It requires both `MONGODB_URI` and a session secret containing at least 32 bytes. Set `NODE_ENV=production` when serving over HTTPS so the session cookie uses the `Secure` attribute. If TLS terminates at a trusted reverse proxy, set `TRUST_PROXY=1` and adjust the proxy trust setting for your deployment.

## Pages

- `/` — landing page
- `/register` — create an account
- `/login` — sign in with a username or email
- `/dashboard` — protected page
- `POST /logout` — end the session
- `/a2rp` — project information

Usernames and email addresses are normalized to lowercase and unique. Passwords are hashed with bcrypt (12 rounds), with an 8-character minimum and bcrypt's 72-byte maximum. Login failures use a generic message, and successful login rotates the session ID. The session cookie is HTTP-only, SameSite Lax, and expires after 8 hours. Login and registration POSTs are rate limited.

## Scope

This is a learning demo, not a production identity system. It binds to localhost by default and has no CSRF token, email verification, password reset, or account recovery. The rate limiter uses in-memory state, so use a shared store and a security review before deploying or handling real accounts.
