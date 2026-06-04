# Fund Door Backend Setup

This workspace now includes a minimal Node.js backend for the existing Fund Door static pages.

## What was added
- `server.js` — Express server that serves the `HOME` folder and provides auth endpoints.
- `package.json` — dependency manifest for `express`.
- `data/users.json` — local storage for signup users.

## Available API endpoints
- `POST /api/signup` — create a new user account
- `POST /api/login` — authenticate a user
- `POST /api/forgot-password` — request a password reset email (demo response)

## Run locally
1. Install Node.js if not already installed.
2. Open a terminal in the project root.
3. Run:
   ```bash
   npm install
   npm start
   ```
4. Open `http://localhost:3000` in your browser.

## Notes
- The current implementation is a demo backend with file-based storage.
- Passwords are hashed before being saved to `data/users.json`.
- To use the forms, open the site through the server, not via `file://`.
