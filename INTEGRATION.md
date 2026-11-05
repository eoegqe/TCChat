# TC Chat integration

TC Chat is an Eggser-scoped messaging client and Cloudflare Worker API. It uses TC Accounts for identity and the existing TC D1 database for account records and chat data.

## Current behavior

- TC Accounts OAuth 2.0 authorization-code sign-in with PKCE.
- Direct messages and group conversations.
- User discovery limited to active Eggser-linked TC accounts.
- Every participant is checked for active Eggser membership when a conversation is created.
- Messages are plain text and limited to 4,000 characters.
- Users can block other Eggser users.
- The web client polls for new messages and conversation updates.
- No user-created public channels or general TC-wide directory.

## Required setup

### 1. Register TC Chat in TC Accounts

Create an OAuth application in TC Accounts with:

- Application name: TC Chat
- Redirect URI: `https://chat.theegget.com/auth/callback`
- Allowed scope: `profile`
- OAuth flow: authorization code with PKCE (S256)

Set the returned client ID as `VITE_TC_OAUTH_CLIENT_ID` during the Vite build. For local builds, create a `.env.local` file using `.env.example` as the template.

### 2. Apply the database migration

The Worker is configured to use the existing TC D1 database. Do not create a second account database.

Run:

```sh
npm install
npm run db:migrate:remote
```

The migration creates the Eggser membership mapping, conversations, participants, messages, and block tables. It does not modify the existing TC Accounts tables.

### 3. Configure the Eggser membership sync

TC Accounts currently returns the TC user ID and username from its OAuth userinfo endpoint; it does not currently return linked sub-account tags. TC Chat therefore fails closed until the authoritative Eggser sub-account system syncs membership records.

Set a long random secret on the TC Chat Worker:

```sh
npx wrangler secret put EGGSER_SYNC_SECRET
```

When an Eggser sub-account is linked or unlinked, the trusted Eggser/TC server must call:

```http
POST https://chat.theegget.com/internal/services/eggser/membership
Content-Type: application/json
x-tc-sync-secret: <shared-secret>

{
  "user_id": "<TC Accounts user ID>",
  "active": true
}
```

Send `active: false` when the Eggser sub-account is unlinked, disabled, or otherwise no longer eligible. This endpoint is server-to-server only; never expose the sync secret in browser code.

The membership source must be the authoritative linked-sub-account record, not a username supplied by the client. Until that source is connected, users without a synced membership will receive an Eggser sub-account eligibility message and cannot enter the messaging API.

### 4. Build and deploy

Set `VITE_TC_OAUTH_CLIENT_ID` in the build environment, then run:

```sh
npm run build
npx wrangler deploy
```

Configure the Cloudflare custom domain `chat.theegget.com` for the Worker after deployment.

## Local development

For UI-only work:

```sh
npm install
npm run dev
```

The Vite server does not run the Worker API. To test the full application, build the assets and run the Worker with Wrangler using a development D1 environment and the required local secrets.

## API overview

- `GET /api/me` — authenticated TC identity and Eggser eligibility.
- `GET /api/directory?q=<username>` — eligible Eggser user search.
- `GET /api/conversations` — current user's conversations.
- `POST /api/conversations` — create a direct or group conversation.
- `GET /api/conversations/:id/messages` — read conversation messages.
- `POST /api/conversations/:id/messages` — send a message.
- `POST /api/users/:id/block` — block an Eggser user.
- `DELETE /api/users/:id/block` — remove a block.
- `POST /internal/services/eggser/membership` — trusted membership synchronization.

All `/api/*` requests require a valid TC Accounts OAuth access token in the Authorization header.
