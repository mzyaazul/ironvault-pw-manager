# IronVault — a zero-knowledge password vault

A password manager where the server (Supabase) never sees a plaintext
password from users. Encryption happens entirely
in the browser with the native Web Crypto API before anything reaches the
database.

**[Live demo →](#)** *(GitHub Pages / Netlify / Vercel URL)*

## Skills this project demonstrates

- **Applied cryptography** — correct use of PBKDF2 key derivation and
  AES-GCM authenticated encryption via the browser's native `SubtleCrypto`
  API, not a third-party crypto library.
- **Security-first architecture** — a deliberate separation between
  *authentication* (Supabase Auth) and *encryption*
  (a master password only the user knows which proves that only user can read the data). The
  backend is designed to be untrustworthy by default and still safe.
- **Database design with access control** — Postgres schema with Row
  Level Security policies enforced at the database layer, not just checked
  in application code.
- **Product thinking around security UX** — clipboard auto-clear, session
  auto-lock, password strength feedback, and a generator backed by a CSPRNG (the small details that separate a real security tool from a demo).

## How it works

1. **Sign in.** A Supabase account (email/password) identifies the user and lets the app fetch user's row from the database. 
2. **Set a master password.** A random 16-byte salt is generated once per
   vault. The master password + salt are run through **PBKDF2-SHA256 with
   200,000 iterations** to derive a 256-bit key. The master password is
   used once, in memory, and never stored or transmitted anywhere.
3. **Encrypt.** The vault (all entries) is serialized to JSON and sealed
   with **AES-256-GCM**, which also authenticates the data — tampering or
   a wrong key causes decryption to fail loudly rather than corrupt data
   silently. A fresh random IV is generated on every save.
4. **Store.** Only ciphertext, salt, and IV are written to Postgres. Row
   Level Security restricts every read and write to `auth.uid() = user_id`,
   so no user — and no one browsing the database directly — can reach
   another user's row or make sense of what's inside it.
5. **Unlock.** Re-entering the master password re-derives the same key and
   attempts decryption. Wrong password → decryption fails → access denied.
   There's no separate "check the password" step that could leak timing
   information.
6. **In use.** Copying a password clears the clipboard automatically after
   20 seconds. The vault locks itself after 5 minutes in a background tab.
   The generator draws from `crypto.getRandomValues` — a real CSPRNG, not
   `Math.random`.

## Architecture: Supabase (Postgres + Auth)

- **Auth** — real email/password accounts via `supabase.auth`, kept
  intentionally separate from the vault's master password. Being logged in
  grants access to *a row*, not to *its contents*.
- **Database** — one `vaults` row per user (schema in
  `supabase-setup.sql`), holding only `salt`, `iv`, and ciphertext.
- **Row Level Security** does the real access control — even with the
  public anon key exposed client-side (expected and normal for Supabase),
  the database itself refuses cross-user access.
- **Zero-knowledge held end to end.** Supabase, including anyone with
  dashboard access to the project, only ever stores and serves opaque
  bytes.

## Honest limitations 

- **No brute-force lockout.** Everything client-side means no server can
  rate-limit unlock attempts. The 200,000-iteration PBKDF2 cost is the only
  friction against guessing — a long master password matters more here
  than in a system with a backend-enforced lockout.
- **Not a 1Password/Bitwarden replacement.** This demonstrates the
  cryptographic approach those tools use, without their audits, recovery
  options, or browser extension integrations.
- **Single-writer assumption.** Two tabs unlocked and editing at once will
  have the last save win — there's no conflict resolution.
- **Email-based recovery only goes so far.** Supabase can reset 
  *account* password, but nothing can recover a forgotten *master*
  password — that's the trade-off zero-knowledge design requires.

## Stack

Plain HTML/CSS/JS plus Supabase (Postgres + Auth). No build step, no
`npm install`, no bundler. The only cryptography-critical dependency is
the browser's built-in [`window.crypto.subtle`](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto);
`supabase-js` is loaded from a CDN.

## Setup

1. Create a free project at [supabase.com](https://supabase.com).
2. Run `supabase-setup.sql` in the SQL Editor to create the table and its
   Row Level Security policies.
3. Copy Project URL and anon public key from
   **Project Settings → API**.
4. Paste them into `index.html` at the top of the `<script>` block:
   ```js
   const SUPABASE_URL = 'https://your-project.supabase.co';
   const SUPABASE_ANON_KEY = 'your-anon-key';
   ```
5. Open `index.html` — create an account, then set a master password.

## Running it

```
git clone <this-repo>
cd ledger
open index.html
```

Or drag the folder onto Netlify / GitHub Pages / Vercel for a live link —
it's a static file, so there's nothing to build or deploy beyond that.