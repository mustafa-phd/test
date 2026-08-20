# Astro Auth Template

A minimal authentication template with **no UI framework and no styling** —
just the logic and the pages: home, register, login, dashboard, and logout.

## Stack

- **Astro** (SSR, no UI framework) — uses Astro Actions, middleware, cookies,
  and redirects.
- **Bun** as the package manager and runtime.
- **JavaScript** only (no TypeScript).
- **LibSQL** for storage (users + sessions).
- **Argon2id** for password hashing, implemented from scratch in pure
  JavaScript (`src/lib/argon2.js`) with no third-party crypto dependency.

No other libraries are used beyond Astro, the Node adapter, and the LibSQL
client.

## Getting started

```sh
bun install
bun run dev
```

Open http://localhost:4321.

The database is created automatically on first use at `data.db` (a local
SQLite file via LibSQL).

## Environment

Copy `.env.example` to `.env` to override defaults:

| Variable               | Default        | Description                                  |
| ---------------------- | -------------- | -------------------------------------------- |
| `DATABASE_URL`         | `file:data.db` | LibSQL URL (local file or remote Turso URL). |
| `DATABASE_AUTH_TOKEN`  | —              | Auth token for a remote Turso database.      |
| `ARGON2_MEMORY_KIB`    | `19456`        | Argon2id memory cost in KiB.                 |
| `ARGON2_ITERATIONS`    | `2`            | Argon2id time cost.                          |
| `ARGON2_PARALLELISM`   | `1`            | Argon2id parallelism.                        |

## Build & run (production)

```sh
bun run build
bun run start
```

## How it works

- `src/lib/argon2.js` — dependency-free Argon2id (verified against the
  RFC 9106 §5 test vectors; run `bun scripts/argon2-test.js`).
- `src/lib/password.js` — Argon2id hashing/verification in PHC format.
- `src/lib/db.js` — LibSQL client and schema.
- `src/lib/session.js` — cookie sessions (raw token in the cookie, its
  SHA-256 digest in the database).
- `src/actions/index.js` — `register`, `login`, `logout` form actions.
- `src/middleware.js` — session resolution and route protection.
- `src/pages/` — the five pages.
