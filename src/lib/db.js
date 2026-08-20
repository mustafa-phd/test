/**
 * LibSQL database client + schema setup.
 *
 * The connection is configured through environment variables:
 *   DATABASE_URL        e.g. "file:data.db" (default) or a Turso URL
 *   DATABASE_AUTH_TOKEN optional auth token for a remote Turso database
 */
import { createClient } from '@libsql/client';

const url = process.env.DATABASE_URL || 'file:data.db';
const authToken = process.env.DATABASE_AUTH_TOKEN;

export const db = createClient(
  authToken ? { url, authToken } : { url },
);

let initPromise;

/**
 * Create the schema once. Safe to call on every request: the work is
 * memoised in a single promise so the tables are only created the first time.
 */
export function ensureDb() {
  if (!initPromise) {
    initPromise = initDb().catch((error) => {
      initPromise = undefined;
      throw error;
    });
  }
  return initPromise;
}

async function initDb() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      email         TEXT    NOT NULL UNIQUE,
      password_hash TEXT    NOT NULL,
      created_at    INTEGER NOT NULL
    )
  `);

  await db.execute(`
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT    PRIMARY KEY,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    )
  `);
}
