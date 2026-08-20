/**
 * Cookie-backed sessions stored in LibSQL.
 *
 * The browser only ever sees a random 256-bit token; the database stores its
 * SHA-256 digest so a leaked database file does not expose live sessions.
 */
import { createHash, randomBytes } from 'node:crypto';
import { db, ensureDb } from './db.js';

export const SESSION_COOKIE = 'session';
export const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

/**
 * Create a session for `userId` and return the raw token to store in a cookie.
 */
export async function createSession(userId) {
  await ensureDb();
  const token = randomBytes(32).toString('hex');
  const createdAt = nowSeconds();
  const expiresAt = createdAt + SESSION_TTL_SECONDS;

  await db.execute({
    sql: 'INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)',
    args: [hashToken(token), userId, createdAt, expiresAt],
  });

  return token;
}

/**
 * Resolve a session token to its user, or `null` if missing/expired/unknown.
 */
export async function getUserBySession(token) {
  if (!token) return null;
  await ensureDb();

  const result = await db.execute({
    sql: `SELECT u.id, u.email, u.created_at
          FROM sessions s
          JOIN users u ON u.id = s.user_id
          WHERE s.token_hash = ? AND s.expires_at > ?`,
    args: [hashToken(token), nowSeconds()],
  });

  const row = result.rows[0];
  if (!row) return null;

  return { id: row.id, email: row.email, createdAt: row.created_at };
}

/**
 * Delete a session by its raw token.
 */
export async function deleteSession(token) {
  if (!token) return;
  await ensureDb();
  await db.execute({
    sql: 'DELETE FROM sessions WHERE token_hash = ?',
    args: [hashToken(token)],
  });
}
