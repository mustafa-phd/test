/**
 * Server actions for the auth flows.
 *
 * `register`, `login` and `logout` are form actions called from the browser
 * with `actions.<name>(formData)` (see the page `<script>` blocks). They run
 * on the server and may set cookies, which are attached to the response.
 */
import { defineAction, ActionError } from 'astro:actions';
import { z } from 'astro/zod';
import { hashPassword, verifyPassword } from '../lib/password.js';
import {
  createSession,
  deleteSession,
  SESSION_COOKIE,
  SESSION_TTL_SECONDS,
} from '../lib/session.js';
import { db, ensureDb } from '../lib/db.js';

const emailSchema = z.string().trim().toLowerCase().email();
const passwordSchema = z.string().min(8).max(1024);

export const server = {
  register: defineAction({
    accept: 'form',
    input: z.object({
      email: emailSchema,
      password: passwordSchema,
    }),
    handler: async ({ email, password }, context) => {
      await ensureDb();

      const passwordHash = hashPassword(password);
      const now = Math.floor(Date.now() / 1000);

      try {
        const result = await db.execute({
          sql: 'INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)',
          args: [email, passwordHash, now],
        });
        const token = await createSession(Number(result.lastInsertRowid));
        setSessionCookie(context, token);
        return { redirectTo: '/dashboard' };
      } catch (error) {
        if (isUniqueViolation(error)) {
          throw new ActionError({
            code: 'CONFLICT',
            message: 'An account with that email already exists.',
          });
        }
        throw error;
      }
    },
  }),

  login: defineAction({
    accept: 'form',
    input: z.object({
      email: emailSchema,
      password: z.string().min(1).max(1024),
    }),
    handler: async ({ email, password }, context) => {
      await ensureDb();

      const result = await db.execute({
        sql: 'SELECT id, email, password_hash FROM users WHERE email = ?',
        args: [email],
      });
      const row = result.rows[0];

      const valid = row
        ? verifyPassword(password, row.password_hash)
        : false;

      if (!valid) {
        throw new ActionError({
          code: 'UNAUTHORIZED',
          message: 'Invalid email or password.',
        });
      }

      const token = await createSession(Number(row.id));
      setSessionCookie(context, token);
      return { redirectTo: '/dashboard' };
    },
  }),

  logout: defineAction({
    accept: 'form',
    handler: async (_input, context) => {
      const token = context.cookies.get(SESSION_COOKIE)?.value;
      if (token) await deleteSession(token);
      context.cookies.delete(SESSION_COOKIE, { path: '/' });
      return { redirectTo: '/' };
    },
  }),
};

function setSessionCookie(context, token) {
  context.cookies.set(SESSION_COOKIE, token, {
    path: '/',
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: SESSION_TTL_SECONDS,
  });
}

function isUniqueViolation(error) {
  const message = error && typeof error.message === 'string'
    ? error.message.toLowerCase()
    : '';
  return (
    message.includes('unique') ||
    message.includes('constraint') ||
    message.includes('already exists')
  );
}
