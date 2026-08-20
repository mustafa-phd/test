/**
 * Request middleware: resolves the session cookie to a user and guards routes.
 *
 * - `context.locals.user` is available to every page (or `null`).
 * - `/dashboard` requires authentication.
 * - `/login` and `/register` redirect to `/dashboard` when already signed in.
 */
import { getUserBySession, SESSION_COOKIE } from './lib/session.js';

export async function onRequest(context, next) {
  const token = context.cookies.get(SESSION_COOKIE)?.value;
  const user = token ? await getUserBySession(token) : null;

  context.locals.user = user;
  context.locals.sessionToken = token ?? null;

  const { pathname } = context.url;

  // Action endpoints (login/logout/register) must stay reachable.
  if (pathname.startsWith('/_actions')) {
    return next();
  }

  // Protected area.
  if (pathname.startsWith('/dashboard')) {
    if (!user) return context.redirect('/login');
    return next();
  }

  // Signed-in users have no business on the auth pages.
  if (user && (pathname === '/login' || pathname === '/register')) {
    return context.redirect('/dashboard');
  }

  return next();
}
