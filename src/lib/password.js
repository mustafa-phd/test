/**
 * Password hashing with Argon2id, encoded in the PHC string format.
 *
 * No third-party libraries: the Argon2id implementation is the
 * dependency-free `src/lib/argon2.js`, and random bytes / constant-time
 * comparison come from the Node.js built-in `crypto` module.
 */
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { argon2 } from './argon2.js';

const VERSION = 0x13; // Argon2 v1.3
const TYPE = 2; // Argon2id
const SALT_LENGTH = 16;
const TAG_LENGTH = 32;

/** Argon2 parameters, overridable via environment variables. */
function params() {
  const m = envInt('ARGON2_MEMORY_KIB', 19456, 8); // memory in KiB
  const t = envInt('ARGON2_ITERATIONS', 2, 1);
  const p = envInt('ARGON2_PARALLELISM', 1, 1);
  return { m, t, p };
}

function envInt(name, fallback, min) {
  const value = Number(process.env[name]);
  if (Number.isInteger(value) && value >= min) return value;
  return fallback;
}

function b64encode(bytes) {
  return Buffer.from(bytes).toString('base64').replace(/=+$/, '');
}

function b64decode(str) {
  return Buffer.from(str, 'base64');
}

/**
 * Hash a password, returning a self-describing PHC string:
 *   $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
 */
export function hashPassword(password) {
  const { m, t, p } = params();
  const salt = randomBytes(SALT_LENGTH);
  const hash = argon2({
    password,
    salt,
    m,
    t,
    p,
    tagLen: TAG_LENGTH,
    type: TYPE,
    version: VERSION,
  });
  return `$argon2id$v=${VERSION}$m=${m},t=${t},p=${p}$${b64encode(salt)}$${b64encode(hash)}`;
}

/**
 * Verify a password against a PHC string produced by `hashPassword`.
 */
export function verifyPassword(password, encoded) {
  const parts = String(encoded).split('$');
  // ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
  if (parts.length !== 6 || parts[1] !== 'argon2id') return false;

  const version = Number(parts[2].replace(/^v=/, ''));
  if (version !== VERSION) return false; // only v1.3 is implemented

  const { m, t, p } = parseParams(parts[3]);
  if (m === undefined || t === undefined || p === undefined) return false;

  const salt = b64decode(parts[4]);
  const expected = b64decode(parts[5]);

  const hash = argon2({
    password,
    salt,
    m,
    t,
    p,
    tagLen: expected.length,
    type: TYPE,
    version,
  });

  if (hash.length !== expected.length) return false;
  return timingSafeEqual(hash, expected);
}

function parseParams(str) {
  const result = {};
  for (const item of str.split(',')) {
    const [key, value] = item.split('=');
    if (key === undefined || value === undefined) continue;
    const n = Number(value);
    if (Number.isInteger(n) && n > 0) result[key] = n;
  }
  return result;
}
