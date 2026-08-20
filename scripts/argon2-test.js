/**
 * Self-test for the dependency-free Argon2id implementation.
 * Vectors from RFC 9106 §5 and BLAKE2b from RFC 7693.
 * Run: bun scripts/argon2-test.js  (or: node scripts/argon2-test.js)
 */
import { argon2 } from "../src/lib/argon2.js";

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const rep = (byte, n) => new Uint8Array(n).fill(byte);

let failures = 0;
function check(name, actual, expected) {
  const ok = actual === expected;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
  if (!ok) {
    failures++;
    console.log(`       expected: ${expected}`);
    console.log(`       actual:   ${actual}`);
  }
}

// RFC 9106 §5.3 — Argon2id
const idTag = argon2({
  password: rep(0x01, 32),
  salt: rep(0x02, 16),
  secret: rep(0x03, 8),
  ad: rep(0x04, 12),
  m: 32,
  t: 3,
  p: 4,
  tagLen: 32,
  type: 2,
});
check(
  "Argon2id (RFC 9106 §5.3)",
  hex(idTag),
  "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
);

// RFC 9106 §5.1 — Argon2d
const dTag = argon2({
  password: rep(0x01, 32),
  salt: rep(0x02, 16),
  secret: rep(0x03, 8),
  ad: rep(0x04, 12),
  m: 32,
  t: 3,
  p: 4,
  tagLen: 32,
  type: 0,
});
check(
  "Argon2d (RFC 9106 §5.1)",
  hex(dTag),
  "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
);

// RFC 9106 §5.2 — Argon2i
const iTag = argon2({
  password: rep(0x01, 32),
  salt: rep(0x02, 16),
  secret: rep(0x03, 8),
  ad: rep(0x04, 12),
  m: 32,
  t: 3,
  p: 4,
  tagLen: 32,
  type: 1,
});
check(
  "Argon2i (RFC 9106 §5.2)",
  hex(iTag),
  "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
);

if (failures > 0) {
  console.log(`\n${failures} test(s) failed`);
  process.exit(1);
}
console.log("\nAll vectors passed ✔");
