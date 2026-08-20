/**
 * Pure-JavaScript Argon2 (Argon2d / Argon2i / Argon2id) + BLAKE2b.
 *
 * Zero third-party dependencies: built entirely on top of JavaScript
 * numbers (64-bit arithmetic is done with two 32-bit limbs) and the
 * Node.js built-in `crypto` module (used only for secure random bytes
 * and constant-time comparison helpers elsewhere in the app).
 *
 * References:
 *   - RFC 9106  (Argon2)          https://www.rfc-editor.org/rfc/rfc9106
 *   - RFC 7693  (BLAKE2b)         https://www.rfc-editor.org/rfc/rfc7693
 *   - P-H-C/phc-winner-argon2 reference implementation (CC0 / Apache-2.0)
 *
 * Verified against the RFC 9106 §5 test vectors (see scripts/argon2-test.js).
 */

// ---------------------------------------------------------------------------
// BLAKE2b constants
// ---------------------------------------------------------------------------

// IV: 8 x 64-bit words, stored as [lo, hi] (each part is an unsigned 32-bit).
const IV = [
  [0xf3bcc908, 0x6a09e667],
  [0x84caa73b, 0xbb67ae85],
  [0xfe94f82b, 0x3c6ef372],
  [0x5f1d36f1, 0xa54ff53a],
  [0xade682d1, 0x510e527f],
  [0x2b3e6c1f, 0x9b05688c],
  [0xfb41bd6b, 0x1f83d9ab],
  [0x137e2179, 0x5be0cd19],
];

// SIGMA message schedule (10 rounds; rounds 10 & 11 reuse 0 & 1).
const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

// ---------------------------------------------------------------------------
// 64-bit helpers (words are [lo, hi] unsigned 32-bit pairs)
// ---------------------------------------------------------------------------

/** 64-bit product of two unsigned 32-bit integers → [lo, hi]. */
function mul32(a, b) {
  const al = a & 0xffff;
  const ah = a >>> 16;
  const bl = b & 0xffff;
  const bh = b >>> 16;
  const ab = al * bl; // < 2^32
  const cross = al * bh + ah * bl; // < 2^33
  const abHi = ab >>> 16; // < 2^16
  const lo = ((ab & 0xffff) + ((abHi + cross) % 65536) * 65536) >>> 0;
  const hi = (ah * bh + Math.floor((abHi + cross) / 65536)) >>> 0;
  return [lo, hi];
}

/** a + b (mod 2^64) → [lo, hi]. */
function add64(aLo, aHi, bLo, bHi) {
  let lo = aLo + bLo;
  const carry = lo >= 0x100000000 ? 1 : 0;
  lo = lo >>> 0;
  const hi = (aHi + bHi + carry) >>> 0;
  return [lo, hi];
}

/** a XOR b → [lo, hi]. */
function xor64(aLo, aHi, bLo, bHi) {
  return [(aLo ^ bLo) >>> 0, (aHi ^ bHi) >>> 0];
}

/** Rotate 64-bit word right by n (0..63) → [lo, hi] (always unsigned). */
function rotr64(lo, hi, n) {
  if (n === 0) return [lo >>> 0, hi >>> 0];
  if (n === 32) return [hi >>> 0, lo >>> 0];
  if (n < 32) {
    return [
      ((lo >>> n) | (hi << (32 - n))) >>> 0,
      ((hi >>> n) | (lo << (32 - n))) >>> 0,
    ];
  }
  return rotr64(hi, lo, n - 32);
}

// ---------------------------------------------------------------------------
// BLAKE2b (RFC 7693), unkeyed, variable digest length (1..64)
// ---------------------------------------------------------------------------

/** BLAKE2b compression function F. h and m are Uint32Array(16) word arrays. */
function blake2bCompress(h, m, tLo, tHi, last) {
  const v = new Uint32Array(32);
  for (let i = 0; i < 8; i++) {
    v[2 * i] = h[2 * i];
    v[2 * i + 1] = h[2 * i + 1];
    v[16 + 2 * i] = IV[i][0];
    v[16 + 2 * i + 1] = IV[i][1];
  }
  v[24] = (v[24] ^ tLo) >>> 0; // v[12] ^= t (low)
  v[25] = (v[25] ^ tHi) >>> 0; // v[12] ^= t (high)
  if (last) {
    v[28] = (v[28] ^ 0xffffffff) >>> 0; // v[14] inverted
    v[29] = (v[29] ^ 0xffffffff) >>> 0;
  }

  for (let round = 0; round < 12; round++) {
    const s = SIGMA[round % 10];
    blake2bG(v, 0, 4, 8, 12, m, s[0], s[1]);
    blake2bG(v, 1, 5, 9, 13, m, s[2], s[3]);
    blake2bG(v, 2, 6, 10, 14, m, s[4], s[5]);
    blake2bG(v, 3, 7, 11, 15, m, s[6], s[7]);
    blake2bG(v, 0, 5, 10, 15, m, s[8], s[9]);
    blake2bG(v, 1, 6, 11, 12, m, s[10], s[11]);
    blake2bG(v, 2, 7, 8, 13, m, s[12], s[13]);
    blake2bG(v, 3, 4, 9, 14, m, s[14], s[15]);
  }

  const out = new Uint32Array(16);
  for (let i = 0; i < 8; i++) {
    out[2 * i] = (h[2 * i] ^ v[2 * i] ^ v[16 + 2 * i]) >>> 0;
    out[2 * i + 1] = (h[2 * i + 1] ^ v[2 * i + 1] ^ v[16 + 2 * i + 1]) >>> 0;
  }
  return out;
}

/** BLAKE2b mixing function G (RFC 7693 §3.1). */
function blake2bG(v, a, b, c, d, m, xi, yi) {
  const xLo = m[2 * xi];
  const xHi = m[2 * xi + 1];
  const yLo = m[2 * yi];
  const yHi = m[2 * yi + 1];

  // v[a] = v[a] + v[b] + x
  let t = add64(v[2 * a], v[2 * a + 1], v[2 * b], v[2 * b + 1]);
  t = add64(t[0], t[1], xLo, xHi);
  v[2 * a] = t[0];
  v[2 * a + 1] = t[1];

  // v[d] = (v[d] ^ v[a]) >>> 32
  t = xor64(v[2 * d], v[2 * d + 1], v[2 * a], v[2 * a + 1]);
  t = rotr64(t[0], t[1], 32);
  v[2 * d] = t[0];
  v[2 * d + 1] = t[1];

  // v[c] = v[c] + v[d]
  t = add64(v[2 * c], v[2 * c + 1], v[2 * d], v[2 * d + 1]);
  v[2 * c] = t[0];
  v[2 * c + 1] = t[1];

  // v[b] = (v[b] ^ v[c]) >>> 24
  t = xor64(v[2 * b], v[2 * b + 1], v[2 * c], v[2 * c + 1]);
  t = rotr64(t[0], t[1], 24);
  v[2 * b] = t[0];
  v[2 * b + 1] = t[1];

  // v[a] = v[a] + v[b] + y
  t = add64(v[2 * a], v[2 * a + 1], v[2 * b], v[2 * b + 1]);
  t = add64(t[0], t[1], yLo, yHi);
  v[2 * a] = t[0];
  v[2 * a + 1] = t[1];

  // v[d] = (v[d] ^ v[a]) >>> 16
  t = xor64(v[2 * d], v[2 * d + 1], v[2 * a], v[2 * a + 1]);
  t = rotr64(t[0], t[1], 16);
  v[2 * d] = t[0];
  v[2 * d + 1] = t[1];

  // v[c] = v[c] + v[d]
  t = add64(v[2 * c], v[2 * c + 1], v[2 * d], v[2 * d + 1]);
  v[2 * c] = t[0];
  v[2 * c + 1] = t[1];

  // v[b] = (v[b] ^ v[c]) >>> 63
  t = xor64(v[2 * b], v[2 * b + 1], v[2 * c], v[2 * c + 1]);
  t = rotr64(t[0], t[1], 63);
  v[2 * b] = t[0];
  v[2 * b + 1] = t[1];
}

/** Read a message (Uint8Array) into little-endian 64-bit words (Uint32Array). */
function bytesToWordsLE(bytes) {
  const words = new Uint32Array(2 * Math.ceil(bytes.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    words[i >> 2] |= bytes[i] << (8 * (i & 3));
  }
  return words;
}

/** BLAKE2b digest of `msg` with output length `outlen` bytes (1..64). */
function blake2b(outlen, msg, key = new Uint8Array(0)) {
  const kk = key.length;
  const h = new Uint32Array(16);
  for (let i = 0; i < 8; i++) {
    h[2 * i] = IV[i][0];
    h[2 * i + 1] = IV[i][1];
  }
  // Parameter block: h[0] ^= 0x01010000 ^ (kk << 8) ^ nn
  h[0] = (h[0] ^ ((0x01010000 | (kk << 8) | outlen) >>> 0)) >>> 0;

  const fullLen = kk + msg.length;
  const emptyZeroBlock = fullLen === 0;

  if (emptyZeroBlock) {
    const m = new Uint32Array(32); // 16 zero words
    const nh = blake2bCompress(h, m, 0, 0, true);
    return wordsToBytesLE(nh, outlen);
  }

  const nb = Math.ceil(fullLen / 128);
  for (let bi = 0; bi < nb; bi++) {
    const start = bi * 128;
    const end = Math.min(start + 128, fullLen);
    const m = new Uint32Array(32);
    for (let j = start; j < end; j++) {
      const byte = j < kk ? key[j] : msg[j - kk];
      const off = j - start;
      m[off >> 2] |= byte << (8 * (off & 3));
    }
    const last = bi === nb - 1;
    const t = last ? fullLen : (bi + 1) * 128;
    const nh = blake2bCompress(h, m, t >>> 0, Math.floor(t / 0x100000000), last);
    h.set(nh);
  }
  return wordsToBytesLE(h, outlen);
}

/** Convert 64-bit little-endian words (Uint32Array) to bytes. */
function wordsToBytesLE(words, outlen) {
  const out = new Uint8Array(outlen);
  for (let i = 0; i < outlen; i++) {
    const w = i >> 3;
    const b = i & 7;
    out[i] = (b < 4 ? words[2 * w] >>> (8 * b) : words[2 * w + 1] >>> (8 * (b - 4))) & 0xff;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Argon2 variable-length hash H' (RFC 9106 §3.3)
// ---------------------------------------------------------------------------

function blake2bLong(outlen, msg) {
  if (outlen <= 64) {
    const prefix = new Uint8Array(4);
    writeU32LE(prefix, 0, outlen);
    return blake2b(outlen, concatBytes(prefix, msg));
  }
  const out = new Uint8Array(outlen);
  const prefix = new Uint8Array(4);
  writeU32LE(prefix, 0, outlen);

  // V_1 = H^64(LE32(T) || A)
  let v = blake2b(64, concatBytes(prefix, msg));

  // W_1 = first 32 bytes of V_1
  let off = 0;
  out.set(v.subarray(0, 32), off);
  off += 32;

  let toproduce = outlen - 32;
  while (toproduce > 64) {
    v = blake2b(64, v); // V_{i+1} = H^64(V_i)
    out.set(v.subarray(0, 32), off); // W_{i+1} = first 32 bytes
    off += 32;
    toproduce -= 32;
  }

  // V_last = H^{toproduce}(V_prev)
  const last = blake2b(toproduce, v);
  out.set(last, off);
  return out;
}

// ---------------------------------------------------------------------------
// Argon2 core (RFC 9106)
// ---------------------------------------------------------------------------

// Scratch buffers reused across the memory fill (single-threaded).
const scratch = new Uint32Array(256); // 1024-byte block as 128 x [lo, hi]
const scratchP = new Uint32Array(32); // 16 words for column permutation

/** Argon2 GB mix (BLAKE2_ROUND_NOMSG) — Figure 18/19 of RFC 9106. */
function gb(v, a, b, c, d) {
  let aLo = v[2 * a];
  let aHi = v[2 * a + 1];
  let bLo = v[2 * b];
  let bHi = v[2 * b + 1];
  let cLo = v[2 * c];
  let cHi = v[2 * c + 1];
  let dLo = v[2 * d];
  let dHi = v[2 * d + 1];

  // a = a + b + 2 * trunc(a) * trunc(b)
  {
    const m = mul32(aLo, bLo);
    let t = add64(aLo, aHi, bLo, bHi);
    // double m
    const m2Lo = (m[0] << 1) >>> 0;
    const m2Hi = ((m[1] << 1) | (m[0] >>> 31)) >>> 0;
    t = add64(t[0], t[1], m2Lo, m2Hi);
    aLo = t[0];
    aHi = t[1];
  }
  // d = (d ^ a) >>> 32
  {
    const t = rotr64(dLo ^ aLo, dHi ^ aHi, 32);
    dLo = t[0];
    dHi = t[1];
  }
  // c = c + d + 2 * trunc(c) * trunc(d)
  {
    const m = mul32(cLo, dLo);
    let t = add64(cLo, cHi, dLo, dHi);
    const m2Lo = (m[0] << 1) >>> 0;
    const m2Hi = ((m[1] << 1) | (m[0] >>> 31)) >>> 0;
    t = add64(t[0], t[1], m2Lo, m2Hi);
    cLo = t[0];
    cHi = t[1];
  }
  // b = (b ^ c) >>> 24
  {
    const t = rotr64(bLo ^ cLo, bHi ^ cHi, 24);
    bLo = t[0];
    bHi = t[1];
  }

  // a = a + b + 2 * trunc(a) * trunc(b)
  {
    const m = mul32(aLo, bLo);
    let t = add64(aLo, aHi, bLo, bHi);
    const m2Lo = (m[0] << 1) >>> 0;
    const m2Hi = ((m[1] << 1) | (m[0] >>> 31)) >>> 0;
    t = add64(t[0], t[1], m2Lo, m2Hi);
    aLo = t[0];
    aHi = t[1];
  }
  // d = (d ^ a) >>> 16
  {
    const t = rotr64(dLo ^ aLo, dHi ^ aHi, 16);
    dLo = t[0];
    dHi = t[1];
  }
  // c = c + d + 2 * trunc(c) * trunc(d)
  {
    const m = mul32(cLo, dLo);
    let t = add64(cLo, cHi, dLo, dHi);
    const m2Lo = (m[0] << 1) >>> 0;
    const m2Hi = ((m[1] << 1) | (m[0] >>> 31)) >>> 0;
    t = add64(t[0], t[1], m2Lo, m2Hi);
    cLo = t[0];
    cHi = t[1];
  }
  // b = (b ^ c) >>> 63
  {
    const t = rotr64(bLo ^ cLo, bHi ^ cHi, 63);
    bLo = t[0];
    bHi = t[1];
  }

  v[2 * a] = aLo;
  v[2 * a + 1] = aHi;
  v[2 * b] = bLo;
  v[2 * b + 1] = bHi;
  v[2 * c] = cLo;
  v[2 * c + 1] = cHi;
  v[2 * d] = dLo;
  v[2 * d + 1] = dHi;
}

/** Permutation P over 16 words (in-place on Uint32Array(32)). */
function permuteP(v) {
  gb(v, 0, 4, 8, 12);
  gb(v, 1, 5, 9, 13);
  gb(v, 2, 6, 10, 14);
  gb(v, 3, 7, 11, 15);
  gb(v, 0, 5, 10, 15);
  gb(v, 1, 6, 11, 12);
  gb(v, 2, 7, 8, 13);
  gb(v, 3, 4, 9, 14);
}

/**
 * Argon2 compression function G(X, Y) → out.
 * X and Y are 1024-byte blocks addressed by (xArr, xOff) and (yArr, yOff).
 * The result is written to outArr starting at outOff (may alias an input).
 */
function compressG(xArr, xOff, yArr, yOff, outArr, outOff) {
  const r = scratch;
  for (let i = 0; i < 256; i++) {
    r[i] = xArr[xOff + i] ^ yArr[yOff + i];
  }
  // Row pass: P applied to each of the 8 rows of 16 words.
  for (let row = 0; row < 8; row++) {
    const base = row * 32;
    for (let k = 0; k < 32; k++) scratchP[k] = r[base + k];
    permuteP(scratchP);
    for (let k = 0; k < 32; k++) r[base + k] = scratchP[k];
  }
  // Column pass: P applied to the 8 "columns" (word pairs at stride 16).
  // Column i gathers words {2i+16k, 2i+1+16k} for k in 0..7.
  for (let col = 0; col < 8; col++) {
    for (let k = 0; k < 8; k++) {
      const src = 4 * col + 32 * k;
      scratchP[4 * k] = r[src];
      scratchP[4 * k + 1] = r[src + 1];
      scratchP[4 * k + 2] = r[src + 2];
      scratchP[4 * k + 3] = r[src + 3];
    }
    permuteP(scratchP);
    for (let k = 0; k < 8; k++) {
      const dst = 4 * col + 32 * k;
      r[dst] = scratchP[4 * k];
      r[dst + 1] = scratchP[4 * k + 1];
      r[dst + 2] = scratchP[4 * k + 2];
      r[dst + 3] = scratchP[4 * k + 3];
    }
  }
  // out = R ^ P(P(R)) where R = X ^ Y
  for (let i = 0; i < 256; i++) {
    outArr[outOff + i] = r[i] ^ xArr[xOff + i] ^ yArr[yOff + i];
  }
}

/** Argon2 reference `index_alpha` (data-dependent indexing). */
function indexAlpha(pass, slice, index, segmentLength, laneLength, sameLane, pseudoRand) {
  let referenceAreaSize;
  if (pass === 0) {
    if (slice === 0) {
      referenceAreaSize = index - 1;
    } else if (sameLane) {
      referenceAreaSize = slice * segmentLength + index - 1;
    } else {
      referenceAreaSize = slice * segmentLength + (index === 0 ? -1 : 0);
    }
  } else if (sameLane) {
    referenceAreaSize = laneLength - segmentLength + index - 1;
  } else {
    referenceAreaSize = laneLength - segmentLength + (index === 0 ? -1 : 0);
  }

  // Map a 32-bit pseudo-random value onto [0, referenceAreaSize).
  const squared = mul32(pseudoRand, pseudoRand)[1]; // (x * x) >> 32
  const weighted = mul32(referenceAreaSize, squared)[1]; // (area * x) >> 32
  const relativePosition = referenceAreaSize - 1 - weighted;

  let startPosition = 0;
  if (pass !== 0) {
    startPosition = slice === 3 ? 0 : (slice + 1) * segmentLength;
  }
  return (startPosition + relativePosition) % laneLength;
}

/**
 * Hash a password with Argon2.
 *
 * @param {object} opts
 *   password: string | Uint8Array
 *   salt: Uint8Array (>= 8 bytes)
 *   m: memory cost in KiB (>= 8 * lanes)
 *   t: number of passes
 *   p: number of lanes
 *   tagLen: output length in bytes (4..64 recommended)
 *   type: 0 = Argon2d, 1 = Argon2i, 2 = Argon2id
 *   secret / ad: optional Uint8Array
 * @returns {Uint8Array} tag
 */
export function argon2({
  password,
  salt,
  m = 19456,
  t = 2,
  p = 1,
  tagLen = 32,
  type = 2,
  secret = new Uint8Array(0),
  ad = new Uint8Array(0),
  version = 0x13,
}) {
  const pwd = typeof password === "string" ? new TextEncoder().encode(password) : password;

  const mprime = 4 * p * Math.floor(m / (4 * p));
  const laneLength = mprime / p;
  const segmentLength = laneLength / 4;

  // H0 (64 bytes).
  const h0Parts = [
    u32le(p),
    u32le(tagLen),
    u32le(m),
    u32le(t),
    u32le(version),
    u32le(type),
    u32le(pwd.length),
    pwd,
    u32le(salt.length),
    salt,
    u32le(secret.length),
    secret,
    u32le(ad.length),
    ad,
  ];
  const h0 = blake2b(64, concatBytes(...h0Parts));

  // Allocate memory as m' blocks of 1024 bytes (128 words = 256 int32).
  const mem = new Uint32Array(mprime * 256);

  // First two blocks of each lane (RFC 9106 figures 3 & 4).
  for (let lane = 0; lane < p; lane++) {
    const seed = new Uint8Array(72);
    seed.set(h0, 0);
    writeU32LE(seed, 64, 0);
    writeU32LE(seed, 68, lane);
    loadBlock(mem, lane * laneLength + 0, blake2bLong(1024, seed));

    writeU32LE(seed, 64, 1);
    loadBlock(mem, lane * laneLength + 1, blake2bLong(1024, seed));
  }

  const zero = new Uint32Array(256);
  const input = new Uint32Array(256);
  const addr = new Uint32Array(256);
  const outScratch = new Uint32Array(256);

  let dataIndependent = false;

  const nextAddresses = () => {
    input[12] = (input[12] + 1) >>> 0; // counter (word 6, low 32 bits)
    compressG(zero, 0, input, 0, addr, 0);
    compressG(zero, 0, addr, 0, addr, 0);
  };

  for (let pass = 0; pass < t; pass++) {
    for (let slice = 0; slice < 4; slice++) {
      for (let lane = 0; lane < p; lane++) {
        dataIndependent = type === 1 || (type === 2 && pass === 0 && slice < 2);

        if (dataIndependent) {
          zero.fill(0);
          input.fill(0);
          input[0] = pass; // word 0
          input[2] = lane; // word 1
          input[4] = slice; // word 2
          input[6] = mprime; // word 3
          input[8] = t; // word 4
          input[10] = type; // word 5
        }

        let startingIndex = 0;
        if (pass === 0 && slice === 0) {
          startingIndex = 2;
          if (dataIndependent) nextAddresses();
        }

        let currOffset = lane * laneLength + slice * segmentLength + startingIndex;
        let prevOffset =
          currOffset % laneLength === 0
            ? currOffset + laneLength - 1
            : currOffset - 1;

        for (let i = startingIndex; i < segmentLength; i++, currOffset++, prevOffset++) {
          if (currOffset % laneLength === 1) {
            prevOffset = currOffset - 1;
          }

          let j1;
          let refLane;
          if (dataIndependent) {
            if (i % 128 === 0) nextAddresses();
            const w = i % 128;
            j1 = addr[2 * w];
            refLane = addr[2 * w + 1] % p;
          } else {
            j1 = mem[prevOffset * 256];
            refLane = mem[prevOffset * 256 + 1] % p;
          }
          if (pass === 0 && slice === 0) refLane = lane;

          const refIndex = indexAlpha(
            pass,
            slice,
            i,
            segmentLength,
            laneLength,
            refLane === lane,
            j1,
          );

          const refOff = (refLane * laneLength + refIndex) * 256;
          const prevOffB = prevOffset * 256;
          const currOffB = currOffset * 256;

          compressG(mem, prevOffB, mem, refOff, outScratch, 0);
          if (pass > 0) {
            // XOR the new block over the old value (RFC 9106 figure 6).
            for (let k = 0; k < 256; k++) {
              mem[currOffB + k] = mem[currOffB + k] ^ outScratch[k];
            }
          } else {
            mem.set(outScratch, currOffB);
          }
        }
      }
    }
  }

  // Final block C = XOR of the last column.
  const lastBlock = new Uint32Array(256);
  lastBlock.set(mem.subarray((laneLength - 1) * 256, laneLength * 256));
  for (let lane = 1; lane < p; lane++) {
    const base = (lane * laneLength + laneLength - 1) * 256;
    for (let i = 0; i < 256; i++) {
      lastBlock[i] ^= mem[base + i];
    }
  }

  return blake2bLong(tagLen, wordsToBytesLE(lastBlock, 1024));
}

// ---------------------------------------------------------------------------
// Small byte helpers
// ---------------------------------------------------------------------------

function u32le(n) {
  const b = new Uint8Array(4);
  writeU32LE(b, 0, n);
  return b;
}

function writeU32LE(dst, off, n) {
  dst[off] = n & 0xff;
  dst[off + 1] = (n >>> 8) & 0xff;
  dst[off + 2] = (n >>> 16) & 0xff;
  dst[off + 3] = (n >>> 24) & 0xff;
}

function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/** Load 1024 bytes into a memory block (128 words). */
function loadBlock(mem, blockIndex, bytes) {
  const off = blockIndex * 256;
  for (let w = 0; w < 128; w++) {
    mem[off + 2 * w] = readU32LE(bytes, 8 * w);
    mem[off + 2 * w + 1] = readU32LE(bytes, 8 * w + 4);
  }
}

function readU32LE(src, off) {
  return (
    src[off] |
    (src[off + 1] << 8) |
    (src[off + 2] << 16) |
    (src[off + 3] << 24)
  ) >>> 0;
}
