/**
 * FYP Bit Engine - 3-Stage Reversible Image Cryptosystem, Portable .msbx Container & Steganography Library
 * 
 * Architecture (Chapter 4 Specification):
 * - Key Derivation: 16-byte cryptographic random salt + iterated SHA-256 (default 100,000 iterations)
 *   with separate domain-tagged streams ("STAGE1_PIXEL_PERM", "STAGE2_CHANNEL_PERM", "STAGE3_MSB_XOR", "MSBX_VERIFY_TAG").
 * - Stage 1: Pixel Permutation (Deterministic Fisher-Yates shuffle)
 * - Stage 2: RGB Channel Permutation (Per-pixel 6-permutation color rotation)
 * - Stage 3: k-MSB XOR Encryption (XOR top k MSB bits with k-bit keystream, default k = 2, preserving lower 8-k bits)
 * - Portable .msbx Container: 68-byte fixed header (magic "MSBX", version, image_mode, k, flags,
 *   width, height, iterations, 16-byte salt, 32-byte SHA-256 verification tag) + encrypted pixel payload.
 */

// Fast, bit-exact FIPS 180-4 SHA-256 implementation for synchronous 100,000-iteration KDF
const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function sha256Bytes(msgBytes) {
  const len = msgBytes.length;
  const bitLenHi = Math.floor((len * 8) / 0x100000000);
  const bitLenLo = (len * 8) >>> 0;
  const padLen = ((len + 9 + 63) & ~63);
  const buf = new Uint8Array(padLen);
  buf.set(msgBytes, 0);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(padLen - 8, bitLenHi, false);
  dv.setUint32(padLen - 4, bitLenLo, false);

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const W = new Uint32Array(64);

  for (let offset = 0; offset < padLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      W[i] = dv.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const v0 = W[i - 15];
      const s0 = (((v0 >>> 7) | (v0 << 25)) ^ ((v0 >>> 18) | (v0 << 14)) ^ (v0 >>> 3)) >>> 0;
      const v1 = W[i - 2];
      const s1 = (((v1 >>> 17) | (v1 << 15)) ^ ((v1 >>> 19) | (v1 << 13)) ^ (v1 >>> 10)) >>> 0;
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = (h + S1 + ch + SHA256_K[i] + W[i]) >>> 0;
      const S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (S0 + maj) >>> 0;

      h = g; g = f; f = e;
      e = (d + temp1) >>> 0;
      d = c; c = b; b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const outDv = new DataView(out.buffer);
  outDv.setUint32(0, h0, false);
  outDv.setUint32(4, h1, false);
  outDv.setUint32(8, h2, false);
  outDv.setUint32(12, h3, false);
  outDv.setUint32(16, h4, false);
  outDv.setUint32(20, h5, false);
  outDv.setUint32(24, h6, false);
  outDv.setUint32(28, h7, false);
  return out;
}

/**
 * Specialized single-block (48-byte = 32B digest + 16B salt) iterated SHA-256 loop.
 * Computes `iterations` rounds of `digest = SHA256(digest || salt)` in ~35ms for 100,000 rounds.
 */
function iterateSha256DigestWithSalt16(initialDigest32, salt16, extraIterations) {
  const sDv = new DataView(salt16.buffer, salt16.byteOffset, 16);
  const s0_w = sDv.getUint32(0, false);
  const s1_w = sDv.getUint32(4, false);
  const s2_w = sDv.getUint32(8, false);
  const s3_w = sDv.getUint32(12, false);

  const dDv = new DataView(initialDigest32.buffer, initialDigest32.byteOffset, 32);
  let d0 = dDv.getUint32(0, false), d1 = dDv.getUint32(4, false);
  let d2 = dDv.getUint32(8, false), d3 = dDv.getUint32(12, false);
  let d4 = dDv.getUint32(16, false), d5 = dDv.getUint32(20, false);
  let d6 = dDv.getUint32(24, false), d7 = dDv.getUint32(28, false);

  const W = new Uint32Array(64);

  for (let iter = 0; iter < extraIterations; iter++) {
    // 48-byte message = 32B digest (W[0..7]) + 16B salt (W[8..11]) + 0x80 padding + 384-bit length
    W[0] = d0; W[1] = d1; W[2] = d2; W[3] = d3;
    W[4] = d4; W[5] = d5; W[6] = d6; W[7] = d7;
    W[8] = s0_w; W[9] = s1_w; W[10] = s2_w; W[11] = s3_w;
    W[12] = 0x80000000;
    W[13] = 0;
    W[14] = 0;
    W[15] = 384; // 48 bytes * 8 bits = 384

    for (let i = 16; i < 64; i++) {
      const v0 = W[i - 15];
      const s0 = (((v0 >>> 7) | (v0 << 25)) ^ ((v0 >>> 18) | (v0 << 14)) ^ (v0 >>> 3)) >>> 0;
      const v1 = W[i - 2];
      const s1 = (((v1 >>> 17) | (v1 << 15)) ^ ((v1 >>> 19) | (v1 << 13)) ^ (v1 >>> 10)) >>> 0;
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }

    let a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a;
    let e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;

    for (let i = 0; i < 64; i++) {
      const S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = (h + S1 + ch + SHA256_K[i] + W[i]) >>> 0;
      const S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (S0 + maj) >>> 0;

      h = g; g = f; f = e;
      e = (d + temp1) >>> 0;
      d = c; c = b; b = a;
      a = (temp1 + temp2) >>> 0;
    }

    d0 = (0x6a09e667 + a) >>> 0; d1 = (0xbb67ae85 + b) >>> 0;
    d2 = (0x3c6ef372 + c) >>> 0; d3 = (0xa54ff53a + d) >>> 0;
    d4 = (0x510e527f + e) >>> 0; d5 = (0x9b05688c + f) >>> 0;
    d6 = (0x1f83d9ab + g) >>> 0; d7 = (0x5be0cd19 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const outDv = new DataView(out.buffer);
  outDv.setUint32(0, d0, false); outDv.setUint32(4, d1, false);
  outDv.setUint32(8, d2, false); outDv.setUint32(12, d3, false);
  outDv.setUint32(16, d4, false); outDv.setUint32(20, d5, false);
  outDv.setUint32(24, d6, false); outDv.setUint32(28, d7, false);
  return out;
}

const BitEngine = {
  MSBX_MAGIC: 'MSBX',
  MSBX_VERSION: 1,
  MSBX_HEADER_SIZE: 68,
  DEFAULT_ITERATIONS: 100000,
  DEFAULT_K: 2,

  // 6 Permutations of RGB color channels (3! = 6)
  CHANNEL_PERMS: [
    [0, 1, 2], // 0: R, G, B (Identity)
    [0, 2, 1], // 1: R, B, G
    [1, 0, 2], // 2: G, R, B
    [1, 2, 0], // 3: G, B, R
    [2, 0, 1], // 4: B, R, G
    [2, 1, 0]  // 5: B, G, R
  ],

  // Inverse permutations corresponding to CHANNEL_PERMS
  INV_CHANNEL_PERMS: [
    [0, 1, 2], // 0: inv of [0, 1, 2] -> [0, 1, 2]
    [0, 2, 1], // 1: inv of [0, 2, 1] -> [0, 2, 1]
    [1, 0, 2], // 2: inv of [1, 0, 2] -> [1, 0, 2]
    [2, 0, 1], // 3: inv of [1, 2, 0] -> [2, 0, 1]
    [1, 2, 0], // 4: inv of [2, 0, 1] -> [1, 2, 0]
    [2, 1, 0]  // 5: inv of [2, 1, 0] -> [2, 1, 0]
  ],

  /**
   * Generalized k-MSB XOR Operation (default k = 2)
   * Takes the top k MSB bits and XORs them with keyBits (0 .. (2^k - 1)),
   * leaving lower (8 - k) bits unchanged.
   */
  xorKMSB(byte, keyBits, k = 2) {
    const kk = Math.max(1, Math.min(8, k | 0));
    if (kk === 8) return (byte ^ (keyBits & 0xFF)) & 0xFF;
    const shift = 8 - kk;
    const mask = (1 << kk) - 1;
    const lowMask = (1 << shift) - 1;
    const msb = (byte >>> shift) & mask;
    const newMsb = (msb ^ (keyBits & mask)) & mask;
    return (byte & lowMask) | (newMsb << shift);
  },

  /**
   * 2-MSB XOR Operation (backwards-compatible shorthand for k = 2)
   */
  xor2MSB(byte, key2) {
    const msb = (byte >> 6) & 0x03;
    const newMsb = (msb ^ (key2 & 0x03)) & 0x03;
    return (byte & 0x3F) | (newMsb << 6);
  },

  /**
   * Helper bit-swap method for inspector / backwards compatibility
   */
  swapMSB(byte) {
    const msb = (byte >> 6) & 0x03;
    let newMsb = msb;
    if (msb === 2) newMsb = 1;
    else if (msb === 1) newMsb = 2;
    return (byte & 0x3F) | (newMsb << 6);
  },

  /**
   * Generate a fresh 16-byte cryptographically random salt.
   */
  generateRandomSalt(length = 16) {
    const salt = new Uint8Array(length);
    if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
      crypto.getRandomValues(salt);
    } else {
      for (let i = 0; i < length; i++) salt[i] = Math.floor(Math.random() * 256);
    }
    return salt;
  },

  bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  hexToBytes(hex) {
    const clean = hex.replace(/[^0-9a-fA-F]/g, '');
    const out = new Uint8Array(clean.length >>> 1);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return out;
  },

  /**
   * Derive a 256-bit cryptographic key from an image file or buffer.
   * Hashes the exact binary bytes of the key image with SHA-256 for bit-exact reproducibility.
   */
  async hashKeyImage(fileOrBuffer) {
    let buffer;
    if (fileOrBuffer instanceof ArrayBuffer) {
      buffer = fileOrBuffer;
    } else if (ArrayBuffer.isView(fileOrBuffer)) {
      buffer = fileOrBuffer.buffer.slice(fileOrBuffer.byteOffset, fileOrBuffer.byteOffset + fileOrBuffer.byteLength);
    } else if (fileOrBuffer && typeof fileOrBuffer.arrayBuffer === 'function') {
      buffer = await fileOrBuffer.arrayBuffer();
    } else {
      throw new Error("Invalid key image format");
    }
    const rawBytes = new Uint8Array(buffer);
    const hashBytes = sha256Bytes(rawBytes);
    const hex = this.bytesToHex(hashBytes);
    return {
      hex: "IMG_KEY:" + hex,
      displayHash: hex.substring(0, 12) + '...' + hex.substring(hex.length - 8),
      fullHash: hex,
      hashBytes,
      hashBuffer: hashBytes.buffer,
      hash32: new Uint32Array(hashBytes.buffer)
    };
  },

  /**
   * Chapter 4 Iterated SHA-256 Key Derivation Function (KDF):
   * Derives a 32-byte master key from a password (or key-image digest) + 16-byte salt
   * using `iterations` rounds of SHA-256 (default 100,000 iterations).
   */
  deriveMasterKeyIterated(passwordOrKey, salt16, iterations = 100000) {
    if (!(salt16 instanceof Uint8Array) || salt16.length !== 16) {
      throw new Error("Invalid salt: must be a 16-byte Uint8Array.");
    }
    const encoder = new TextEncoder();
    const secretBytes = (passwordOrKey instanceof Uint8Array)
      ? passwordOrKey
      : encoder.encode(String(passwordOrKey || ''));

    // Round 0: digest = SHA256(secretBytes || salt16)
    const initBuf = new Uint8Array(secretBytes.length + 16);
    initBuf.set(secretBytes, 0);
    initBuf.set(salt16, secretBytes.length);
    const round0 = sha256Bytes(initBuf);

    const totalIters = Math.max(1, iterations | 0);
    if (totalIters === 1) return round0;
    return iterateSha256DigestWithSalt16(round0, salt16, totalIters - 1);
  },

  /**
   * Create a deterministic Xoshiro128** stream PRNG from a 32-byte masterKey,
   * 16-byte salt, and domain tag ("STAGE1_PIXEL_PERM", "STAGE2_CHANNEL_PERM", "STAGE3_MSB_XOR").
   */
  createDomainPRNG(masterKey32, salt16, domainTag) {
    const encoder = new TextEncoder();
    const tagBytes = encoder.encode(domainTag);
    const buf = new Uint8Array(masterKey32.length + salt16.length + tagBytes.length);
    buf.set(masterKey32, 0);
    buf.set(salt16, masterKey32.length);
    buf.set(tagBytes, masterKey32.length + salt16.length);

    const seedBytes = sha256Bytes(buf);
    const hash32 = new Uint32Array(seedBytes.buffer, seedBytes.byteOffset, 8);

    let s0 = hash32[0] || 0x12345678;
    let s1 = hash32[1] || 0x9abcdef0;
    let s2 = hash32[2] || 0x0fedcba9;
    let s3 = hash32[3] || 0x87654321;

    function rotl(x, r) {
      return ((x << r) | (x >>> (32 - r))) >>> 0;
    }

    return {
      nextUint32() {
        const result = Math.imul(rotl(Math.imul(s1, 5) >>> 0, 7), 9) >>> 0;
        const t = (s1 << 9) >>> 0;
        s2 ^= s0;
        s3 ^= s1;
        s1 ^= s2;
        s0 ^= s3;
        s2 ^= t;
        s3 = rotl(s3, 11);
        return result;
      },
      nextInt(max) {
        if (max <= 1) return 0;
        return (this.nextUint32() % max) >>> 0;
      },
      nextByte() {
        return (this.nextUint32() & 0xFF);
      },
      next2Bits() {
        return (this.nextUint32() & 0x03);
      },
      nextKBits(k = 2) {
        const mask = (1 << Math.max(1, Math.min(8, k))) - 1;
        return (this.nextUint32() & mask);
      }
    };
  },

  /**
   * Compute the 32-byte SHA-256 verification tag for an .msbx container.
   * Authenticates the derived master key, the header fields (bytes 0..35),
   * the plaintext pixel buffer, and any optional scope mask trailer.
   */
  computeVerificationTag(masterKey32, salt16, headerPrefix36, plaintextPixelBytes, maskTrailerBytes = null) {
    const encoder = new TextEncoder();
    const tagDomain = encoder.encode('MSBX_VERIFY_TAG');
    const vkInput = new Uint8Array(masterKey32.length + salt16.length + tagDomain.length);
    vkInput.set(masterKey32, 0);
    vkInput.set(salt16, masterKey32.length);
    vkInput.set(tagDomain, masterKey32.length + salt16.length);
    const verifyKey = sha256Bytes(vkInput);

    const trailerLen = maskTrailerBytes ? maskTrailerBytes.length : 0;
    const total = verifyKey.length + 36 + plaintextPixelBytes.length + trailerLen;
    const msg = new Uint8Array(total);
    let pos = 0;
    msg.set(verifyKey, pos); pos += verifyKey.length;
    msg.set(headerPrefix36.subarray(0, 36), pos); pos += 36;
    msg.set(plaintextPixelBytes, pos); pos += plaintextPixelBytes.length;
    if (trailerLen > 0) msg.set(maskTrailerBytes, pos);

    return sha256Bytes(msg);
  },

  /**
   * Generate SHA-256 seeded deterministic PRNG (Xoshiro128**) for legacy single-pass mode / stego
   */
  async createPRNG(password, salt = "") {
    const encoder = new TextEncoder();
    const keyString = (password && password.length > 0 ? password : "DEFAULT_FYP_SEED_KEY_2026") + ":" + salt;
    const data = encoder.encode(keyString);
    const seedBytes = sha256Bytes(data);
    const hash32 = new Uint32Array(seedBytes.buffer, seedBytes.byteOffset, 8);

    let s0 = hash32[0] || 0x12345678;
    let s1 = hash32[1] || 0x9abcdef0;
    let s2 = hash32[2] || 0x0fedcba9;
    let s3 = hash32[3] || 0x87654321;

    function rotl(x, k) {
      return ((x << k) | (x >>> (32 - k))) >>> 0;
    }

    return {
      nextUint32() {
        const result = Math.imul(rotl(s1 * 5, 7), 9) >>> 0;
        const t = s1 << 9;
        s2 ^= s0;
        s3 ^= s1;
        s1 ^= s2;
        s0 ^= s3;
        s2 ^= t;
        s3 = rotl(s3, 11);
        return result;
      },
      nextInt(max) {
        if (max <= 1) return 0;
        return (this.nextUint32() % max) >>> 0;
      },
      nextByte() {
        return (this.nextUint32() & 0xFF);
      },
      next2Bits() {
        return (this.nextUint32() & 0x03);
      },
      nextKBits(k = 2) {
        const mask = (1 << Math.max(1, Math.min(8, k))) - 1;
        return (this.nextUint32() & mask);
      }
    };
  },

  /**
   * Keystream generator for Steganography
   */
  async createKeystream(password) {
    const prng = await this.createPRNG(password, "STEGANO_STREAM");
    return function getNextKeyByte() {
      return prng.nextByte();
    };
  },

  /**
   * Extract active pixel indices (within contour mask, bounding boxes, or full image)
   */
  getTargetPixelIndices(imageData, maskOrRegions) {
    const totalPixels = imageData.data.length / 4;
    const imgWidth = imageData.width;

    const isPixelMask = maskOrRegions && (
      maskOrRegions instanceof Uint8Array ||
      maskOrRegions instanceof Uint8ClampedArray ||
      (Array.isArray(maskOrRegions) && typeof maskOrRegions[0] === 'number')
    ) && maskOrRegions.length === totalPixels;

    let regionList = [];
    if (!isPixelMask && maskOrRegions) {
      if (Array.isArray(maskOrRegions)) {
        regionList = maskOrRegions.filter(r => r && r.width > 0 && r.height > 0);
      } else if (maskOrRegions.width > 0 && maskOrRegions.height > 0) {
        regionList = [maskOrRegions];
      }
    }
    const hasRegions = regionList.length > 0;

    const indices = [];
    for (let i = 0; i < totalPixels; i++) {
      if (isPixelMask) {
        if (maskOrRegions[i] > 0) indices.push(i);
      } else if (hasRegions) {
        const px = i % imgWidth;
        const py = Math.floor(i / imgWidth);
        let inRegion = false;
        for (let r = 0; r < regionList.length; r++) {
          const reg = regionList[r];
          const rx = Math.min(reg.x, reg.x + reg.width);
          const ry = Math.min(reg.y, reg.y + reg.height);
          const rw = Math.abs(reg.width);
          const rh = Math.abs(reg.height);
          if (px >= rx && px <= rx + rw && py >= ry && py <= ry + rh) {
            inRegion = true;
            break;
          }
        }
        if (inRegion) indices.push(i);
      } else {
        indices.push(i); // Full image
      }
    }
    return new Int32Array(indices);
  },

  /**
   * Run-length encode a binary pixel mask (0/1) as LEB128 varints for compact .msbx mask trailer.
   */
  encodeMaskTrailer(mask) {
    const bytes = [];
    const pushVarint = (v) => {
      while (v >= 0x80) { bytes.push((v & 0x7F) | 0x80); v >>>= 7; }
      bytes.push(v);
    };
    let cur = 0, run = 0;
    for (let i = 0; i < mask.length; i++) {
      const v = mask[i] ? 1 : 0;
      if (v === cur) run++;
      else { pushVarint(run); cur = v; run = 1; }
    }
    pushVarint(run);
    return Uint8Array.from(bytes);
  },

  decodeMaskTrailer(bytes, totalPixels) {
    const mask = new Uint8Array(totalPixels);
    let pos = 0, cur = 0, i = 0;
    while (i < bytes.length && pos < totalPixels) {
      let v = 0, shift = 0, b;
      do {
        b = bytes[i++];
        v |= (b & 0x7F) << shift;
        shift += 7;
      } while ((b & 0x80) && i < bytes.length);
      v >>>= 0;
      if (cur === 1) mask.fill(1, pos, Math.min(totalPixels, pos + v));
      pos += v;
      cur ^= 1;
    }
    if (pos !== totalPixels) {
      throw new Error("Corrupted .msbx scope mask trailer.");
    }
    return mask;
  },

  /**
   * Core 3-Stage Encryption with explicit PRNG streams and configurable k (1..8, default 2).
   */
  _encryptWithStreams(imageData, prngPixel, prngChannel, prngXor, maskOrRegions = null, kVal = 2) {
    const data = imageData.data;
    const originalCopy = new Uint8ClampedArray(data);
    const targetIndices = this.getTargetPixelIndices(imageData, maskOrRegions);
    const M = targetIndices.length;

    if (M === 0) {
      return { imageData, swappedCount: 0, mse: 0, psnr: '∞' };
    }

    // === STAGE 1: PIXEL PERMUTATION (Fisher-Yates Shuffle) ===
    const perm = new Int32Array(M);
    for (let i = 0; i < M; i++) perm[i] = i;
    for (let i = M - 1; i > 0; i--) {
      const j = prngPixel.nextInt(i + 1);
      const temp = perm[i];
      perm[i] = perm[j];
      perm[j] = temp;
    }

    const stage1Data = new Uint8ClampedArray(data);
    for (let idx = 0; idx < M; idx++) {
      const srcIdx = targetIndices[idx] * 4;
      const dstIdx = targetIndices[perm[idx]] * 4;
      stage1Data[dstIdx] = data[srcIdx];
      stage1Data[dstIdx + 1] = data[srcIdx + 1];
      stage1Data[dstIdx + 2] = data[srcIdx + 2];
      stage1Data[dstIdx + 3] = data[srcIdx + 3];
    }

    // === STAGE 2: RGB CHANNEL PERMUTATION ===
    const stage2Data = new Uint8ClampedArray(stage1Data);
    for (let idx = 0; idx < M; idx++) {
      const pixelIdx = targetIndices[idx] * 4;
      const r = stage1Data[pixelIdx];
      const g = stage1Data[pixelIdx + 1];
      const b = stage1Data[pixelIdx + 2];
      const rgb = [r, g, b];

      const permId = prngChannel.nextInt(6);
      const pOrder = this.CHANNEL_PERMS[permId];

      stage2Data[pixelIdx] = rgb[pOrder[0]];
      stage2Data[pixelIdx + 1] = rgb[pOrder[1]];
      stage2Data[pixelIdx + 2] = rgb[pOrder[2]];
    }

    // === STAGE 3: k-MSB XOR ENCRYPTION ===
    let swappedCount = 0;
    let totalDiffSq = 0;
    let channelCount = 0;

    for (let idx = 0; idx < M; idx++) {
      const pixelIdx = targetIndices[idx] * 4;
      for (let c = 0; c < 3; c++) {
        const cIdx = pixelIdx + c;
        const originalByte = originalCopy[cIdx];
        const currentByte = stage2Data[cIdx];
        const keyBits = kVal === 2 ? prngXor.next2Bits() : prngXor.nextKBits(kVal);

        const newByte = kVal === 2 ? this.xor2MSB(currentByte, keyBits) : this.xorKMSB(currentByte, keyBits, kVal);
        data[cIdx] = newByte;

        if (newByte !== originalByte) swappedCount++;
        const diff = originalByte - newByte;
        totalDiffSq += diff * diff;
        channelCount++;
      }
    }

    const mse = channelCount > 0 ? (totalDiffSq / channelCount) : 0;
    const psnr = mse === 0 ? Infinity : 10 * Math.log10((255 * 255) / mse);

    return {
      imageData,
      swappedCount,
      mse: parseFloat(mse.toFixed(4)),
      psnr: psnr === Infinity ? '∞' : parseFloat(psnr.toFixed(2))
    };
  },

  /**
   * Core 3-Stage Decryption with explicit PRNG streams and configurable k (1..8, default 2).
   */
  _decryptWithStreams(imageData, prngPixel, prngChannel, prngXor, maskOrRegions = null, kVal = 2) {
    const data = imageData.data;
    const inputCopy = new Uint8ClampedArray(data);
    const targetIndices = this.getTargetPixelIndices(imageData, maskOrRegions);
    const M = targetIndices.length;

    if (M === 0) {
      return { imageData, swappedCount: 0, mse: 0, psnr: '∞' };
    }

    // === REVERSE STAGE 3: UNDO k-MSB XOR ENCRYPTION ===
    const unXorData = new Uint8ClampedArray(data);
    for (let idx = 0; idx < M; idx++) {
      const pixelIdx = targetIndices[idx] * 4;
      for (let c = 0; c < 3; c++) {
        const cIdx = pixelIdx + c;
        const keyBits = kVal === 2 ? prngXor.next2Bits() : prngXor.nextKBits(kVal);
        unXorData[cIdx] = kVal === 2 ? this.xor2MSB(data[cIdx], keyBits) : this.xorKMSB(data[cIdx], keyBits, kVal);
      }
    }

    // === REVERSE STAGE 2: UNDO RGB CHANNEL PERMUTATION ===
    const unChannelData = new Uint8ClampedArray(unXorData);
    for (let idx = 0; idx < M; idx++) {
      const pixelIdx = targetIndices[idx] * 4;
      const r = unXorData[pixelIdx];
      const g = unXorData[pixelIdx + 1];
      const b = unXorData[pixelIdx + 2];
      const rgb = [r, g, b];

      const permId = prngChannel.nextInt(6);
      const invOrder = this.INV_CHANNEL_PERMS[permId];

      unChannelData[pixelIdx] = rgb[invOrder[0]];
      unChannelData[pixelIdx + 1] = rgb[invOrder[1]];
      unChannelData[pixelIdx + 2] = rgb[invOrder[2]];
    }

    // === REVERSE STAGE 1: UNDO PIXEL PERMUTATION ===
    const perm = new Int32Array(M);
    for (let i = 0; i < M; i++) perm[i] = i;
    for (let i = M - 1; i > 0; i--) {
      const j = prngPixel.nextInt(i + 1);
      const temp = perm[i];
      perm[i] = perm[j];
      perm[j] = temp;
    }

    for (let idx = 0; idx < M; idx++) {
      const srcIdx = targetIndices[perm[idx]] * 4;
      const dstIdx = targetIndices[idx] * 4;
      data[dstIdx] = unChannelData[srcIdx];
      data[dstIdx + 1] = unChannelData[srcIdx + 1];
      data[dstIdx + 2] = unChannelData[srcIdx + 2];
      data[dstIdx + 3] = unChannelData[srcIdx + 3];
    }

    let swappedCount = 0;
    let totalDiffSq = 0;
    let channelCount = 0;

    for (let idx = 0; idx < M; idx++) {
      const pixelIdx = targetIndices[idx] * 4;
      for (let c = 0; c < 3; c++) {
        const cIdx = pixelIdx + c;
        const beforeByte = inputCopy[cIdx];
        const afterByte = data[cIdx];
        if (beforeByte !== afterByte) swappedCount++;
        const diff = beforeByte - afterByte;
        totalDiffSq += diff * diff;
        channelCount++;
      }
    }

    const mse = channelCount > 0 ? (totalDiffSq / channelCount) : 0;
    const psnr = mse === 0 ? Infinity : 10 * Math.log10((255 * 255) / mse);

    return {
      imageData,
      swappedCount,
      mse: parseFloat(mse.toFixed(4)),
      psnr: psnr === Infinity ? '∞' : parseFloat(psnr.toFixed(2))
    };
  },

  /**
   * Extract compact pixel payload bytes from RGBA ImageData according to imageMode:
   * mode 1 = RGB (3 bytes/pixel), mode 2 = RGBA (4 bytes/pixel).
   */
  extractPixelPayload(rgbaData, totalPixels, imageMode) {
    if (imageMode === 2) {
      return new Uint8Array(rgbaData.buffer.slice(rgbaData.byteOffset, rgbaData.byteOffset + totalPixels * 4));
    }
    const rgb = new Uint8Array(totalPixels * 3);
    for (let i = 0, j = 0; i < totalPixels; i++, j += 3) {
      const p = i * 4;
      rgb[j] = rgbaData[p];
      rgb[j + 1] = rgbaData[p + 1];
      rgb[j + 2] = rgbaData[p + 2];
    }
    return rgb;
  },

  /**
   * Expand compact pixel payload bytes (mode 0 = L, mode 1 = RGB, mode 2 = RGBA) into RGBA ImageData.
   */
  payloadToImageData(payloadBytes, width, height, imageMode) {
    const totalPixels = width * height;
    const rgba = new Uint8ClampedArray(totalPixels * 4);
    if (imageMode === 2) {
      rgba.set(payloadBytes.subarray(0, totalPixels * 4));
    } else if (imageMode === 1) {
      for (let i = 0, j = 0; i < totalPixels; i++, j += 3) {
        const p = i * 4;
        rgba[p] = payloadBytes[j];
        rgba[p + 1] = payloadBytes[j + 1];
        rgba[p + 2] = payloadBytes[j + 2];
        rgba[p + 3] = 255;
      }
    } else if (imageMode === 0) {
      for (let i = 0; i < totalPixels; i++) {
        const v = payloadBytes[i];
        const p = i * 4;
        rgba[p] = v;
        rgba[p + 1] = v;
        rgba[p + 2] = v;
        rgba[p + 3] = 255;
      }
    } else {
      throw new Error(`Unsupported .msbx image mode (${imageMode}).`);
    }
    return new ImageData(rgba, width, height);
  },

  /**
   * Encrypt an ImageData and package it into a portable Chapter 4 `.msbx` binary container.
   *
   * 68-byte Fixed Header Layout (Big-Endian network byte order):
   * - [0..3]   4B : Magic ASCII "MSBX"
   * - [4]      1B : Version (1)
   * - [5]      1B : Image Mode (1 = RGB 24-bit, 2 = RGBA 32-bit, 0 = Grayscale 8-bit)
   * - [6]      1B : k value (1..8, default 2 for 2-MSB XOR)
   * - [7]      1B : Flags (bit 0 = keyMode [0=password, 1=imageKey]; bits 1..2 = scopeCode; bit 7 = hasMaskTrailer)
   * - [8..11]  4B : Width (uint32 BE)
   * - [12..15] 4B : Height (uint32 BE)
   * - [16..19] 4B : Iteration count (uint32 BE, default 100,000)
   * - [20..35] 16B: Fresh cryptographic random salt
   * - [36..67] 32B: SHA-256 verification tag
   * Followed by:
   * - Encrypted pixel payload (`width * height * channels` bytes)
   * - Optional RLE mask trailer if partial scope (Body/Face/ROI) was selected
   */
  async encryptToMSBX(imageData, passwordOrKey, maskOrRegions = null, options = {}) {
    const width = imageData.width;
    const height = imageData.height;
    const totalPixels = width * height;
    const kVal = Math.max(1, Math.min(8, (options.k || this.DEFAULT_K) | 0));
    const iterations = Math.max(1, (options.iterations || this.DEFAULT_ITERATIONS) | 0);
    const keyType = options.keyType === 'image' ? 'image' : 'text';
    const scope = options.scope || 'full';

    // Detect if source image uses alpha transparency (< 255); use RGB (mode 1) or RGBA (mode 2)
    let hasTransparency = false;
    const srcRgba = imageData.data;
    for (let i = 3; i < srcRgba.length; i += 4) {
      if (srcRgba[i] < 255) { hasTransparency = true; break; }
    }
    const imageMode = hasTransparency ? 2 : 1;

    // Build binary scope mask trailer if a partial region (person, face, or custom ROI) is active
    let maskTrailer = null;
    if (maskOrRegions) {
      const targetIdx = this.getTargetPixelIndices(imageData, maskOrRegions);
      if (targetIdx.length > 0 && targetIdx.length < totalPixels) {
        const fullMask = new Uint8Array(totalPixels);
        for (let i = 0; i < targetIdx.length; i++) fullMask[targetIdx[i]] = 1;
        maskTrailer = this.encodeMaskTrailer(fullMask);
      }
    }

    const scopeCodeMap = { full: 0, person: 1, face: 2, custom: 3 };
    const scopeCode = maskTrailer ? (scopeCodeMap[scope] || 3) : 0;
    const flags = (keyType === 'image' ? 0x01 : 0x00)
                | ((scopeCode & 0x03) << 1)
                | (maskTrailer ? 0x80 : 0x00);

    // 1. Fresh 16-byte random salt for every encryption
    const salt = options.salt instanceof Uint8Array && options.salt.length === 16
      ? options.salt
      : this.generateRandomSalt(16);

    // 2. Capture plaintext pixel payload before in-place encryption for the verification tag
    const plaintextPayload = this.extractPixelPayload(srcRgba, totalPixels, imageMode);

    // 3. Derive 32-byte master key via iterated SHA-256 (100,000 iterations)
    const masterKey = this.deriveMasterKeyIterated(passwordOrKey, salt, iterations);

    // 4. Assemble first 36 bytes of the 68-byte header
    const header = new Uint8Array(this.MSBX_HEADER_SIZE);
    header[0] = 0x4D; // 'M'
    header[1] = 0x53; // 'S'
    header[2] = 0x42; // 'B'
    header[3] = 0x58; // 'X'
    header[4] = this.MSBX_VERSION;
    header[5] = imageMode;
    header[6] = kVal;
    header[7] = flags;
    const hDv = new DataView(header.buffer);
    hDv.setUint32(8, width, false);
    hDv.setUint32(12, height, false);
    hDv.setUint32(16, iterations, false);
    header.set(salt, 20);

    // 5. Compute 32-byte SHA-256 verification tag
    const verifyTag = this.computeVerificationTag(masterKey, salt, header.subarray(0, 36), plaintextPayload, maskTrailer);
    header.set(verifyTag, 36);

    // 6. Create domain-tagged PRNG streams and run 3-stage encryption
    const prngPixel = this.createDomainPRNG(masterKey, salt, 'STAGE1_PIXEL_PERM');
    const prngChannel = this.createDomainPRNG(masterKey, salt, 'STAGE2_CHANNEL_PERM');
    const prngXor = this.createDomainPRNG(masterKey, salt, 'STAGE3_MSB_XOR');

    const encResult = this._encryptWithStreams(imageData, prngPixel, prngChannel, prngXor, maskOrRegions, kVal);
    const encryptedPayload = this.extractPixelPayload(imageData.data, totalPixels, imageMode);

    // 7. Concatenate 68-byte header + encrypted pixel payload (+ optional mask trailer)
    const trailerLen = maskTrailer ? (4 + maskTrailer.length) : 0;
    const msbxBytes = new Uint8Array(this.MSBX_HEADER_SIZE + encryptedPayload.length + trailerLen);
    msbxBytes.set(header, 0);
    msbxBytes.set(encryptedPayload, this.MSBX_HEADER_SIZE);
    if (maskTrailer) {
      const tPos = this.MSBX_HEADER_SIZE + encryptedPayload.length;
      const mDv = new DataView(msbxBytes.buffer);
      mDv.setUint32(tPos, maskTrailer.length, false);
      msbxBytes.set(maskTrailer, tPos + 4);
    }

    return {
      ...encResult,
      msbxBytes,
      header: {
        magic: 'MSBX',
        version: this.MSBX_VERSION,
        imageMode,
        imageModeLabel: imageMode === 2 ? 'RGBA (32-bit)' : 'RGB (24-bit)',
        k: kVal,
        flags,
        keyType,
        scope: maskTrailer ? scope : 'full',
        width,
        height,
        iterations,
        salt,
        saltHex: this.bytesToHex(salt),
        verificationTag: verifyTag,
        tagHex: this.bytesToHex(verifyTag),
        byteLength: msbxBytes.byteLength
      }
    };
  },

  /**
   * Parse and validate the 68-byte `.msbx` header and extract a visual preview ImageData
   * of the encrypted ciphertext pixels without requiring the decryption key yet.
   */
  inspectMSBX(bufferOrBytes) {
    const bytes = bufferOrBytes instanceof Uint8Array
      ? bufferOrBytes
      : new Uint8Array(bufferOrBytes);

    if (bytes.byteLength < this.MSBX_HEADER_SIZE) {
      throw new Error(`Invalid or truncated .msbx file: Expected at least ${this.MSBX_HEADER_SIZE} header bytes, but file is only ${bytes.byteLength} bytes.`);
    }

    const magic = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]);
    if (magic !== this.MSBX_MAGIC) {
      throw new Error(`Invalid file header: Magic bytes are "${magic.replace(/[^\x20-\x7E]/g, '?')}", expected "MSBX".`);
    }

    const version = bytes[4];
    if (version !== this.MSBX_VERSION) {
      throw new Error(`Unsupported .msbx format version (v${version}): Only version ${this.MSBX_VERSION} is supported.`);
    }

    const rawMode = bytes[5];
    const imageMode = rawMode & 0x0F;
    if (imageMode !== 0 && imageMode !== 1 && imageMode !== 2) {
      throw new Error(`Invalid .msbx image mode (${imageMode}): Expected 0 (Grayscale), 1 (RGB), or 2 (RGBA).`);
    }

    // Support both uint8 k at byte[6] + flags at byte[7] AND big-endian uint16 k at bytes[6..7]
    let kVal = bytes[6];
    let flags = bytes[7];
    if (kVal === 0 && flags >= 1 && flags <= 8) {
      kVal = flags;
      flags = 0;
    }
    if (kVal < 1 || kVal > 8) {
      throw new Error(`Invalid .msbx k-MSB parameter (k = ${kVal}): Must be between 1 and 8.`);
    }

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const width = dv.getUint32(8, false);
    const height = dv.getUint32(12, false);
    const iterations = dv.getUint32(16, false);

    if (width === 0 || height === 0 || width > 16384 || height > 16384) {
      throw new Error(`Invalid .msbx image dimensions (${width} × ${height}).`);
    }
    if (iterations < 1 || iterations > 5000000) {
      throw new Error(`Invalid .msbx iteration count (${iterations}).`);
    }

    const channels = imageMode === 2 ? 4 : (imageMode === 1 ? 3 : 1);
    const pixelByteLength = width * height * channels;
    const payloadStart = this.MSBX_HEADER_SIZE;
    const payloadEnd = payloadStart + pixelByteLength;

    if (bytes.byteLength < payloadEnd) {
      throw new Error(`Truncated or corrupted .msbx payload: Expected ${pixelByteLength.toLocaleString()} encrypted pixel bytes for ${width}×${height} image, but only ${(bytes.byteLength - payloadStart).toLocaleString()} bytes are present.`);
    }

    const salt = bytes.slice(20, 36);
    const verificationTag = bytes.slice(36, 68);
    const encryptedPayload = bytes.subarray(payloadStart, payloadEnd);

    const hasMaskTrailer = (flags & 0x80) !== 0;
    let mask = null;
    let maskTrailerBytes = null;
    if (hasMaskTrailer) {
      if (bytes.byteLength < payloadEnd + 4) {
        throw new Error("Truncated .msbx file: Missing scope mask trailer header.");
      }
      const maskLen = dv.getUint32(payloadEnd, false);
      if (bytes.byteLength < payloadEnd + 4 + maskLen) {
        throw new Error("Truncated .msbx file: Scope mask trailer is incomplete.");
      }
      maskTrailerBytes = bytes.slice(payloadEnd + 4, payloadEnd + 4 + maskLen);
      mask = this.decodeMaskTrailer(maskTrailerBytes, width * height);
    } else if (bytes.byteLength !== payloadEnd) {
      throw new Error(`Corrupted .msbx payload: Unexpected ${bytes.byteLength - payloadEnd} trailing bytes after pixel data.`);
    }

    const scopeCode = (flags >> 1) & 0x03;
    const scopeNames = ['full', 'person', 'face', 'custom'];
    const scope = hasMaskTrailer ? (scopeNames[scopeCode] || 'custom') : 'full';
    const keyType = (flags & 0x01) ? 'image' : 'text';

    const previewImageData = this.payloadToImageData(encryptedPayload, width, height, imageMode);

    return {
      header: {
        magic,
        version,
        imageMode,
        imageModeLabel: imageMode === 2 ? 'RGBA (32-bit)' : (imageMode === 1 ? 'RGB (24-bit)' : 'Grayscale (8-bit)'),
        channels,
        k: kVal,
        flags,
        keyType,
        scope,
        width,
        height,
        iterations,
        salt,
        saltHex: this.bytesToHex(salt),
        verificationTag,
        tagHex: this.bytesToHex(verificationTag),
        byteLength: bytes.byteLength
      },
      mask,
      maskTrailerBytes,
      previewImageData
    };
  },

  /**
   * Unpack, decrypt, and cryptographically verify a portable `.msbx` container.
   * Throws a descriptive Error if the header is invalid, payload is truncated/corrupted,
   * or the password / key image is wrong (SHA-256 verification tag mismatch).
   */
  async decryptFromMSBX(bufferOrBytes, passwordOrKey) {
    const bytes = bufferOrBytes instanceof Uint8Array
      ? bufferOrBytes
      : new Uint8Array(bufferOrBytes);

    const inspected = this.inspectMSBX(bytes);
    const { header, mask, maskTrailerBytes, previewImageData } = inspected;

    // 1. Derive candidate masterKey using header's 16-byte salt and iteration count
    const masterKey = this.deriveMasterKeyIterated(passwordOrKey, header.salt, header.iterations);

    // 2. Decrypt a working copy of the ciphertext ImageData
    const workingImageData = new ImageData(
      new Uint8ClampedArray(previewImageData.data),
      header.width,
      header.height
    );

    const prngPixel = this.createDomainPRNG(masterKey, header.salt, 'STAGE1_PIXEL_PERM');
    const prngChannel = this.createDomainPRNG(masterKey, header.salt, 'STAGE2_CHANNEL_PERM');
    const prngXor = this.createDomainPRNG(masterKey, header.salt, 'STAGE3_MSB_XOR');

    const decResult = this._decryptWithStreams(
      workingImageData,
      prngPixel,
      prngChannel,
      prngXor,
      mask,
      header.k
    );

    // 3. Reconstruct candidate plaintext payload bytes and verify the 32-byte SHA-256 tag
    const candidatePlaintextPayload = this.extractPixelPayload(
      decResult.imageData.data,
      header.width * header.height,
      header.imageMode
    );
    const expectedTag = this.computeVerificationTag(
      masterKey,
      header.salt,
      bytes.subarray(0, 36),
      candidatePlaintextPayload,
      maskTrailerBytes
    );

    let diffBits = 0;
    for (let i = 0; i < 32; i++) {
      diffBits |= (expectedTag[i] ^ header.verificationTag[i]);
    }
    if (diffBits !== 0) {
      throw new Error("Decryption verification failed: Incorrect password or key image (SHA-256 verification tag mismatch).");
    }

    return {
      ...decResult,
      header,
      verified: true
    };
  },

  /**
   * Encode an ImageData buffer into a standard, uncompressed 24-bit (or 32-bit) BMP Blob.
   * Ensures browsers can download true lossless .bmp files on any device.
   */
  imageDataToBMPBlob(imageData) {
    const width = imageData.width;
    const height = imageData.height;
    const src = imageData.data;

    // 24-bit BGR with rows padded to 4-byte multiples (standard Windows BITMAPINFOHEADER)
    const rowStride = ((width * 3 + 3) & ~3);
    const pixelArraySize = rowStride * height;
    const fileSize = 54 + pixelArraySize;
    const buf = new Uint8Array(fileSize);
    const dv = new DataView(buf.buffer);

    // BITMAPFILEHEADER (14 bytes)
    buf[0] = 0x42; // 'B'
    buf[1] = 0x4D; // 'M'
    dv.setUint32(2, fileSize, true);
    dv.setUint32(6, 0, true);
    dv.setUint32(10, 54, true);

    // BITMAPINFOHEADER (40 bytes)
    dv.setUint32(14, 40, true);
    dv.setInt32(18, width, true);
    dv.setInt32(22, -height, true); // top-down DIB
    dv.setUint16(26, 1, true);
    dv.setUint16(28, 24, true);     // 24 bpp
    dv.setUint32(30, 0, true);      // BI_RGB
    dv.setUint32(34, pixelArraySize, true);
    dv.setInt32(38, 2835, true);    // 72 DPI
    dv.setInt32(42, 2835, true);
    dv.setUint32(46, 0, true);
    dv.setUint32(50, 0, true);

    let offset = 54;
    for (let y = 0; y < height; y++) {
      let rowPos = offset;
      for (let x = 0; x < width; x++) {
        const idx = (y * width + x) * 4;
        buf[rowPos] = src[idx + 2];     // B
        buf[rowPos + 1] = src[idx + 1]; // G
        buf[rowPos + 2] = src[idx];     // R
        rowPos += 3;
      }
      offset += rowStride;
    }

    return new Blob([buf], { type: 'image/bmp' });
  },

  /**
   * 3-Stage Reversible Image Encryption (Legacy direct ImageData API, preserved for backwards compatibility)
   */
  async encryptImage(imageData, password, maskOrRegions = null, kVal = 2) {
    const prngPixel = await this.createPRNG(password, "STAGE1_PIXEL_PERM");
    const prngChannel = await this.createPRNG(password, "STAGE2_CHANNEL_PERM");
    const prngXor = await this.createPRNG(password, "STAGE3_MSB_XOR");
    return this._encryptWithStreams(imageData, prngPixel, prngChannel, prngXor, maskOrRegions, kVal);
  },

  /**
   * 3-Stage Reversible Image Decryption (Legacy direct ImageData API, preserved for backwards compatibility)
   */
  async decryptImage(imageData, password, maskOrRegions = null, kVal = 2) {
    const prngPixel = await this.createPRNG(password, "STAGE1_PIXEL_PERM");
    const prngChannel = await this.createPRNG(password, "STAGE2_CHANNEL_PERM");
    const prngXor = await this.createPRNG(password, "STAGE3_MSB_XOR");
    return this._decryptWithStreams(imageData, prngPixel, prngChannel, prngXor, maskOrRegions, kVal);
  },

  /**
   * Unified dispatcher for processing (enc/dec)
   */
  async processImage(imageData, password, maskOrRegions = null, isDecrypt = false) {
    if (isDecrypt) {
      return this.decryptImage(imageData, password, maskOrRegions);
    }
    return this.encryptImage(imageData, password, maskOrRegions);
  },

  /**
   * Compare two ImageData buffers and compute MSE, PSNR, and difference stats
   * @param {ImageData} dataA 
   * @param {ImageData} dataB 
   * @returns {{mse: number, psnr: number|string, diffCount: number, channelCount: number}}
   */
  calculateMetrics(dataA, dataB) {
    if (!dataA || !dataB || dataA.data.length !== dataB.data.length) {
      return { mse: 0, psnr: '∞', diffCount: 0, channelCount: 0 };
    }
    const bufA = dataA.data;
    const bufB = dataB.data;
    let totalDiffSq = 0;
    let diffCount = 0;
    let channelCount = 0;

    for (let i = 0; i < bufA.length; i += 4) {
      for (let c = 0; c < 3; c++) {
        const diff = bufA[i + c] - bufB[i + c];
        if (diff !== 0) diffCount++;
        totalDiffSq += diff * diff;
        channelCount++;
      }
    }

    const mse = channelCount > 0 ? (totalDiffSq / channelCount) : 0;
    const psnr = mse === 0 ? Infinity : 10 * Math.log10((255 * 255) / mse);

    return {
      mse: parseFloat(mse.toFixed(4)),
      psnr: psnr === Infinity ? '∞' : parseFloat(psnr.toFixed(2)),
      diffCount,
      channelCount
    };
  },

  /**
   * Steganography: Embed text payload into LSB bits of ImageData
   * @param {ImageData} imageData 
   * @param {string} textPayload 
   * @param {string} password 
   * @returns {Promise<ImageData>}
   */
  async embedStegoPayload(imageData, textPayload, password) {
    const data = imageData.data;
    const getKeyByte = await this.createKeystream(password);

    // Convert text payload to byte array
    const encoder = new TextEncoder();
    const payloadBytes = encoder.encode(textPayload);
    
    // Header: 4 bytes (32-bit uint) holding length of payload
    const len = payloadBytes.length;
    const fullBuffer = new Uint8Array(4 + len);
    fullBuffer[0] = (len >> 24) & 0xFF;
    fullBuffer[1] = (len >> 16) & 0xFF;
    fullBuffer[2] = (len >> 8) & 0xFF;
    fullBuffer[3] = len & 0xFF;
    fullBuffer.set(payloadBytes, 4);

    // XOR encrypt payload buffer with password keystream
    for (let i = 0; i < fullBuffer.length; i++) {
      fullBuffer[i] ^= getKeyByte();
    }

    // Convert fullBuffer into binary bitstream
    let bits = [];
    for (let b of fullBuffer) {
      for (let shift = 7; shift >= 0; shift--) {
        bits.push((b >> shift) & 1);
      }
    }

    const maxBits = (data.length / 4) * 3; // 1 bit per RGB channel
    if (bits.length > maxBits) {
      throw new Error(`Text message too long! Max length for this image is ${Math.floor((maxBits - 32)/8)} characters.`);
    }

    let bitIdx = 0;
    for (let i = 0; i < data.length && bitIdx < bits.length; i += 4) {
      for (let c = 0; c < 3 && bitIdx < bits.length; c++) {
        const idx = i + c;
        const bitToHide = bits[bitIdx++];
        // Replace bit b0 of channel
        data[idx] = (data[idx] & 0xFE) | bitToHide;
      }
    }

    return imageData;
  },

  /**
   * Steganography: Extract text payload from LSB bits of ImageData
   * @param {ImageData} imageData 
   * @param {string} password 
   * @returns {Promise<string>}
   */
  async extractStegoPayload(imageData, password) {
    const data = imageData.data;
    const getKeyByte = await this.createKeystream(password);

    // Extract raw bitstream from LSB (b0) of RGB channels
    let bits = [];
    for (let i = 0; i < data.length; i += 4) {
      for (let c = 0; c < 3; c++) {
        bits.push(data[i + c] & 1);
      }
    }

    // Read first 32 bits for length header
    if (bits.length < 32) {
      throw new Error("Image too small to contain valid stego payload.");
    }

    let rawHeaderBytes = new Uint8Array(4);
    for (let byteIdx = 0; byteIdx < 4; byteIdx++) {
      let b = 0;
      for (let bitIdx = 0; bitIdx < 8; bitIdx++) {
        b = (b << 1) | bits[byteIdx * 8 + bitIdx];
      }
      rawHeaderBytes[byteIdx] = b ^ getKeyByte();
    }

    const payloadLen = (rawHeaderBytes[0] << 24) | (rawHeaderBytes[1] << 16) | (rawHeaderBytes[2] << 8) | rawHeaderBytes[3];

    if (payloadLen <= 0 || payloadLen > (bits.length - 32) / 8) {
      throw new Error("Invalid payload length or incorrect password.");
    }

    let rawPayloadBytes = new Uint8Array(payloadLen);
    const startBitOffset = 32;

    for (let byteIdx = 0; byteIdx < payloadLen; byteIdx++) {
      let b = 0;
      for (let bitIdx = 0; bitIdx < 8; bitIdx++) {
        b = (b << 1) | bits[startBitOffset + byteIdx * 8 + bitIdx];
      }
      rawPayloadBytes[byteIdx] = b ^ getKeyByte();
    }

    const decoder = new TextDecoder('utf-8');
    return decoder.decode(rawPayloadBytes);
  },

  /**
   * Convert Byte into 8-bit binary string padded with zeros
   * @param {number} byte 
   * @returns {string} e.g. "10100001"
   */
  toBinary8(byte) {
    return byte.toString(2).padStart(8, '0');
  },

  /**
   * Derive a fast 256-bit cryptographic master key from password for video stream processing
   * @param {string} password
   * @returns {Promise<Uint32Array>} 8 uint32 values
   */
  async createFastMasterKey(password) {
    const encoder = new TextEncoder();
    const keyString = (password && password.length > 0 ? password : "DEFAULT_FYP_VIDEO_KEY_2026") + ":VIDEO_STREAM_SEED";
    const data = encoder.encode(keyString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return new Uint32Array(hashBuffer);
  },

  /**
   * Fast synchronous PRNG for frame-by-frame encryption (Xoshiro128**)
   * Seeding deterministically combines master key with frame index & stage identifier.
   */
  getFramePRNG(master32, frameIndex, stageId = 0) {
    let s0 = (master32[0] ^ (frameIndex * 0x9E3779B9 + stageId * 0x85EBCA6B)) >>> 0;
    let s1 = (master32[1] ^ (frameIndex * 0xC2B2AE35 + stageId * 0x7F4A7C15)) >>> 0;
    let s2 = (master32[2] ^ (frameIndex * 0x27D4EB2F + stageId * 0x165667B1)) >>> 0;
    let s3 = (master32[3] ^ (frameIndex * 0x9E3779B9 ^ (master32[4] || 0x12345678))) >>> 0;

    if ((s0 | s1 | s2 | s3) === 0) {
      s0 = 0x12345678; s1 = 0x9abcdef0; s2 = 0x0fedcba9; s3 = 0x87654321;
    }

    function rotl(x, k) {
      return ((x << k) | (x >>> (32 - k))) >>> 0;
    }

    return {
      nextUint32() {
        const result = Math.imul(rotl(s1 * 5, 7), 9) >>> 0;
        const t = s1 << 9;
        s2 ^= s0;
        s3 ^= s1;
        s1 ^= s2;
        s0 ^= s3;
        s2 ^= t;
        s3 = rotl(s3, 11);
        return result;
      },
      nextInt(max) {
        if (max <= 1) return 0;
        return (this.nextUint32() % max) >>> 0;
      },
      nextByte() {
        return (this.nextUint32() & 0xFF);
      },
      next2Bits() {
        return (this.nextUint32() & 0x03);
      }
    };
  },

  /**
   * Encrypt a single video frame with high throughput
   * Supports: '3stage' (Pixel shuffle + RGB perm + 2-MSB XOR), '2msb' (High speed MSB keystream), or 'block' (Macroblock 16x16 shuffle + 2-MSB XOR)
   */
  encryptVideoFrame(imageData, master32, frameIndex, mode = '3stage', cachedPerm = null) {
    const data = imageData.data;
    const width = imageData.width;
    const height = imageData.height;
    const totalPixels = width * height;

    let swappedCount = 0;
    let totalDiffSq = 0;

    if (mode === '2msb') {
      // High-speed 2-MSB XOR Stream Cipher
      const prng = this.getFramePRNG(master32, frameIndex, 3);
      for (let i = 0; i < totalPixels; i++) {
        const px = i * 4;
        const keyVal = prng.nextUint32();
        for (let c = 0; c < 3; c++) {
          const idx = px + c;
          const orig = data[idx];
          const key2 = (keyVal >>> (c * 2)) & 0x03;
          const enc = this.xor2MSB(orig, key2);
          data[idx] = enc;
          if (enc !== orig) swappedCount++;
          const diff = orig - enc;
          totalDiffSq += diff * diff;
        }
      }
    } else if (mode === 'block') {
      // Macroblock tile permutation (16x16) + 2-MSB XOR
      const blockSize = 16;
      const cols = Math.floor(width / blockSize);
      const rows = Math.floor(height / blockSize);
      const numBlocks = cols * rows;

      const prngBlock = this.getFramePRNG(master32, frameIndex, 1);
      const prngXor = this.getFramePRNG(master32, frameIndex, 3);

      const blockPerm = new Int32Array(numBlocks);
      for (let b = 0; b < numBlocks; b++) blockPerm[b] = b;
      for (let b = numBlocks - 1; b > 0; b--) {
        const j = prngBlock.nextInt(b + 1);
        const tmp = blockPerm[b];
        blockPerm[b] = blockPerm[j];
        blockPerm[j] = tmp;
      }

      const srcData = new Uint8ClampedArray(data);
      for (let srcB = 0; srcB < numBlocks; srcB++) {
        const dstB = blockPerm[srcB];
        const srcCol = srcB % cols;
        const srcRow = Math.floor(srcB / cols);
        const dstCol = dstB % cols;
        const dstRow = Math.floor(dstB / cols);

        for (let by = 0; by < blockSize; by++) {
          const srcY = srcRow * blockSize + by;
          const dstY = dstRow * blockSize + by;
          for (let bx = 0; bx < blockSize; bx++) {
            const srcX = srcCol * blockSize + bx;
            const dstX = dstCol * blockSize + bx;
            const srcIdx = (srcY * width + srcX) * 4;
            const dstIdx = (dstY * width + dstX) * 4;

            data[dstIdx] = srcData[srcIdx];
            data[dstIdx + 1] = srcData[srcIdx + 1];
            data[dstIdx + 2] = srcData[srcIdx + 2];
            data[dstIdx + 3] = srcData[srcIdx + 3];
          }
        }
      }

      for (let i = 0; i < totalPixels; i++) {
        const px = i * 4;
        const keyVal = prngXor.nextUint32();
        for (let c = 0; c < 3; c++) {
          const idx = px + c;
          const orig = srcData[idx];
          const cur = data[idx];
          const key2 = (keyVal >>> (c * 2)) & 0x03;
          const enc = this.xor2MSB(cur, key2);
          data[idx] = enc;
          if (enc !== orig) swappedCount++;
          const diff = orig - enc;
          totalDiffSq += diff * diff;
        }
      }
    } else {
      // mode === '3stage' (Full Pixel Shuffle + RGB Perm + 2-MSB XOR)
      const prngPixel = this.getFramePRNG(master32, frameIndex, 1);
      const prngChannel = this.getFramePRNG(master32, frameIndex, 2);
      const prngXor = this.getFramePRNG(master32, frameIndex, 3);

      let perm = cachedPerm;
      if (!perm || perm.length !== totalPixels) {
        perm = new Int32Array(totalPixels);
        for (let i = 0; i < totalPixels; i++) perm[i] = i;
        for (let i = totalPixels - 1; i > 0; i--) {
          const j = prngPixel.nextInt(i + 1);
          const tmp = perm[i];
          perm[i] = perm[j];
          perm[j] = tmp;
        }
      }

      const origData = new Uint8ClampedArray(data);
      const permData = new Uint8ClampedArray(data);

      for (let i = 0; i < totalPixels; i++) {
        const src = i * 4;
        const dst = perm[i] * 4;
        permData[dst] = origData[src];
        permData[dst + 1] = origData[src + 1];
        permData[dst + 2] = origData[src + 2];
        permData[dst + 3] = origData[src + 3];
      }

      for (let i = 0; i < totalPixels; i++) {
        const px = i * 4;
        const r = permData[px];
        const g = permData[px + 1];
        const b = permData[px + 2];
        const rgb = [r, g, b];

        const permId = prngChannel.nextInt(6);
        const pOrder = this.CHANNEL_PERMS[permId];

        const k2R = prngXor.next2Bits();
        const k2G = prngXor.next2Bits();
        const k2B = prngXor.next2Bits();

        const encR = this.xor2MSB(rgb[pOrder[0]], k2R);
        const encG = this.xor2MSB(rgb[pOrder[1]], k2G);
        const encB = this.xor2MSB(rgb[pOrder[2]], k2B);

        data[px] = encR;
        data[px + 1] = encG;
        data[px + 2] = encB;

        const origR = origData[px];
        const origG = origData[px + 1];
        const origB = origData[px + 2];

        if (encR !== origR) swappedCount++;
        if (encG !== origG) swappedCount++;
        if (encB !== origB) swappedCount++;

        totalDiffSq += (origR - encR) * (origR - encR);
        totalDiffSq += (origG - encG) * (origG - encG);
        totalDiffSq += (origB - encB) * (origB - encB);
      }
    }

    const channelCount = totalPixels * 3;
    const mse = channelCount > 0 ? (totalDiffSq / channelCount) : 0;
    const psnr = mse === 0 ? Infinity : 10 * Math.log10((255 * 255) / mse);

    return {
      swappedCount,
      mse: parseFloat(mse.toFixed(2)),
      psnr: psnr === Infinity ? '∞' : parseFloat(psnr.toFixed(2))
    };
  },

  /**
   * Decrypt a single video frame in reverse
   */
  decryptVideoFrame(imageData, master32, frameIndex, mode = '3stage', cachedPerm = null) {
    const data = imageData.data;
    const width = imageData.width;
    const height = imageData.height;
    const totalPixels = width * height;

    if (mode === '2msb') {
      const prng = this.getFramePRNG(master32, frameIndex, 3);
      for (let i = 0; i < totalPixels; i++) {
        const px = i * 4;
        const keyVal = prng.nextUint32();
        for (let c = 0; c < 3; c++) {
          const idx = px + c;
          const key2 = (keyVal >>> (c * 2)) & 0x03;
          data[idx] = this.xor2MSB(data[idx], key2);
        }
      }
    } else if (mode === 'block') {
      const blockSize = 16;
      const cols = Math.floor(width / blockSize);
      const rows = Math.floor(height / blockSize);
      const numBlocks = cols * rows;

      const prngBlock = this.getFramePRNG(master32, frameIndex, 1);
      const prngXor = this.getFramePRNG(master32, frameIndex, 3);

      for (let i = 0; i < totalPixels; i++) {
        const px = i * 4;
        const keyVal = prngXor.nextUint32();
        for (let c = 0; c < 3; c++) {
          const idx = px + c;
          const key2 = (keyVal >>> (c * 2)) & 0x03;
          data[idx] = this.xor2MSB(data[idx], key2);
        }
      }

      const blockPerm = new Int32Array(numBlocks);
      for (let b = 0; b < numBlocks; b++) blockPerm[b] = b;
      for (let b = numBlocks - 1; b > 0; b--) {
        const j = prngBlock.nextInt(b + 1);
        const tmp = blockPerm[b];
        blockPerm[b] = blockPerm[j];
        blockPerm[j] = tmp;
      }

      const copy = new Uint8ClampedArray(data);
      for (let srcB = 0; srcB < numBlocks; srcB++) {
        const dstB = blockPerm[srcB];
        const srcCol = srcB % cols;
        const srcRow = Math.floor(srcB / cols);
        const dstCol = dstB % cols;
        const dstRow = Math.floor(dstB / cols);

        for (let by = 0; by < blockSize; by++) {
          const origY = srcRow * blockSize + by;
          const encY = dstRow * blockSize + by;
          for (let bx = 0; bx < blockSize; bx++) {
            const origX = srcCol * blockSize + bx;
            const encX = dstCol * blockSize + bx;
            const encIdx = (encY * width + encX) * 4;
            const origIdx = (origY * width + origX) * 4;

            data[origIdx] = copy[encIdx];
            data[origIdx + 1] = copy[encIdx + 1];
            data[origIdx + 2] = copy[encIdx + 2];
            data[origIdx + 3] = copy[encIdx + 3];
          }
        }
      }
    } else {
      const prngPixel = this.getFramePRNG(master32, frameIndex, 1);
      const prngChannel = this.getFramePRNG(master32, frameIndex, 2);
      const prngXor = this.getFramePRNG(master32, frameIndex, 3);

      let perm = cachedPerm;
      if (!perm || perm.length !== totalPixels) {
        perm = new Int32Array(totalPixels);
        for (let i = 0; i < totalPixels; i++) perm[i] = i;
        for (let i = totalPixels - 1; i > 0; i--) {
          const j = prngPixel.nextInt(i + 1);
          const tmp = perm[i];
          perm[i] = perm[j];
          perm[j] = tmp;
        }
      }

      const unChannelData = new Uint8ClampedArray(data.length);
      for (let i = 0; i < totalPixels; i++) {
        const px = i * 4;
        const k2R = prngXor.next2Bits();
        const k2G = prngXor.next2Bits();
        const k2B = prngXor.next2Bits();

        const unXorR = this.xor2MSB(data[px], k2R);
        const unXorG = this.xor2MSB(data[px + 1], k2G);
        const unXorB = this.xor2MSB(data[px + 2], k2B);
        const rgb = [unXorR, unXorG, unXorB];

        const permId = prngChannel.nextInt(6);
        const invOrder = this.INV_CHANNEL_PERMS[permId];

        unChannelData[px] = rgb[invOrder[0]];
        unChannelData[px + 1] = rgb[invOrder[1]];
        unChannelData[px + 2] = rgb[invOrder[2]];
        unChannelData[px + 3] = data[px + 3];
      }

      for (let i = 0; i < totalPixels; i++) {
        const src = perm[i] * 4;
        const dst = i * 4;
        data[dst] = unChannelData[src];
        data[dst + 1] = unChannelData[src + 1];
        data[dst + 2] = unChannelData[src + 2];
        data[dst + 3] = unChannelData[src + 3];
      }
    }

    return { success: true };
  }

};

if (typeof window !== 'undefined') window.BitEngine = BitEngine;
if (typeof globalThis !== 'undefined') globalThis.BitEngine = BitEngine;
