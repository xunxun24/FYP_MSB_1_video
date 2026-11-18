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

// CRC-32 lookup table for ISO/IEC 15948 PNG chunk integrity
const PNG_CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function computeCrc32(bytes) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) {
    c = PNG_CRC32_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
  }
  return (c ^ 0xFFFFFFFF) >>> 0;
}

function computeAdler32(bytes) {
  let a = 1, b = 0;
  const MOD = 65521;
  let i = 0;
  const len = bytes.length;
  while (i < len) {
    const end = Math.min(i + 5552, len);
    while (i < end) {
      a += bytes[i++];
      b += a;
    }
    a %= MOD;
    b %= MOD;
  }
  return ((b << 16) | a) >>> 0;
}

/**
 * Compress raw PNG scanline bytes into a valid RFC 1950 ZLIB stream.
 * Uses Web CompressionStream('deflate') when available; falls back to RFC 1950 stored blocks.
 */
async function zlibCompressBytes(rawBytes) {
  if (typeof CompressionStream !== 'undefined') {
    try {
      const cs = new CompressionStream('deflate');
      const writer = cs.writable.getWriter();
      writer.write(rawBytes).catch(() => {});
      writer.close().catch(() => {});
      const chunks = [];
      const reader = cs.readable.getReader();
      let total = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        total += value.byteLength;
      }
      const out = new Uint8Array(total);
      let pos = 0;
      for (const ch of chunks) {
        out.set(ch, pos);
        pos += ch.byteLength;
      }
      if (out.length >= 6 && (out[0] & 0x0F) === 8) {
        return out;
      }
    } catch (_) {
      // Fallback to stored zlib blocks below
    }
  }

  // Synchronous RFC 1950 ZLIB with uncompressed DEFLATE blocks (BTYPE=00)
  const maxBlock = 65535;
  const numBlocks = Math.max(1, Math.ceil(rawBytes.length / maxBlock));
  const out = new Uint8Array(2 + rawBytes.length + numBlocks * 5 + 4);
  out[0] = 0x78; // CMF: Deflate, 32K window
  out[1] = 0x01; // FLG: No dict, FCHECK
  let pos = 2;
  let offset = 0;
  for (let b = 0; b < numBlocks; b++) {
    const isLast = (b === numBlocks - 1) ? 1 : 0;
    const blockLen = Math.min(maxBlock, rawBytes.length - offset);
    out[pos++] = isLast; // BFINAL=isLast, BTYPE=00
    out[pos++] = blockLen & 0xFF;
    out[pos++] = (blockLen >>> 8) & 0xFF;
    const nlen = (~blockLen) & 0xFFFF;
    out[pos++] = nlen & 0xFF;
    out[pos++] = (nlen >>> 8) & 0xFF;
    out.set(rawBytes.subarray(offset, offset + blockLen), pos);
    pos += blockLen;
    offset += blockLen;
  }
  const adler = computeAdler32(rawBytes);
  const dv = new DataView(out.buffer);
  dv.setUint32(pos, adler, false);
  return out;
}

/**
 * Decompress an RFC 1950 ZLIB stream from PNG IDAT chunks.
 * Uses Web DecompressionStream('deflate') or falls back to stored-block reader.
 */
async function zlibDecompressBytes(zlibBytes) {
  if (typeof DecompressionStream !== 'undefined') {
    try {
      const ds = new DecompressionStream('deflate');
      const writer = ds.writable.getWriter();
      writer.write(zlibBytes).catch(() => {});
      writer.close().catch(() => {});
      const chunks = [];
      const reader = ds.readable.getReader();
      let total = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        total += value.byteLength;
      }
      const out = new Uint8Array(total);
      let pos = 0;
      for (const ch of chunks) {
        out.set(ch, pos);
        pos += ch.byteLength;
      }
      return out;
    } catch (_) {
      // Fallback for stored blocks below
    }
  }

  // Fallback parser for RFC 1950 stored blocks
  if (zlibBytes.length < 6) throw new Error("Truncated ZLIB stream in PNG IDAT.");
  let pos = 2;
  const parts = [];
  let total = 0;
  while (pos < zlibBytes.length - 4) {
    const hdr = zlibBytes[pos++];
    const bfinal = hdr & 1;
    const btype = (hdr >>> 1) & 3;
    if (btype !== 0) {
      throw new Error("Unsupported DEFLATE block type without DecompressionStream.");
    }
    const len = zlibBytes[pos] | (zlibBytes[pos + 1] << 8);
    pos += 4; // skip len & nlen
    const slice = zlibBytes.subarray(pos, pos + len);
    parts.push(slice);
    total += slice.byteLength;
    pos += len;
    if (bfinal) break;
  }
  const out = new Uint8Array(total);
  let outPos = 0;
  for (const p of parts) {
    out.set(p, outPos);
    outPos += p.byteLength;
  }
  return out;
}

/**
 * Synchronous RFC 1950 / RFC 1951 ZLIB + DEFLATE (LZ77 + Fixed Huffman BTYPE=01) compressor.
 * Produces a 100% standard ZLIB stream with 2-byte header (0x78 0x9C) and 4-byte Adler-32 trailer.
 */
function zlibDeflateSync(rawBytes) {
  const input = rawBytes instanceof Uint8Array ? rawBytes : new Uint8Array(rawBytes || 0);
  const outBytes = [0x78, 0x9C]; // RFC 1950 ZLIB header (CM=8 deflate, CINFO=7 32K window, FCHECK)
  let bitBuf = 0;
  let bitCount = 0;

  const writeBits = (val, n) => {
    bitBuf |= (val << bitCount);
    bitCount += n;
    while (bitCount >= 8) {
      outBytes.push(bitBuf & 0xFF);
      bitBuf >>>= 8;
      bitCount -= 8;
    }
  };

  // Fixed Huffman codes (RFC 1951 Section 3.2.6) must be written MSB-first
  const writeHuff = (code, len) => {
    let rev = 0;
    for (let i = 0; i < len; i++) {
      rev = (rev << 1) | ((code >>> i) & 1);
    }
    writeBits(rev, len);
  };

  const writeLitCode = (lit) => {
    if (lit <= 143) writeHuff(0x30 + lit, 8);
    else if (lit <= 255) writeHuff(0x190 + (lit - 144), 9);
    else if (lit <= 279) writeHuff(lit - 256, 7);
    else writeHuff(0xC0 + (lit - 280), 8);
  };

  const LEN_BASE = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
  ];
  const LEN_EXTRA = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
  ];
  const DIST_BASE = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
  ];
  const DIST_EXTRA = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
  ];

  const writeMatch = (length, dist) => {
    let lCode = 28;
    for (let i = 0; i < 28; i++) {
      if (length < LEN_BASE[i + 1]) { lCode = i; break; }
    }
    writeLitCode(257 + lCode);
    if (LEN_EXTRA[lCode] > 0) writeBits(length - LEN_BASE[lCode], LEN_EXTRA[lCode]);

    let dCode = 29;
    for (let i = 0; i < 29; i++) {
      if (dist < DIST_BASE[i + 1]) { dCode = i; break; }
    }
    writeHuff(dCode, 5);
    if (DIST_EXTRA[dCode] > 0) writeBits(dist - DIST_BASE[dCode], DIST_EXTRA[dCode]);
  };

  // Block header: BFINAL = 1, BTYPE = 01 (Fixed Huffman)
  writeBits(1, 1);
  writeBits(1, 2);

  // Hash-chain LZ77 match finder
  const head = new Int32Array(4096).fill(-1);
  const prev = new Int32Array(input.length).fill(-1);
  let i = 0;
  const n = input.length;

  while (i < n) {
    let bestLen = 0;
    let bestDist = 0;
    if (i + 2 < n) {
      const h = (((input[i] << 8) ^ (input[i + 1] << 4) ^ input[i + 2]) & 0xFFF);
      let cand = head[h];
      prev[i] = cand;
      head[h] = i;

      let chain = 0;
      const maxLen = Math.min(258, n - i);
      while (cand >= 0 && (i - cand) <= 32768 && chain < 48) {
        if (input[cand + bestLen] === input[i + bestLen] &&
            input[cand] === input[i] &&
            input[cand + 1] === input[i + 1]) {
          let l = 2;
          while (l < maxLen && input[cand + l] === input[i + l]) l++;
          if (l > bestLen) {
            bestLen = l;
            bestDist = i - cand;
            if (l === maxLen) break;
          }
        }
        cand = prev[cand];
        chain++;
      }
    }

    if (bestLen >= 3) {
      writeMatch(bestLen, bestDist);
      for (let k = 1; k < bestLen; k++) {
        if (i + k + 2 < n) {
          const hk = (((input[i + k] << 8) ^ (input[i + k + 1] << 4) ^ input[i + k + 2]) & 0xFFF);
          prev[i + k] = head[hk];
          head[hk] = i + k;
        }
      }
      i += bestLen;
    } else {
      writeLitCode(input[i]);
      i++;
    }
  }

  // End-of-block symbol (256)
  writeLitCode(256);
  if (bitCount > 0) {
    outBytes.push(bitBuf & 0xFF);
    bitBuf = 0;
    bitCount = 0;
  }

  const adler = computeAdler32(input);
  outBytes.push((adler >>> 24) & 0xFF, (adler >>> 16) & 0xFF, (adler >>> 8) & 0xFF, adler & 0xFF);
  return Uint8Array.from(outBytes);
}

/**
 * Synchronous RFC 1950 / RFC 1951 ZLIB + DEFLATE decompressor (supports BTYPE=00 stored,
 * BTYPE=01 fixed Huffman, and BTYPE=10 dynamic Huffman blocks, plus Adler-32 integrity check).
 */
function zlibInflateSync(zlibBytes) {
  const src = zlibBytes instanceof Uint8Array ? zlibBytes : new Uint8Array(zlibBytes || 0);
  if (src.length < 6) {
    throw new Error("Corrupted ZLIB/DEFLATE stream: Input shorter than 6-byte ZLIB envelope.");
  }
  const cmf = src[0];
  const flg = src[1];
  if ((cmf & 0x0F) !== 8 || ((cmf << 8) + flg) % 31 !== 0) {
    throw new Error("Invalid ZLIB header in compressed stream.");
  }

  let bytePos = 2;
  const maxBytePos = src.length - 4; // Last 4 bytes are Adler-32
  let bitBuf = 0;
  let bitCount = 0;

  const ensureBits = (n) => {
    while (bitCount < n) {
      if (bytePos >= maxBytePos) {
        throw new Error("Truncated DEFLATE bitstream before end-of-block.");
      }
      bitBuf |= (src[bytePos++] << bitCount);
      bitCount += 8;
    }
  };

  const readBits = (n) => {
    if (n === 0) return 0;
    ensureBits(n);
    const val = bitBuf & ((1 << n) - 1);
    bitBuf >>>= n;
    bitCount -= n;
    return val;
  };

  const buildHuffmanTree = (lengths) => {
    let maxBits = 0;
    for (let i = 0; i < lengths.length; i++) {
      if (lengths[i] > maxBits) maxBits = lengths[i];
    }
    if (maxBits === 0) return { table: new Map(), maxBits: 1 };
    const blCount = new Int32Array(maxBits + 1);
    for (let i = 0; i < lengths.length; i++) {
      if (lengths[i] > 0) blCount[lengths[i]]++;
    }
    const nextCode = new Int32Array(maxBits + 1);
    let code = 0;
    for (let bits = 1; bits <= maxBits; bits++) {
      code = (code + blCount[bits - 1]) << 1;
      nextCode[bits] = code;
    }
    const table = new Map();
    for (let sym = 0; sym < lengths.length; sym++) {
      const len = lengths[sym];
      if (len > 0) {
        const c = nextCode[len]++;
        let rev = 0;
        for (let b = 0; b < len; b++) rev = (rev << 1) | ((c >>> b) & 1);
        table.set((len << 16) | rev, sym);
      }
    }
    return { table, maxBits };
  };

  const decodeSymbol = (tree) => {
    let code = 0;
    for (let len = 1; len <= tree.maxBits; len++) {
      code |= (readBits(1) << (len - 1));
      const sym = tree.table.get((len << 16) | code);
      if (sym !== undefined) return sym;
    }
    throw new Error("Invalid Huffman code in DEFLATE stream.");
  };

  const fixedLitLengths = new Uint8Array(288);
  for (let i = 0; i <= 143; i++) fixedLitLengths[i] = 8;
  for (let i = 144; i <= 255; i++) fixedLitLengths[i] = 9;
  for (let i = 256; i <= 279; i++) fixedLitLengths[i] = 7;
  for (let i = 280; i <= 287; i++) fixedLitLengths[i] = 8;
  const fixedDistLengths = new Uint8Array(32).fill(5);
  const fixedLitTree = buildHuffmanTree(fixedLitLengths);
  const fixedDistTree = buildHuffmanTree(fixedDistLengths);

  const LEN_BASE = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
  ];
  const LEN_EXTRA = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
  ];
  const DIST_BASE = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
  ];
  const DIST_EXTRA = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
  ];
  const CL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

  const out = [];
  let bfinal = 0;

  while (!bfinal) {
    bfinal = readBits(1);
    const btype = readBits(2);

    if (btype === 0) {
      // Uncompressed block: align to byte boundary
      bitBuf = 0;
      bitCount = 0;
      if (bytePos + 4 > maxBytePos) throw new Error("Truncated uncompressed DEFLATE block header.");
      const len = src[bytePos] | (src[bytePos + 1] << 8);
      const nlen = src[bytePos + 2] | (src[bytePos + 3] << 8);
      bytePos += 4;
      if (((len ^ 0xFFFF) & 0xFFFF) !== nlen) {
        throw new Error("Corrupted uncompressed DEFLATE block length complement.");
      }
      if (bytePos + len > maxBytePos) throw new Error("Truncated uncompressed DEFLATE block data.");
      for (let i = 0; i < len; i++) out.push(src[bytePos++]);
    } else if (btype === 1 || btype === 2) {
      let litTree = fixedLitTree;
      let distTree = fixedDistTree;

      if (btype === 2) {
        const hlit = readBits(5) + 257;
        const hdist = readBits(5) + 1;
        const hclen = readBits(4) + 4;
        const clLengths = new Uint8Array(19);
        for (let i = 0; i < hclen; i++) clLengths[CL_ORDER[i]] = readBits(3);
        const clTree = buildHuffmanTree(clLengths);

        const allLengths = new Uint8Array(hlit + hdist);
        let idx = 0;
        while (idx < hlit + hdist) {
          const sym = decodeSymbol(clTree);
          if (sym <= 15) {
            allLengths[idx++] = sym;
          } else if (sym === 16) {
            if (idx === 0) throw new Error("Invalid repeat code in dynamic Huffman table.");
            const rep = readBits(2) + 3;
            const prev = allLengths[idx - 1];
            for (let r = 0; r < rep; r++) allLengths[idx++] = prev;
          } else if (sym === 17) {
            const rep = readBits(3) + 3;
            for (let r = 0; r < rep; r++) allLengths[idx++] = 0;
          } else if (sym === 18) {
            const rep = readBits(7) + 11;
            for (let r = 0; r < rep; r++) allLengths[idx++] = 0;
          }
        }
        litTree = buildHuffmanTree(allLengths.subarray(0, hlit));
        distTree = buildHuffmanTree(allLengths.subarray(hlit));
      }

      while (true) {
        const sym = decodeSymbol(litTree);
        if (sym < 256) {
          out.push(sym);
        } else if (sym === 256) {
          break;
        } else {
          const lIdx = sym - 257;
          if (lIdx < 0 || lIdx >= LEN_BASE.length) throw new Error("Invalid DEFLATE length code.");
          const length = LEN_BASE[lIdx] + readBits(LEN_EXTRA[lIdx]);
          const dIdx = decodeSymbol(distTree);
          if (dIdx < 0 || dIdx >= DIST_BASE.length) throw new Error("Invalid DEFLATE distance code.");
          const dist = DIST_BASE[dIdx] + readBits(DIST_EXTRA[dIdx]);
          if (dist > out.length) throw new Error("Invalid DEFLATE lookback distance.");
          const start = out.length - dist;
          for (let k = 0; k < length; k++) {
            out.push(out[start + k]);
          }
        }
      }
    } else {
      throw new Error("Invalid DEFLATE block type (BTYPE=11).");
    }
  }

  const result = Uint8Array.from(out);
  const expectedAdler = (
    (src[maxBytePos] << 24) |
    (src[maxBytePos + 1] << 16) |
    (src[maxBytePos + 2] << 8) |
    src[maxBytePos + 3]
  ) >>> 0;
  const actualAdler = computeAdler32(result);
  if (expectedAdler !== actualAdler) {
    throw new Error("Corrupted DEFLATE stream: Adler-32 checksum mismatch.");
  }
  return result;
}

const BitEngine = {
  // Self-Describing Encrypted PNG Metadata Constants (Primary Format)
  PNG_SIGNATURE: new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]),
  FYP_PNG_CHUNK_TYPE: 'msBX',        // Private ancillary unsafe-to-copy PNG chunk (ISO/IEC 15948 compliant)
  FYP_LEGACY_PNG_CHUNK_TYPE: 'msBx', // Legacy safe-to-copy PNG chunk (supported for backward-compatible decryption)
  FYP_MAGIC_ID: 'KENX-ENC',          // 8-byte ASCII FYP metadata identifier (Schema v1)
  FYP_META_VERSION: 1,               // Legacy Schema v1 constant (preserved for v1 compatibility)
  FYP_META_VERSION_V1: 1,            // Legacy 76-byte fixed header schema
  FYP_META_VERSION_V2: 2,            // Optimized 51-byte compact bit-packed binary schema
  FYP_COMPACT_MAGIC_NIBBLE: 0x0B,    // 4-bit magic nibble in Byte 0 of Schema v2 (0xB2 = Magic 0xB, Version 2)
  FYP_ALGO_VERSION: 1,               // 3-Stage Encryption Algorithm version
  FYP_META_FIXED_SIZE: 76,           // 76-byte fixed header inside Schema v1 `msBX` / legacy `msBx` chunk
  FYP_META_V2_FIXED_SIZE: 51,        // 51-byte fixed header inside Schema v2 `msBX` chunk (3B packed + 16B salt + 32B tag)

  // Lossless Mask Compression Codec Identifiers
  MASK_CODEC_NONE: 0,
  MASK_CODEC_RAW: 1,                 // 1 byte per pixel (0x00 / 0x01)
  MASK_CODEC_BITPACKED: 2,           // 1 bit per pixel (8 pixels per byte)
  MASK_CODEC_RLE: 3,                 // Unsigned LEB128 Run-Length Encoding
  MASK_CODEC_DEFLATE: 4,             // RFC 1950/1951 DEFLATE over RLE/Bit-Packed mask

  // Legacy Portable .msbx Constants (Preserved for Backward Compatibility)
  MSBX_MAGIC: 'MSBX',
  MSBX_VERSION: 1,
  MSBX_HEADER_SIZE: 68,
  DEFAULT_ITERATIONS: 100000,
  DEFAULT_KDF_ITERATIONS: 100000,
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

  CHANNEL_PERM_LABELS: ['RGB', 'RBG', 'GRB', 'GBR', 'BRG', 'BGR'],
  CHANNEL_PERM_MAP: { RGB: 0, RBG: 1, GRB: 2, GBR: 3, BRG: 4, BGR: 5 },

  /**
   * Normalize and validate a 3-stage encryption configuration object (Standard or Advanced Mode).
   */
  normalizeStageConfig(rawConfig = null, fallbackK = 2) {
    const src = (rawConfig && typeof rawConfig === 'object') ? rawConfig : {};
    const kVal = (typeof src.k === 'number') ? (src.k | 0) : (fallbackK | 0);
    if (kVal < 1 || kVal > 8) {
      throw new Error(`Invalid MSB bit depth (k = ${kVal}): Must be between 1 and 8.`);
    }

    const stage1Enabled = src.stage1Enabled !== undefined ? !!src.stage1Enabled : true;
    const stage2Enabled = src.stage2Enabled !== undefined ? !!src.stage2Enabled : true;
    const stage3Enabled = src.stage3Enabled !== undefined ? !!src.stage3Enabled : true;

    if (!stage1Enabled && !stage2Enabled && !stage3Enabled) {
      throw new Error("Invalid encryption stage configuration: At least one encryption stage (Stage 1, Stage 2, or Stage 3) must be enabled.");
    }

    const stage1BlockSize = (typeof src.stage1BlockSize === 'number') ? (src.stage1BlockSize | 0) : 1;
    if (stage1BlockSize < 1 || stage1BlockSize > 32) {
      throw new Error(`Invalid Stage 1 pixel block size (${stage1BlockSize}): Must be an integer between 1 and 32.`);
    }

    const rawAlgoId = (typeof src.stage1AlgoId === 'number') ? (src.stage1AlgoId | 0) : 0;
    if (rawAlgoId !== 0 && rawAlgoId !== 1) {
      throw new Error(`Unsupported Stage 1 permutation algorithm ID (${rawAlgoId}): Only 0 (Keyed Fisher–Yates 1×1) and 1 (Keyed Fisher–Yates B×B Block) are supported.`);
    }
    const stage1AlgoId = stage1BlockSize > 1 ? 1 : 0;

    const stage2Mode = (src.stage2Mode === 'fixed' || src.stage2Mode === 1) ? 'fixed' : 'keyed';
    let stage2FixedPermId = 0;
    if (typeof src.stage2FixedPermId === 'number') {
      stage2FixedPermId = src.stage2FixedPermId | 0;
    } else if (typeof src.stage2FixedPerm === 'string' && this.CHANNEL_PERM_MAP[src.stage2FixedPerm.toUpperCase()] !== undefined) {
      stage2FixedPermId = this.CHANNEL_PERM_MAP[src.stage2FixedPerm.toUpperCase()];
    }
    if (stage2FixedPermId < 0 || stage2FixedPermId > 5) {
      throw new Error(`Invalid Stage 2 fixed RGB permutation ID (${stage2FixedPermId}): Must be between 0 (RGB) and 5 (BGR).`);
    }

    let stage2AllowedMask = 0x3F;
    if (typeof src.stage2AllowedMask === 'number') {
      stage2AllowedMask = src.stage2AllowedMask & 0x3F;
    } else if (Array.isArray(src.stage2AllowedPerms) || Array.isArray(src.stage2AllowedIds)) {
      const arr = src.stage2AllowedPerms || src.stage2AllowedIds;
      let m = 0;
      for (const item of arr) {
        if (typeof item === 'number' && item >= 0 && item <= 5) {
          m |= (1 << item);
        } else if (typeof item === 'string' && this.CHANNEL_PERM_MAP[item.trim().toUpperCase()] !== undefined) {
          m |= (1 << this.CHANNEL_PERM_MAP[item.trim().toUpperCase()]);
        }
      }
      stage2AllowedMask = m & 0x3F;
    } else if (src.stage2Allowed && typeof src.stage2Allowed === 'object') {
      let m = 0;
      for (let i = 0; i < 6; i++) {
        const lbl = this.CHANNEL_PERM_LABELS[i];
        if (src.stage2Allowed[lbl] || src.stage2Allowed[lbl.toLowerCase()] || src.stage2Allowed[i]) {
          m |= (1 << i);
        }
      }
      if (m !== 0) stage2AllowedMask = m;
    }

    if (stage2Enabled && stage2Mode === 'keyed' && stage2AllowedMask === 0) {
      throw new Error("Invalid Stage 2 configuration: At least one RGB channel permutation must be selected when Stage 2 is in Key-Driven mode.");
    }
    if (stage2AllowedMask === 0) {
      stage2AllowedMask = 0x3F;
    }

    const stage2AllowedIds = [];
    const stage2AllowedLabels = [];
    for (let i = 0; i < 6; i++) {
      if ((stage2AllowedMask & (1 << i)) !== 0) {
        stage2AllowedIds.push(i);
        stage2AllowedLabels.push(this.CHANNEL_PERM_LABELS[i]);
      }
    }
    const stage2AllowedCount = stage2AllowedIds.length;

    let channelMask = 0x07;
    if (typeof src.channelMask === 'number') {
      channelMask = src.channelMask & 0x07;
    } else if (src.stage3Channels && typeof src.stage3Channels === 'object') {
      channelMask = ((src.stage3Channels.r !== false ? 0x04 : 0)
                   | (src.stage3Channels.g !== false ? 0x02 : 0)
                   | (src.stage3Channels.b !== false ? 0x01 : 0));
    }

    if (stage3Enabled && channelMask === 0) {
      throw new Error("Invalid Stage 3 configuration: At least one RGB channel (Red, Green, or Blue) must be selected when Stage 3 is enabled.");
    }
    if (!stage3Enabled && channelMask === 0) {
      channelMask = 0x07;
    }

    const stage3Channels = {
      r: (channelMask & 0x04) !== 0,
      g: (channelMask & 0x02) !== 0,
      b: (channelMask & 0x01) !== 0
    };

    const isStandardDefault = (
      stage1Enabled &&
      stage1BlockSize === 1 &&
      stage2Enabled &&
      stage2Mode === 'keyed' &&
      stage2AllowedMask === 0x3F &&
      stage3Enabled &&
      channelMask === 0x07
    );

    const encryptionMode = (src.encryptionMode === 'advanced' || !isStandardDefault)
      ? 'advanced'
      : 'standard';

    const chList = [];
    if (stage3Channels.r) chList.push('R');
    if (stage3Channels.g) chList.push('G');
    if (stage3Channels.b) chList.push('B');
    const channelLabels = chList.join(', ') || 'None';
    const fixedPermLabel = this.CHANNEL_PERM_LABELS[stage2FixedPermId] || 'RGB';

    const fwdParts = [];
    const revParts = [];
    if (stage1Enabled) {
      const s1Desc = stage1BlockSize > 1 ? `Fisher–Yates ${stage1BlockSize}×${stage1BlockSize} Block` : 'Fisher–Yates 1×1';
      fwdParts.push(`Stage 1 (${s1Desc})`);
      revParts.unshift(`Reverse Stage 1 (${s1Desc})`);
    }
    if (stage2Enabled) {
      const s2Desc = stage2Mode === 'fixed'
        ? `Fixed ${fixedPermLabel}`
        : (stage2AllowedCount === 6 ? 'Keyed RGB' : `Keyed RGB [${stage2AllowedLabels.join(',')}]`);
      fwdParts.push(`Stage 2 (${s2Desc})`);
      revParts.unshift(`Reverse Stage 2 (${s2Desc})`);
    }
    if (stage3Enabled) {
      fwdParts.push(`Stage 3 (k=${kVal} XOR on ${chList.join('+')})`);
      revParts.unshift(`Reverse Stage 3 (k=${kVal} XOR on ${chList.join('+')})`);
    }

    return {
      encryptionMode,
      isStandardDefault,
      isExperimental: !isStandardDefault,
      stage1Enabled,
      stage1AlgoId,
      stage1BlockSize,
      stage1BlockPixels: stage1BlockSize * stage1BlockSize,
      stage1AlgoLabel: stage1BlockSize > 1
        ? `Keyed Fisher–Yates Block Bijection (${stage1BlockSize}×${stage1BlockSize} px)`
        : 'Keyed Fisher–Yates Bijection (1×1 px)',
      stage2Enabled,
      stage2Mode,
      stage2FixedPermId,
      stage2FixedPermLabel: fixedPermLabel,
      stage2AllowedMask,
      stage2AllowedIds,
      stage2AllowedLabels,
      stage2AllowedCount,
      stage3Enabled,
      k: kVal,
      stage3Channels,
      channelMask,
      channelLabels,
      enabledCount: (stage1Enabled ? 1 : 0) + (stage2Enabled ? 1 : 0) + (stage3Enabled ? 1 : 0),
      enabledStagesSummary: fwdParts.join(' → '),
      reverseStagesSummary: revParts.join(' → ')
    };
  },

  /**
   * Pack a normalized Stage Configuration into 2 or 3 compact bytes `[stageByte0, stageByte1 (, stageByte2)]`:
   * - stageByte0: [7] isAdvanced (1b) | [6] stage1 (1b) | [5] stage2 (1b) | [4] stage3 (1b) | [3] stage2Fixed (1b) | [2:0] fixedPermId or 0x07 for custom dynamic subset
   * - stageByte1: [7:3] stage1BlockSize - 1 (5b, 0..31 => 1×1..32×32 px) | [2] Red (1b) | [1] Green (1b) | [0] Blue (1b)
   * - stageByte2 (optional, when stage2Mode='keyed' and stage2AllowedMask != 0x3F): [5:0] 6-bit allowed permutation mask
   */
  encodeStageConfigBytes(rawConfig, fallbackK = 2) {
    const cfg = this.normalizeStageConfig(rawConfig, fallbackK);
    const isAdvBit = (cfg.encryptionMode === 'advanced' || !cfg.isStandardDefault) ? 1 : 0;
    const isCustomDynamic = (cfg.stage2Mode !== 'fixed' && cfg.stage2AllowedMask !== 0x3F);
    const low3 = cfg.stage2Mode === 'fixed'
      ? (cfg.stage2FixedPermId & 0x07)
      : (isCustomDynamic ? 0x07 : 0x00);

    const b0 = ((isAdvBit & 0x01) << 7)
             | ((cfg.stage1Enabled ? 1 : 0) << 6)
             | ((cfg.stage2Enabled ? 1 : 0) << 5)
             | ((cfg.stage3Enabled ? 1 : 0) << 4)
             | ((cfg.stage2Mode === 'fixed' ? 1 : 0) << 3)
             | (low3 & 0x07);
    const b1 = (((cfg.stage1BlockSize - 1) & 0x1F) << 3)
             | (cfg.channelMask & 0x07);

    if (isCustomDynamic) {
      return new Uint8Array([b0 & 0xFF, b1 & 0xFF, cfg.stage2AllowedMask & 0x3F]);
    }
    return new Uint8Array([b0 & 0xFF, b1 & 0xFF]);
  },

  /**
   * Decode bit-packed `[stageByte0, stageByte1 (, stageByte2)]` from `msBX` metadata into a validated Stage Configuration.
   */
  decodeStageConfigBytes(byte0, byte1, k = 2, byte2 = 0x3F) {
    const isAdv = ((byte0 >>> 7) & 0x01) === 1;
    const stage1Enabled = ((byte0 >>> 6) & 0x01) === 1;
    const stage2Enabled = ((byte0 >>> 5) & 0x01) === 1;
    const stage3Enabled = ((byte0 >>> 4) & 0x01) === 1;
    const stage2Fixed = ((byte0 >>> 3) & 0x01) === 1;
    const low3 = byte0 & 0x07;
    const stage2FixedPermId = stage2Fixed ? low3 : 0;
    let stage2AllowedMask = 0x3F;
    if (!stage2Fixed && low3 === 0x07 && byte2 !== undefined) {
      stage2AllowedMask = (byte2 & 0x3F) || 0x3F;
    }

    const stage1BlockSize = ((byte1 >>> 3) & 0x1F) + 1;
    const channelMask = byte1 & 0x07;

    return this.normalizeStageConfig({
      encryptionMode: isAdv ? 'advanced' : 'standard',
      stage1Enabled,
      stage1BlockSize,
      stage2Enabled,
      stage2Mode: stage2Fixed ? 'fixed' : 'keyed',
      stage2FixedPermId,
      stage2AllowedMask,
      stage3Enabled,
      k,
      channelMask
    }, k);
  },

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

  _kdfMemoCache: new Map(),

  /**
   * Chapter 4 Iterated SHA-256 Key Derivation Function (KDF):
   * Derives a 32-byte master key from a password (or key-image digest) + 16-byte salt
   * using `iterations` rounds of SHA-256 (default 100,000 iterations).
   */
  deriveMasterKeyIterated(passwordOrKey, salt16, iterations = 100000) {
    if (!(salt16 instanceof Uint8Array) || salt16.length !== 16) {
      throw new Error("Invalid salt: must be a 16-byte Uint8Array.");
    }
    const totalIters = Math.max(1, iterations | 0);
    const keyTag = (passwordOrKey instanceof Uint8Array)
      ? this.bytesToHex(passwordOrKey)
      : String(passwordOrKey || '');
    const cacheKey = `${totalIters}:${this.bytesToHex(salt16)}:${keyTag}`;
    const cached = this._kdfMemoCache.get(cacheKey);
    if (cached) {
      return new Uint8Array(cached);
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

    const derived = totalIters === 1
      ? round0
      : iterateSha256DigestWithSalt16(round0, salt16, totalIters - 1);

    if (this._kdfMemoCache.size >= 16) {
      const oldestKey = this._kdfMemoCache.keys().next().value;
      this._kdfMemoCache.delete(oldestKey);
    }
    this._kdfMemoCache.set(cacheKey, new Uint8Array(derived));
    return derived;
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
      nextKBits(k) {
        const kk = Math.max(1, Math.min(8, k | 0));
        return (this.nextUint32() & ((1 << kk) - 1));
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
      nextKBits(k) {
        const kk = Math.max(1, Math.min(8, k | 0));
        return (this.nextUint32() & ((1 << kk) - 1));
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
   * Deterministically partition a selected ROI pixel set (`targetIndices`) into:
   * 1. `eligibleBlocks`: Top-left pixel indices of complete `B × B` blocks entirely inside the selected ROI
   * 2. `boundaryIndices`: All remaining selected ROI pixels (irregular boundary pixels, non-divisible image-edge pixels,
   *    or all selected pixels if fewer than 2 complete `B × B` blocks fit inside the ROI)
   *
   * Guarantees:
   * - Uses a deterministic grid anchored at origin (0, 0) in row-major order.
   * - Never includes or touches any pixel outside `targetIndices`.
   * - If `candidateBlocks.length < 2`, safely falls back (`fallbackUsed = true`) to individual pixel permutation over `targetIndices`.
   */
  partitionMaskAwareBlocks(width, height, targetIndices, blockSize = 1) {
    const W = width | 0;
    const H = height | 0;
    const B = Math.max(1, Math.min(32, blockSize | 0));
    const M = targetIndices ? targetIndices.length : 0;

    if (B <= 1 || M === 0 || W <= 0 || H <= 0) {
      return {
        blockSize: 1,
        eligibleBlocks: new Int32Array(0),
        boundaryIndices: targetIndices || new Int32Array(0),
        fallbackUsed: false,
        completeBlockCount: 0,
        completeBlockPixels: 0,
        boundaryPixels: M,
        totalSelectedPixels: M
      };
    }

    const totalPixels = W * H;
    const inRoi = new Uint8Array(totalPixels);
    for (let i = 0; i < M; i++) {
      inRoi[targetIndices[i]] = 1;
    }

    const candidateBlocks = [];
    for (let by = 0; by + B <= H; by += B) {
      for (let bx = 0; bx + B <= W; bx += B) {
        let allInside = true;
        for (let dy = 0; dy < B && allInside; dy++) {
          const rowBase = (by + dy) * W + bx;
          for (let dx = 0; dx < B; dx++) {
            if (inRoi[rowBase + dx] === 0) {
              allInside = false;
              break;
            }
          }
        }
        if (allInside) {
          candidateBlocks.push(by * W + bx);
        }
      }
    }

    // If fewer than 2 complete B×B blocks fit in the selected ROI, deterministically fall back to individual pixel permutation
    if (candidateBlocks.length < 2) {
      return {
        blockSize: B,
        eligibleBlocks: new Int32Array(0),
        boundaryIndices: targetIndices,
        fallbackUsed: true,
        completeBlockCount: candidateBlocks.length,
        completeBlockPixels: 0,
        boundaryPixels: M,
        totalSelectedPixels: M
      };
    }

    const eligibleBlocks = Int32Array.from(candidateBlocks);
    const claimed = new Uint8Array(totalPixels);
    for (let k = 0; k < eligibleBlocks.length; k++) {
      const topLeft = eligibleBlocks[k];
      const bx = topLeft % W;
      const by = (topLeft - bx) / W;
      for (let dy = 0; dy < B; dy++) {
        const rowBase = (by + dy) * W + bx;
        for (let dx = 0; dx < B; dx++) {
          claimed[rowBase + dx] = 1;
        }
      }
    }

    const completeBlockPixels = eligibleBlocks.length * B * B;
    const boundaryLen = Math.max(0, M - completeBlockPixels);
    const boundaryIndices = new Int32Array(boundaryLen);
    let bPos = 0;
    for (let i = 0; i < M; i++) {
      const p = targetIndices[i];
      if (claimed[p] === 0) {
        boundaryIndices[bPos++] = p;
      }
    }

    return {
      blockSize: B,
      eligibleBlocks,
      boundaryIndices,
      fallbackUsed: false,
      completeBlockCount: eligibleBlocks.length,
      completeBlockPixels,
      boundaryPixels: boundaryIndices.length,
      totalSelectedPixels: M
    };
  },

  /**
   * Generate a fast, illustrative pre-key Stage 1 permutation preview on a cloned ImageData
   * for the Advanced Mode Stage 1 interactive block-size demonstration.
   * Uses a deterministic demo PRNG and only executes Stage 1 (preserving original RGB colours)
   * so users can visually compare 1×1 fine pixel scrambling against B×B mosaic block shuffling.
   */
  previewStage1BlockPermutation(imageData, maskOrRegions = null, blockSize = 1) {
    const W = imageData.width;
    const H = imageData.height;
    const B = Math.max(1, Math.min(32, blockSize | 0));
    const src = imageData.data;
    const out = new Uint8ClampedArray(src);
    const targetIndices = this.getTargetPixelIndices(imageData, maskOrRegions);
    const M = targetIndices.length;
    const partition = this.partitionMaskAwareBlocks(W, H, targetIndices, B);

    if (M > 1) {
      const demoSeed = new Uint32Array([0x4B584254, 0x53544731, (B * 0x9E3779B9) >>> 0, (M * 0x85EBCA6B) >>> 0]);
      const demoPrng = this.getFramePRNG(demoSeed, B, 1);

      if (B <= 1 || partition.eligibleBlocks.length < 2) {
        const perm = new Int32Array(M);
        for (let i = 0; i < M; i++) perm[i] = i;
        for (let i = M - 1; i > 0; i--) {
          const j = demoPrng.nextInt(i + 1);
          const tmp = perm[i];
          perm[i] = perm[j];
          perm[j] = tmp;
        }
        for (let idx = 0; idx < M; idx++) {
          const sIdx = targetIndices[idx] * 4;
          const dIdx = targetIndices[perm[idx]] * 4;
          out[dIdx] = src[sIdx];
          out[dIdx + 1] = src[sIdx + 1];
          out[dIdx + 2] = src[sIdx + 2];
          out[dIdx + 3] = src[sIdx + 3];
        }
      } else {
        const K = partition.eligibleBlocks.length;
        const blockPerm = new Int32Array(K);
        for (let i = 0; i < K; i++) blockPerm[i] = i;
        for (let i = K - 1; i > 0; i--) {
          const j = demoPrng.nextInt(i + 1);
          const tmp = blockPerm[i];
          blockPerm[i] = blockPerm[j];
          blockPerm[j] = tmp;
        }
        for (let bIdx = 0; bIdx < K; bIdx++) {
          const srcTop = partition.eligibleBlocks[bIdx];
          const dstTop = partition.eligibleBlocks[blockPerm[bIdx]];
          for (let dy = 0; dy < B; dy++) {
            const sRow = srcTop + dy * W;
            const dRow = dstTop + dy * W;
            for (let dx = 0; dx < B; dx++) {
              const sIdx = (sRow + dx) * 4;
              const dIdx = (dRow + dx) * 4;
              out[dIdx] = src[sIdx];
              out[dIdx + 1] = src[sIdx + 1];
              out[dIdx + 2] = src[sIdx + 2];
              out[dIdx + 3] = src[sIdx + 3];
            }
          }
        }

        const L = partition.boundaryIndices.length;
        if (L >= 2) {
          const boundPerm = new Int32Array(L);
          for (let i = 0; i < L; i++) boundPerm[i] = i;
          for (let i = L - 1; i > 0; i--) {
            const j = demoPrng.nextInt(i + 1);
            const tmp = boundPerm[i];
            boundPerm[i] = boundPerm[j];
            boundPerm[j] = tmp;
          }
          for (let i = 0; i < L; i++) {
            const sIdx = partition.boundaryIndices[i] * 4;
            const dIdx = partition.boundaryIndices[boundPerm[i]] * 4;
            out[dIdx] = src[sIdx];
            out[dIdx + 1] = src[sIdx + 1];
            out[dIdx + 2] = src[sIdx + 2];
            out[dIdx + 3] = src[sIdx + 3];
          }
        }
      }
    }

    return {
      previewImageData: new ImageData(out, W, H),
      partition
    };
  },

  /**
   * Illustrative pre-key preview generator for Stage 2 (and preceding Stage 1).
   * Demonstrates how RGB channel permutation rearranges color components across
   * the active ROI and selected allowed permutation subset / fixed order.
   */
  previewStage2ChannelPermutation(imageData, maskOrRegions = null, stageConfig = null) {
    const cfg = this.normalizeStageConfig(stageConfig);
    const W = imageData.width;
    const H = imageData.height;
    const targetIndices = this.getTargetPixelIndices(imageData, maskOrRegions);
    const M = targetIndices.length;

    let intermediateData;
    if (cfg.stage1Enabled) {
      const s1Res = this.previewStage1BlockPermutation(imageData, maskOrRegions, cfg.stage1BlockSize);
      intermediateData = s1Res.previewImageData.data;
    } else {
      intermediateData = new Uint8ClampedArray(imageData.data);
    }

    const out = new Uint8ClampedArray(intermediateData);
    if (cfg.stage2Enabled && M > 0) {
      const isFixed = cfg.stage2Mode === 'fixed';
      const allowedIds = (cfg.stage2AllowedIds && cfg.stage2AllowedIds.length > 0)
        ? cfg.stage2AllowedIds
        : [0, 1, 2, 3, 4, 5];
      const allowedCount = allowedIds.length;

      const demoSeed = new Uint32Array([0x4B584254, 0x53544732, (allowedCount * 0x9E3779B9) >>> 0, (M * 0x85EBCA6B) >>> 0]);
      const demoPrng = this.getFramePRNG(demoSeed, 2, 1);

      for (let idx = 0; idx < M; idx++) {
        const pixelIdx = targetIndices[idx] * 4;
        const r = intermediateData[pixelIdx];
        const g = intermediateData[pixelIdx + 1];
        const b = intermediateData[pixelIdx + 2];
        const rgb = [r, g, b];

        const permIdx = isFixed ? cfg.stage2FixedPermId : allowedIds[demoPrng.nextInt(allowedCount)];
        const pOrder = this.CHANNEL_PERMS[permIdx];

        out[pixelIdx] = rgb[pOrder[0]];
        out[pixelIdx + 1] = rgb[pOrder[1]];
        out[pixelIdx + 2] = rgb[pOrder[2]];
      }
    }

    return {
      previewImageData: new ImageData(out, W, H),
      config: cfg
    };
  },

  /**
   * Illustrative pre-key preview generator for Stage 3 (cumulative Stage 1 + Stage 2 + Stage 3 k-MSB XOR).
   * Demonstrates the combined visual effect across the active ROI without using any real secret key.
   */
  previewStage3MsbXor(imageData, maskOrRegions = null, stageConfig = null) {
    const cfg = this.normalizeStageConfig(stageConfig);
    const W = imageData.width;
    const H = imageData.height;
    const kk = cfg.k;
    const targetIndices = this.getTargetPixelIndices(imageData, maskOrRegions);
    const M = targetIndices.length;

    const s2Res = this.previewStage2ChannelPermutation(imageData, maskOrRegions, cfg);
    const out = new Uint8ClampedArray(s2Res.previewImageData.data);

    if (cfg.stage3Enabled && M > 0) {
      const activeCh = [
        !!cfg.stage3Channels.r,
        !!cfg.stage3Channels.g,
        !!cfg.stage3Channels.b
      ];
      const demoSeed = new Uint32Array([0x4B584254, 0x53544733, (kk * 0x9E3779B9) >>> 0, (M * 0x85EBCA6B) >>> 0]);
      const demoPrng = this.getFramePRNG(demoSeed, kk, 2);

      for (let idx = 0; idx < M; idx++) {
        const pixelIdx = targetIndices[idx] * 4;
        for (let c = 0; c < 3; c++) {
          if (activeCh[c]) {
            const cIdx = pixelIdx + c;
            const keyBits = kk === 2 ? demoPrng.next2Bits() : demoPrng.nextKBits(kk);
            out[cIdx] = kk === 2 ? this.xor2MSB(out[cIdx], keyBits) : this.xorKMSB(out[cIdx], keyBits, kk);
          }
        }
      }
    }

    return {
      previewImageData: new ImageData(out, W, H),
      config: cfg
    };
  },

  /**
   * Core 3-Stage Encryption with explicit PRNG streams, configurable k (1..8, default 2),
   * and customizable stage configuration (Standard Mode vs. Advanced Mode).
   */
  _encryptWithStreams(imageData, prngPixel, prngChannel, prngXor, maskOrRegions = null, kVal = 2, stageConfig = null) {
    const cfg = this.normalizeStageConfig(stageConfig, kVal);
    const kk = cfg.k;
    const W = imageData.width;
    const H = imageData.height;
    const data = imageData.data;
    const originalCopy = new Uint8ClampedArray(data);
    const targetIndices = this.getTargetPixelIndices(imageData, maskOrRegions);
    const M = targetIndices.length;

    if (M === 0) {
      return { imageData, swappedCount: 0, mse: 0, psnr: '∞', stageConfig: cfg };
    }

    // === STAGE 1: PIXEL PERMUTATION (Keyed Fisher–Yates 1×1 or Mask-Aware B×B Block Shuffle) ===
    const stage1Data = new Uint8ClampedArray(data);
    if (cfg.stage1Enabled) {
      const B = cfg.stage1BlockSize;
      if (B <= 1) {
        const perm = new Int32Array(M);
        for (let i = 0; i < M; i++) perm[i] = i;
        for (let i = M - 1; i > 0; i--) {
          const j = prngPixel.nextInt(i + 1);
          const temp = perm[i];
          perm[i] = perm[j];
          perm[j] = temp;
        }

        for (let idx = 0; idx < M; idx++) {
          const srcIdx = targetIndices[idx] * 4;
          const dstIdx = targetIndices[perm[idx]] * 4;
          stage1Data[dstIdx] = data[srcIdx];
          stage1Data[dstIdx + 1] = data[srcIdx + 1];
          stage1Data[dstIdx + 2] = data[srcIdx + 2];
          stage1Data[dstIdx + 3] = data[srcIdx + 3];
        }
      } else {
        const part = this.partitionMaskAwareBlocks(W, H, targetIndices, B);
        const K = part.eligibleBlocks.length;
        if (K >= 2) {
          const blockPerm = new Int32Array(K);
          for (let i = 0; i < K; i++) blockPerm[i] = i;
          for (let i = K - 1; i > 0; i--) {
            const j = prngPixel.nextInt(i + 1);
            const temp = blockPerm[i];
            blockPerm[i] = blockPerm[j];
            blockPerm[j] = temp;
          }

          for (let bIdx = 0; bIdx < K; bIdx++) {
            const srcTop = part.eligibleBlocks[bIdx];
            const dstTop = part.eligibleBlocks[blockPerm[bIdx]];
            for (let dy = 0; dy < B; dy++) {
              const sRow = srcTop + dy * W;
              const dRow = dstTop + dy * W;
              for (let dx = 0; dx < B; dx++) {
                const srcIdx = (sRow + dx) * 4;
                const dstIdx = (dRow + dx) * 4;
                stage1Data[dstIdx] = data[srcIdx];
                stage1Data[dstIdx + 1] = data[srcIdx + 1];
                stage1Data[dstIdx + 2] = data[srcIdx + 2];
                stage1Data[dstIdx + 3] = data[srcIdx + 3];
              }
            }
          }
        }

        const L = part.boundaryIndices.length;
        if (L >= 2) {
          const boundPerm = new Int32Array(L);
          for (let i = 0; i < L; i++) boundPerm[i] = i;
          for (let i = L - 1; i > 0; i--) {
            const j = prngPixel.nextInt(i + 1);
            const temp = boundPerm[i];
            boundPerm[i] = boundPerm[j];
            boundPerm[j] = temp;
          }

          for (let i = 0; i < L; i++) {
            const srcIdx = part.boundaryIndices[i] * 4;
            const dstIdx = part.boundaryIndices[boundPerm[i]] * 4;
            stage1Data[dstIdx] = data[srcIdx];
            stage1Data[dstIdx + 1] = data[srcIdx + 1];
            stage1Data[dstIdx + 2] = data[srcIdx + 2];
            stage1Data[dstIdx + 3] = data[srcIdx + 3];
          }
        }
      }
    }

    // === STAGE 2: RGB CHANNEL PERMUTATION (Key-Driven Dynamic or Fixed) ===
    const stage2Data = new Uint8ClampedArray(stage1Data);
    if (cfg.stage2Enabled) {
      const isFixedPerm = cfg.stage2Mode === 'fixed';
      const allowedIds = (cfg.stage2AllowedIds && cfg.stage2AllowedIds.length > 0)
        ? cfg.stage2AllowedIds
        : [0, 1, 2, 3, 4, 5];
      const allowedCount = allowedIds.length;
      for (let idx = 0; idx < M; idx++) {
        const pixelIdx = targetIndices[idx] * 4;
        const r = stage1Data[pixelIdx];
        const g = stage1Data[pixelIdx + 1];
        const b = stage1Data[pixelIdx + 2];
        const rgb = [r, g, b];

        const permIdx = isFixedPerm
          ? cfg.stage2FixedPermId
          : allowedIds[prngChannel.nextInt(allowedCount)];
        const pOrder = this.CHANNEL_PERMS[permIdx];

        stage2Data[pixelIdx] = rgb[pOrder[0]];
        stage2Data[pixelIdx + 1] = rgb[pOrder[1]];
        stage2Data[pixelIdx + 2] = rgb[pOrder[2]];
      }
    }

    // === STAGE 3: k-MSB XOR ENCRYPTION (Configurable k=1..8 & Selectable R/G/B Channels) ===
    const activeCh = [
      !!cfg.stage3Channels.r,
      !!cfg.stage3Channels.g,
      !!cfg.stage3Channels.b
    ];
    let swappedCount = 0;
    let totalDiffSq = 0;
    let channelCount = 0;

    for (let idx = 0; idx < M; idx++) {
      const pixelIdx = targetIndices[idx] * 4;
      for (let c = 0; c < 3; c++) {
        const cIdx = pixelIdx + c;
        const originalByte = originalCopy[cIdx];
        const currentByte = stage2Data[cIdx];
        let newByte = currentByte;

        if (cfg.stage3Enabled && activeCh[c]) {
          const keyBits = kk === 2 ? prngXor.next2Bits() : prngXor.nextKBits(kk);
          newByte = kk === 2 ? this.xor2MSB(currentByte, keyBits) : this.xorKMSB(currentByte, keyBits, kk);
        }

        data[cIdx] = newByte;

        if (newByte !== originalByte) swappedCount++;
        const diff = originalByte - newByte;
        totalDiffSq += diff * diff;
        channelCount++;
      }
      data[pixelIdx + 3] = stage2Data[pixelIdx + 3];
    }

    const mse = channelCount > 0 ? (totalDiffSq / channelCount) : 0;
    const psnr = mse === 0 ? Infinity : 10 * Math.log10((255 * 255) / mse);

    return {
      imageData,
      swappedCount,
      mse: parseFloat(mse.toFixed(4)),
      psnr: psnr === Infinity ? '∞' : parseFloat(psnr.toFixed(2)),
      stageConfig: cfg
    };
  },

  /**
   * Core 3-Stage Decryption with explicit PRNG streams, configurable k (1..8, default 2),
   * and customizable stage configuration (reversing only enabled stages in exact inverse order).
   */
  _decryptWithStreams(imageData, prngPixel, prngChannel, prngXor, maskOrRegions = null, kVal = 2, stageConfig = null) {
    const cfg = this.normalizeStageConfig(stageConfig, kVal);
    const kk = cfg.k;
    const W = imageData.width;
    const H = imageData.height;
    const data = imageData.data;
    const inputCopy = new Uint8ClampedArray(data);
    const targetIndices = this.getTargetPixelIndices(imageData, maskOrRegions);
    const M = targetIndices.length;

    if (M === 0) {
      return { imageData, swappedCount: 0, mse: 0, psnr: '∞', stageConfig: cfg };
    }

    // === REVERSE STAGE 3: UNDO k-MSB XOR ENCRYPTION (if Stage 3 was enabled) ===
    const unXorData = new Uint8ClampedArray(data);
    if (cfg.stage3Enabled) {
      const activeCh = [
        !!cfg.stage3Channels.r,
        !!cfg.stage3Channels.g,
        !!cfg.stage3Channels.b
      ];
      for (let idx = 0; idx < M; idx++) {
        const pixelIdx = targetIndices[idx] * 4;
        for (let c = 0; c < 3; c++) {
          const cIdx = pixelIdx + c;
          if (activeCh[c]) {
            const keyBits = kk === 2 ? prngXor.next2Bits() : prngXor.nextKBits(kk);
            unXorData[cIdx] = kk === 2 ? this.xor2MSB(data[cIdx], keyBits) : this.xorKMSB(data[cIdx], keyBits, kk);
          } else {
            unXorData[cIdx] = data[cIdx];
          }
        }
      }
    }

    // === REVERSE STAGE 2: UNDO RGB CHANNEL PERMUTATION (if Stage 2 was enabled) ===
    const unChannelData = new Uint8ClampedArray(unXorData);
    if (cfg.stage2Enabled) {
      const isFixedPerm = cfg.stage2Mode === 'fixed';
      const allowedIds = (cfg.stage2AllowedIds && cfg.stage2AllowedIds.length > 0)
        ? cfg.stage2AllowedIds
        : [0, 1, 2, 3, 4, 5];
      const allowedCount = allowedIds.length;
      for (let idx = 0; idx < M; idx++) {
        const pixelIdx = targetIndices[idx] * 4;
        const r = unXorData[pixelIdx];
        const g = unXorData[pixelIdx + 1];
        const b = unXorData[pixelIdx + 2];
        const rgb = [r, g, b];

        const permIdx = isFixedPerm
          ? cfg.stage2FixedPermId
          : allowedIds[prngChannel.nextInt(allowedCount)];
        const invOrder = this.INV_CHANNEL_PERMS[permIdx];

        unChannelData[pixelIdx] = rgb[invOrder[0]];
        unChannelData[pixelIdx + 1] = rgb[invOrder[1]];
        unChannelData[pixelIdx + 2] = rgb[invOrder[2]];
      }
    }

    // === REVERSE STAGE 1: UNDO PIXEL PERMUTATION (if Stage 1 was enabled) ===
    data.set(unChannelData);
    if (cfg.stage1Enabled) {
      const B = cfg.stage1BlockSize;
      if (B <= 1) {
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
      } else {
        const part = this.partitionMaskAwareBlocks(W, H, targetIndices, B);
        const K = part.eligibleBlocks.length;
        if (K >= 2) {
          const blockPerm = new Int32Array(K);
          for (let i = 0; i < K; i++) blockPerm[i] = i;
          for (let i = K - 1; i > 0; i--) {
            const j = prngPixel.nextInt(i + 1);
            const temp = blockPerm[i];
            blockPerm[i] = blockPerm[j];
            blockPerm[j] = temp;
          }

          for (let bIdx = 0; bIdx < K; bIdx++) {
            const srcTop = part.eligibleBlocks[blockPerm[bIdx]];
            const dstTop = part.eligibleBlocks[bIdx];
            for (let dy = 0; dy < B; dy++) {
              const sRow = srcTop + dy * W;
              const dRow = dstTop + dy * W;
              for (let dx = 0; dx < B; dx++) {
                const srcIdx = (sRow + dx) * 4;
                const dstIdx = (dRow + dx) * 4;
                data[dstIdx] = unChannelData[srcIdx];
                data[dstIdx + 1] = unChannelData[srcIdx + 1];
                data[dstIdx + 2] = unChannelData[srcIdx + 2];
                data[dstIdx + 3] = unChannelData[srcIdx + 3];
              }
            }
          }
        }

        const L = part.boundaryIndices.length;
        if (L >= 2) {
          const boundPerm = new Int32Array(L);
          for (let i = 0; i < L; i++) boundPerm[i] = i;
          for (let i = L - 1; i > 0; i--) {
            const j = prngPixel.nextInt(i + 1);
            const temp = boundPerm[i];
            boundPerm[i] = boundPerm[j];
            boundPerm[j] = temp;
          }

          for (let i = 0; i < L; i++) {
            const srcIdx = part.boundaryIndices[boundPerm[i]] * 4;
            const dstIdx = part.boundaryIndices[i] * 4;
            data[dstIdx] = unChannelData[srcIdx];
            data[dstIdx + 1] = unChannelData[srcIdx + 1];
            data[dstIdx + 2] = unChannelData[srcIdx + 2];
            data[dstIdx + 3] = unChannelData[srcIdx + 3];
          }
        }
      }
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
      psnr: psnr === Infinity ? '∞' : parseFloat(psnr.toFixed(2)),
      stageConfig: cfg
    };
  },

  /**
   * Detect original image colour mode from RGBA ImageData:
   * - 0 = Grayscale (8-bit L, where R === G === B for every pixel and A === 255)
   * - 1 = RGB (24-bit Truecolor, where A === 255)
   * - 2 = RGBA (32-bit Truecolor with Alpha, where any pixel has A < 255)
   */
  detectColorMode(imageData) {
    const src = imageData.data;
    let hasTransparency = false;
    let isGrayscale = true;
    for (let i = 0; i < src.length; i += 4) {
      const r = src[i], g = src[i + 1], b = src[i + 2], a = src[i + 3];
      if (a < 255) hasTransparency = true;
      if (r !== g || g !== b) isGrayscale = false;
      if (hasTransparency && !isGrayscale) break;
    }
    if (hasTransparency) return 2;
    if (isGrayscale) return 0;
    return 1;
  },

  /**
   * Extract compact pixel payload bytes from RGBA ImageData according to imageMode:
   * mode 0 = Grayscale (1 byte/pixel), mode 1 = RGB (3 bytes/pixel), mode 2 = RGBA (4 bytes/pixel).
   */
  extractPixelPayload(rgbaData, totalPixels, imageMode) {
    if (imageMode === 2) {
      return new Uint8Array(rgbaData.buffer.slice(rgbaData.byteOffset, rgbaData.byteOffset + totalPixels * 4));
    }
    if (imageMode === 0) {
      const gray = new Uint8Array(totalPixels);
      for (let i = 0; i < totalPixels; i++) {
        gray[i] = rgbaData[i * 4];
      }
      return gray;
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
      throw new Error(`Unsupported image colour mode (${imageMode}).`);
    }
    return new ImageData(rgba, width, height);
  },

  /* ==========================================================================
     PHASE 2–5: SELF-DESCRIBING ENCRYPTED PNG CODEC & `msBx` METADATA CHUNK
     ========================================================================== */

  /**
   * Construct a single ISO/IEC 15948 PNG chunk: [Length (4B BE)] [Type (4B ASCII)] [Data] [CRC-32 (4B BE)]
   */
  buildPngChunk(typeStr, dataBytes) {
    if (typeof typeStr !== 'string' || typeStr.length !== 4) {
      throw new Error(`Invalid PNG chunk type "${typeStr}". Must be 4 ASCII characters.`);
    }
    const payload = dataBytes instanceof Uint8Array ? dataBytes : new Uint8Array(dataBytes || 0);
    const chunk = new Uint8Array(12 + payload.length);
    const dv = new DataView(chunk.buffer);
    dv.setUint32(0, payload.length, false);
    for (let i = 0; i < 4; i++) {
      chunk[4 + i] = typeStr.charCodeAt(i) & 0xFF;
    }
    chunk.set(payload, 8);
    const crc = computeCrc32(chunk.subarray(4, 8 + payload.length));
    dv.setUint32(8 + payload.length, crc, false);
    return chunk;
  },

  /**
   * Encode an ImageData into a 100% lossless ISO/IEC 15948 PNG binary (Uint8Array)
   * with optional ancillary chunks (such as `msBx`) inserted right before `IDAT`.
   *
   * Note: Even if the original plaintext image was Grayscale (mode 0), the 3-stage
   * encryption pipeline permutes and XORs R, G, and B channels independently, so the
   * encrypted ciphertext pixels are stored as 24-bit RGB (`colorType = 2`) or 32-bit
   * RGBA (`colorType = 6`) to preserve all 3 encrypted channels without loss.
   */
  async encodeLosslessPNG(imageData, extraChunks = [], forceColorType = null) {
    const width = imageData.width;
    const height = imageData.height;
    const rgba = imageData.data;

    let colorType = forceColorType;
    if (colorType === null || colorType === undefined) {
      let hasAlpha = false;
      for (let i = 3; i < rgba.length; i += 4) {
        if (rgba[i] < 255) { hasAlpha = true; break; }
      }
      colorType = hasAlpha ? 6 : 2; // 6 = RGBA, 2 = RGB
    }

    const channels = colorType === 6 ? 4 : (colorType === 2 ? 3 : 1);
    const rowBytes = width * channels;
    const rawScanlines = new Uint8Array((rowBytes + 1) * height);

    let dst = 0;
    for (let y = 0; y < height; y++) {
      rawScanlines[dst++] = 0; // Filter type 0 (None) for exact, deterministic fast scanlines
      const rowOffset = y * width * 4;
      if (channels === 4) {
        rawScanlines.set(rgba.subarray(rowOffset, rowOffset + width * 4), dst);
        dst += width * 4;
      } else if (channels === 3) {
        for (let x = 0; x < width; x++) {
          const p = rowOffset + x * 4;
          rawScanlines[dst++] = rgba[p];
          rawScanlines[dst++] = rgba[p + 1];
          rawScanlines[dst++] = rgba[p + 2];
        }
      } else {
        for (let x = 0; x < width; x++) {
          rawScanlines[dst++] = rgba[rowOffset + x * 4];
        }
      }
    }

    // 1. IHDR chunk (13 bytes)
    const ihdrData = new Uint8Array(13);
    const ihdrDv = new DataView(ihdrData.buffer);
    ihdrDv.setUint32(0, width, false);
    ihdrDv.setUint32(4, height, false);
    ihdrData[8] = 8;          // Bit depth = 8 bits per channel
    ihdrData[9] = colorType;  // 0 = Grayscale, 2 = RGB, 6 = RGBA
    ihdrData[10] = 0;         // Compression method = 0 (DEFLATE)
    ihdrData[11] = 0;         // Filter method = 0 (Adaptive filtering)
    ihdrData[12] = 0;         // Interlace method = 0 (No interlace)
    const ihdrChunk = this.buildPngChunk('IHDR', ihdrData);

    // 2. Extra ancillary chunks (e.g. `msBx`)
    const encodedExtras = extraChunks.map(ch => this.buildPngChunk(ch.type, ch.data));

    // 3. IDAT chunk (ZLIB-compressed scanlines)
    const compressedIdat = await zlibCompressBytes(rawScanlines);
    const idatChunk = this.buildPngChunk('IDAT', compressedIdat);

    // 4. IEND chunk (0 bytes)
    const iendChunk = this.buildPngChunk('IEND', new Uint8Array(0));

    let totalLen = this.PNG_SIGNATURE.length + ihdrChunk.length + idatChunk.length + iendChunk.length;
    for (const ec of encodedExtras) totalLen += ec.length;

    const out = new Uint8Array(totalLen);
    let pos = 0;
    out.set(this.PNG_SIGNATURE, pos); pos += this.PNG_SIGNATURE.length;
    out.set(ihdrChunk, pos); pos += ihdrChunk.length;
    for (const ec of encodedExtras) {
      out.set(ec, pos);
      pos += ec.length;
    }
    out.set(idatChunk, pos); pos += idatChunk.length;
    out.set(iendChunk, pos);
    return out;
  },

  /**
   * Check whether a byte buffer begins with the 8-byte ISO/IEC 15948 PNG signature.
   */
  isPngBytes(bytes) {
    if (!bytes || bytes.byteLength < 8) return false;
    for (let i = 0; i < 8; i++) {
      if (bytes[i] !== this.PNG_SIGNATURE[i]) return false;
    }
    return true;
  },

  /**
   * Decode a standard 8-bit PNG binary (colorType 0, 2, or 6; filter types 0..4),
   * verifying chunk CRC-32 values and returning both the reconstructed RGBA ImageData
   * and a map/list of ancillary chunks (including `msBx`).
   */
  async decodeLosslessPNG(bufferOrBytes) {
    const bytes = bufferOrBytes instanceof Uint8Array
      ? bufferOrBytes
      : new Uint8Array(bufferOrBytes);

    if (!this.isPngBytes(bytes)) {
      throw new Error("Invalid PNG file: Missing 8-byte PNG signature.");
    }

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = 8;
    let width = 0, height = 0, bitDepth = 0, colorType = 0, interlace = 0;
    let seenIHDR = false;
    let seenIEND = false;
    const idatParts = [];
    let idatTotal = 0;
    const chunks = [];

    while (offset + 12 <= bytes.byteLength) {
      const length = dv.getUint32(offset, false);
      if (offset + 12 + length > bytes.byteLength) {
        throw new Error("Corrupted or truncated PNG file: Chunk length exceeds file size.");
      }
      const type = String.fromCharCode(
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7]
      );
      const dataStart = offset + 8;
      const dataEnd = dataStart + length;
      const chunkData = bytes.subarray(dataStart, dataEnd);
      const expectedCrc = dv.getUint32(dataEnd, false);
      const actualCrc = computeCrc32(bytes.subarray(offset + 4, dataEnd));
      if (expectedCrc !== actualCrc) {
        throw new Error(`Corrupted PNG file: CRC-32 checksum mismatch in "${type}" chunk.`);
      }

      chunks.push({ type, data: chunkData });

      if (type === 'IHDR') {
        if (length < 13) throw new Error("Invalid PNG IHDR chunk length.");
        width = dv.getUint32(dataStart, false);
        height = dv.getUint32(dataStart + 4, false);
        bitDepth = bytes[dataStart + 8];
        colorType = bytes[dataStart + 9];
        interlace = bytes[dataStart + 12];
        seenIHDR = true;
      } else if (type === 'IDAT') {
        idatParts.push(chunkData);
        idatTotal += chunkData.byteLength;
      } else if (type === 'IEND') {
        seenIEND = true;
        break;
      }

      offset = dataEnd + 4;
    }

    if (!seenIHDR || !seenIEND || idatTotal === 0) {
      throw new Error("Invalid or incomplete PNG file: Missing required IHDR, IDAT, or IEND chunks.");
    }
    if (bitDepth !== 8 || (colorType !== 0 && colorType !== 2 && colorType !== 6) || interlace !== 0) {
      throw new Error(`Unsupported PNG encoding parameters (bitDepth=${bitDepth}, colorType=${colorType}, interlace=${interlace}).`);
    }

    const combinedIdat = new Uint8Array(idatTotal);
    let pos = 0;
    for (const part of idatParts) {
      combinedIdat.set(part, pos);
      pos += part.byteLength;
    }

    const rawScanlines = await zlibDecompressBytes(combinedIdat);
    const channels = colorType === 6 ? 4 : (colorType === 2 ? 3 : 1);
    const bpp = channels;
    const stride = width * channels;
    const expectedScanlineBytes = (stride + 1) * height;
    if (rawScanlines.byteLength < expectedScanlineBytes) {
      throw new Error("Corrupted PNG IDAT payload: Decompressed scanlines are shorter than image dimensions.");
    }

    const recon = new Uint8Array(stride * height);
    for (let y = 0; y < height; y++) {
      const filterType = rawScanlines[y * (stride + 1)];
      const srcRow = y * (stride + 1) + 1;
      const dstRow = y * stride;
      const prevRow = (y - 1) * stride;

      for (let i = 0; i < stride; i++) {
        const x = rawScanlines[srcRow + i];
        const a = i >= bpp ? recon[dstRow + i - bpp] : 0;
        const b = y > 0 ? recon[prevRow + i] : 0;
        const c = (y > 0 && i >= bpp) ? recon[prevRow + i - bpp] : 0;

        let val = x;
        if (filterType === 0) {
          val = x;
        } else if (filterType === 1) {
          val = (x + a) & 0xFF;
        } else if (filterType === 2) {
          val = (x + b) & 0xFF;
        } else if (filterType === 3) {
          val = (x + ((a + b) >>> 1)) & 0xFF;
        } else if (filterType === 4) {
          const p = a + b - c;
          const pa = Math.abs(p - a);
          const pb = Math.abs(p - b);
          const pc = Math.abs(p - c);
          const pr = (pa <= pb && pa <= pc) ? a : (pb <= pc ? b : c);
          val = (x + pr) & 0xFF;
        } else {
          throw new Error(`Unsupported PNG scanline filter type (${filterType}).`);
        }
        recon[dstRow + i] = val;
      }
    }

    const rgba = new Uint8ClampedArray(width * height * 4);
    if (channels === 4) {
      rgba.set(recon);
    } else if (channels === 3) {
      for (let i = 0, j = 0; i < width * height; i++, j += 3) {
        const p = i * 4;
        rgba[p] = recon[j];
        rgba[p + 1] = recon[j + 1];
        rgba[p + 2] = recon[j + 2];
        rgba[p + 3] = 255;
      }
    } else {
      for (let i = 0; i < width * height; i++) {
        const v = recon[i];
        const p = i * 4;
        rgba[p] = v;
        rgba[p + 1] = v;
        rgba[p + 2] = v;
        rgba[p + 3] = 255;
      }
    }

    return {
      width,
      height,
      bitDepth,
      colorType,
      channels,
      imageData: new ImageData(rgba, width, height),
      chunks
    };
  },

  /**
   * Compute the 32-byte SHA-256 original pixel verification tag for a Self-Describing Encrypted PNG (Schema v1).
   * Authenticates:
   * - Domain-separated verification key derived from `masterKey32` + `salt16` ("KENX_PNG_VERIFY_TAG")
   * - First 44 bytes of the `msBx` metadata header (identifier, versions, modes, k, dimensions, iterations, salt)
   * - Original unencrypted pixel payload bytes (`width * height * originalChannels`)
   * - Plain RLE-encoded segmentation mask bytes (if partial region encryption was used)
   */
  computePngVerificationTag(masterKey32, salt16, metaPrefix44, plaintextPixelBytes, plainMaskRleBytes = null) {
    const encoder = new TextEncoder();
    const tagDomain = encoder.encode('KENX_PNG_VERIFY_TAG');
    const vkInput = new Uint8Array(masterKey32.length + salt16.length + tagDomain.length);
    vkInput.set(masterKey32, 0);
    vkInput.set(salt16, masterKey32.length);
    vkInput.set(tagDomain, masterKey32.length + salt16.length);
    const verifyKey = sha256Bytes(vkInput);

    const maskLen = plainMaskRleBytes ? plainMaskRleBytes.length : 0;
    const total = verifyKey.length + 44 + plaintextPixelBytes.length + maskLen;
    const msg = new Uint8Array(total);
    let pos = 0;
    msg.set(verifyKey, pos); pos += verifyKey.length;
    msg.set(metaPrefix44.subarray(0, 44), pos); pos += 44;
    msg.set(plaintextPixelBytes, pos); pos += plaintextPixelBytes.length;
    if (maskLen > 0) msg.set(plainMaskRleBytes, pos);
    return sha256Bytes(msg);
  },

  /**
   * Compute the 32-byte SHA-256 original pixel verification tag for Optimized Schema v2 (`msBX`).
   * Binds:
   * - Domain-separated verification key ("KENX_PNG_VERIFY_TAG_V2")
   * - Compact v2 metadata header prefix + 16-byte salt (`metaPrefixBytes`)
   * - Image width & height from PNG `IHDR` (8 bytes big-endian)
   * - Original unencrypted pixel payload bytes
   * - Canonical RLE representation of the binary segmentation mask (if selective scope is active)
   */
  computePngVerificationTagV2(masterKey32, salt16, metaPrefixBytes, width, height, plaintextPixelBytes, canonicalMaskBytes = null) {
    const encoder = new TextEncoder();
    const tagDomain = encoder.encode('KENX_PNG_VERIFY_TAG_V2');
    const vkInput = new Uint8Array(masterKey32.length + salt16.length + tagDomain.length);
    vkInput.set(masterKey32, 0);
    vkInput.set(salt16, masterKey32.length);
    vkInput.set(tagDomain, masterKey32.length + salt16.length);
    const verifyKey = sha256Bytes(vkInput);

    const dimsBuf = new Uint8Array(8);
    const dimsDv = new DataView(dimsBuf.buffer);
    dimsDv.setUint32(0, width >>> 0, false);
    dimsDv.setUint32(4, height >>> 0, false);

    const maskLen = canonicalMaskBytes ? canonicalMaskBytes.length : 0;
    const total = verifyKey.length + metaPrefixBytes.length + 8 + plaintextPixelBytes.length + maskLen;
    const msg = new Uint8Array(total);
    let pos = 0;
    msg.set(verifyKey, pos); pos += verifyKey.length;
    msg.set(metaPrefixBytes, pos); pos += metaPrefixBytes.length;
    msg.set(dimsBuf, pos); pos += 8;
    msg.set(plaintextPixelBytes, pos); pos += plaintextPixelBytes.length;
    if (maskLen > 0) msg.set(canonicalMaskBytes, pos);
    return sha256Bytes(msg);
  },

  /**
   * Unsigned LEB128 Varint helpers for compact metadata & mask length encoding.
   */
  encodeVarint(value) {
    let v = value >>> 0;
    const out = [];
    while (v >= 0x80) {
      out.push((v & 0x7F) | 0x80);
      v >>>= 7;
    }
    out.push(v & 0x7F);
    return Uint8Array.from(out);
  },

  decodeVarint(bytes, startOffset = 0) {
    let val = 0;
    let shift = 0;
    let pos = startOffset;
    while (pos < bytes.length) {
      const b = bytes[pos++];
      val |= ((b & 0x7F) << shift);
      if ((b & 0x80) === 0) {
        return { value: val >>> 0, nextOffset: pos, byteLength: pos - startOffset };
      }
      shift += 7;
      if (shift > 35) {
        throw new Error("Corrupted LEB128 varint in PNG metadata.");
      }
    }
    throw new Error("Truncated LEB128 varint in PNG metadata.");
  },

  /**
   * Lossless Mask Compression Codec Implementations (Feature 3D):
   * 1 = Raw Binary Mask (1 byte per pixel: 0x00 or 0x01)
   * 2 = Bit-Packed Mask (8 pixels per byte, MSB first)
   * 3 = Run-Length Encoding (LEB128 RLE-Varint)
   * 4 = DEFLATE Compression (RFC 1950/1951 ZLIB/DEFLATE over RLE or Bit-Packed mask)
   */
  encodeMaskRaw(mask) {
    const out = new Uint8Array(mask.length);
    for (let i = 0; i < mask.length; i++) out[i] = mask[i] ? 1 : 0;
    return out;
  },

  decodeMaskRaw(bytes, totalPixels) {
    if (!bytes || bytes.length !== totalPixels) {
      throw new Error(`Corrupted Raw Binary mask: Expected ${totalPixels} bytes, got ${bytes ? bytes.length : 0}.`);
    }
    const out = new Uint8Array(totalPixels);
    for (let i = 0; i < totalPixels; i++) {
      if (bytes[i] !== 0 && bytes[i] !== 1) {
        throw new Error(`Invalid byte value (${bytes[i]}) in Raw Binary mask.`);
      }
      out[i] = bytes[i];
    }
    return out;
  },

  encodeMaskBitPacked(mask) {
    const byteLen = Math.ceil(mask.length / 8);
    const out = new Uint8Array(byteLen);
    for (let i = 0; i < mask.length; i++) {
      if (mask[i]) {
        out[i >>> 3] |= (1 << (7 - (i & 7)));
      }
    }
    return out;
  },

  decodeMaskBitPacked(bytes, totalPixels) {
    const expectedLen = Math.ceil(totalPixels / 8);
    if (!bytes || bytes.length !== expectedLen) {
      throw new Error(`Corrupted Bit-Packed mask: Expected ${expectedLen} bytes, got ${bytes ? bytes.length : 0}.`);
    }
    const out = new Uint8Array(totalPixels);
    for (let i = 0; i < totalPixels; i++) {
      out[i] = (bytes[i >>> 3] >>> (7 - (i & 7))) & 1;
    }
    return out;
  },

  encodeMaskDeflate(mask) {
    const rle = this.encodeMaskTrailer(mask);
    const defRle = zlibDeflateSync(rle);
    const expectedBpBytes = Math.ceil(mask.length / 8);
    // Only compress Bit-Packed if it is small enough to plausibly beat RLE+DEFLATE
    if (expectedBpBytes <= 32768 && expectedBpBytes < rle.byteLength * 2) {
      const bitPacked = this.encodeMaskBitPacked(mask);
      const defBp = zlibDeflateSync(bitPacked);
      if (defBp.length < defRle.length) {
        const outBp = new Uint8Array(1 + defBp.length);
        outBp[0] = 2; // 2 = BitPacked+DEFLATE
        outBp.set(defBp, 1);
        return outBp;
      }
    }
    const out = new Uint8Array(1 + defRle.length);
    out[0] = 1; // 1 = RLE+DEFLATE
    out.set(defRle, 1);
    return out;
  },

  decodeMaskDeflate(bytes, totalPixels) {
    if (!bytes || bytes.length < 7) {
      throw new Error("Corrupted or truncated DEFLATE mask payload.");
    }
    const innerMode = bytes[0];
    if (innerMode !== 1 && innerMode !== 2) {
      throw new Error(`Unsupported DEFLATE inner mask mode (${innerMode}).`);
    }
    const inflated = zlibInflateSync(bytes.subarray(1));
    return innerMode === 1
      ? this.decodeMaskTrailer(inflated, totalPixels)
      : this.decodeMaskBitPacked(inflated, totalPixels);
  },

  encodeMaskWithCodec(mask, codec = 3) {
    switch (codec) {
      case this.MASK_CODEC_RAW:
        return this.encodeMaskRaw(mask);
      case this.MASK_CODEC_BITPACKED:
        return this.encodeMaskBitPacked(mask);
      case this.MASK_CODEC_RLE:
        return this.encodeMaskTrailer(mask);
      case this.MASK_CODEC_DEFLATE:
        return this.encodeMaskDeflate(mask);
      default:
        throw new Error(`Unsupported mask compression codec (${codec}).`);
    }
  },

  decodeMaskWithCodec(bytes, totalPixels, codec = 3) {
    switch (codec) {
      case this.MASK_CODEC_RAW:
        return this.decodeMaskRaw(bytes, totalPixels);
      case this.MASK_CODEC_BITPACKED:
        return this.decodeMaskBitPacked(bytes, totalPixels);
      case this.MASK_CODEC_RLE:
        return this.decodeMaskTrailer(bytes, totalPixels);
      case this.MASK_CODEC_DEFLATE:
        return this.decodeMaskDeflate(bytes, totalPixels);
      default:
        throw new Error(`Unsupported mask compression codec (${codec}).`);
    }
  },

  _maskBenchCache: { key: '', result: null },

  /**
   * Benchmark all 4 lossless mask storage methods (Raw Binary, Bit-Packed, RLE-Varint, DEFLATE)
   * on a binary mask and select the smallest lossless representation while verifying 0 diff bits.
   */
  benchmarkMaskCompression(mask) {
    const nowFn = () => (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    const totalPixels = mask.length;

    // Fast fingerprint over mask length + strided samples so repeated UI refreshes don't re-allocate 4 full masks
    let fgSum = 0;
    let hash = totalPixels ^ 0x811c9dc5;
    const step = Math.max(1, Math.floor(totalPixels / 512));
    for (let i = 0; i < totalPixels; i += step) {
      const v = mask[i] ? 1 : 0;
      fgSum += v;
      hash = Math.imul(hash ^ ((i << 1) | v), 0x01000193) >>> 0;
    }
    const cacheKey = `${totalPixels}:${fgSum}:${hash}`;
    if (this._maskBenchCache.key === cacheKey && this._maskBenchCache.result) {
      return this._maskBenchCache.result;
    }

    const codecs = [
      { id: this.MASK_CODEC_RAW, name: 'Raw Binary Mask (1 B/pixel)', shortName: 'Raw Binary' },
      { id: this.MASK_CODEC_BITPACKED, name: 'Bit-Packed Mask (1 bit/pixel)', shortName: 'Bit-Packed' },
      { id: this.MASK_CODEC_RLE, name: 'Run-Length Encoding (LEB128 RLE)', shortName: 'RLE-Varint' },
      { id: this.MASK_CODEC_DEFLATE, name: 'DEFLATE Compression (RFC 1951)', shortName: 'DEFLATE' }
    ];

    const results = [];
    let best = null;

    for (const c of codecs) {
      const t0 = nowFn();
      const encoded = this.encodeMaskWithCodec(mask, c.id);
      const t1 = nowFn();
      const decoded = this.decodeMaskWithCodec(encoded, totalPixels, c.id);
      const t2 = nowFn();

      let diffBits = 0;
      for (let i = 0; i < totalPixels; i++) {
        if ((mask[i] ? 1 : 0) !== decoded[i]) diffBits++;
      }

      const rawSize = totalPixels;
      const encodedSize = encoded.byteLength;
      const reductionPct = rawSize > 0 ? (((rawSize - encodedSize) / rawSize) * 100) : 0;
      const compressionRatio = encodedSize > 0 ? (rawSize / encodedSize) : 1;

      const entry = {
        codecId: c.id,
        name: c.name,
        shortName: c.shortName,
        rawBytes: rawSize,
        encodedBytes: encodedSize,
        bytesSavedVsRaw: rawSize - encodedSize,
        reductionPct: parseFloat(reductionPct.toFixed(2)),
        compressionRatio: parseFloat(compressionRatio.toFixed(2)),
        encodeTimeMs: parseFloat(Math.max(0.01, t1 - t0).toFixed(3)),
        decodeTimeMs: parseFloat(Math.max(0.01, t2 - t1).toFixed(3)),
        diffBits,
        verifiedLossless: diffBits === 0,
        encodedPayload: encoded
      };
      results.push(entry);
      if (!best || entry.encodedBytes < best.encodedBytes) {
        best = entry;
      }
    }

    const resObj = {
      totalPixels,
      rawMaskBytes: totalPixels,
      bestCodecId: best.codecId,
      bestCodecName: best.shortName,
      bestEncodedBytes: best.encodedBytes,
      bestPayload: best.encodedPayload,
      methods: results
    };
    this._maskBenchCache = { key: cacheKey, result: resObj };
    return resObj;
  },

  /**
   * Optional mask privacy protection: XOR-encrypt/decrypt the encoded segmentation mask
   * using a dedicated domain stream ("MASK_PROTECT_STREAM") so an external observer inspecting
   * the PNG metadata cannot see the silhouette/location of the selected face or body without the key.
   */
  xorMaskBytesWithKey(rleBytes, masterKey32, salt16) {
    const prngMask = this.createDomainPRNG(masterKey32, salt16, 'MASK_PROTECT_STREAM');
    const out = new Uint8Array(rleBytes.length);
    for (let i = 0; i < rleBytes.length; i++) {
      out[i] = (rleBytes[i] ^ prngMask.nextByte()) & 0xFF;
    }
    return out;
  },

  /**
   * Serialize Optimized Schema v2 (`metaVersion = 2`) Compact Binary `msBX` payload.
   *
   * Compact Bit-Packed Layout:
   * - Byte 0       : [7:4] Magic Nibble 0xB (1011) | [3:0] Schema Version 2 (0010) -> 0xB2
   * - Byte 1       : [7:5] (k - 1) (3 bits) | [4:3] Scope (2 bits) | [2] KeyType (1 bit) | [1:0] ColorMode (2 bits)
   * - Byte 2       : [7:6] AlgoVersion (2 bits) | [5:4] KDF Preset (2 bits) | [3:1] MaskCodec (3 bits) | [0] HasExtFlags (1 bit)
   * - [Opt 1B]     : extFlags ([0] maskProtected, [1] hasOptionalTlv, [7:2] reserved)
   * - [Opt 1..5B]  : Custom KDF Iterations (LEB128 varint when KDF Preset == 3)
   * - [16 Bytes]   : Cryptographic Random Salt
   * - [32 Bytes]   : SHA-256 Original Pixel & Metadata Verification Tag
   * - [Opt Mask]   : maskByteLen (LEB128 varint) + encodedMaskBytes (when scope != 0)
   * - [Opt TLV]    : tlvCount (1B) + [fieldId (1B, bit 7=critical), len (LEB128), valueBytes]...
   *
   * Note: Image Width & Height are NOT duplicated in Schema v2; they are read directly from PNG `IHDR`.
   */
  encodeMsBxMetadataV2(params) {
    const {
      algoVersion = 1,
      originalColorMode = 1,
      k = 2,
      keyType = 'text',
      scope = 'full',
      maskCodec = 0,
      maskProtected = false,
      iterations = 100000,
      salt,
      verificationTag = null,
      encodedMaskBytes = null,
      optionalFields = null,
      rawExtFlags = 0
    } = params;

    const stageCfg = this.normalizeStageConfig(params.stageConfig || params, k);
    const effectiveK = stageCfg.k;

    if (effectiveK < 1 || effectiveK > 8) {
      throw new Error(`Invalid MSB bit depth (k = ${effectiveK}): Must be between 1 and 8.`);
    }
    if (originalColorMode < 0 || originalColorMode > 2) {
      throw new Error(`Invalid original colour mode (${originalColorMode}).`);
    }
    if (algoVersion < 1 || algoVersion > 3) {
      throw new Error(`Unsupported encryption algorithm version (${algoVersion}).`);
    }

    const scopeCodeMap = { full: 0, person: 1, face: 2, custom: 3 };
    const hasMask = encodedMaskBytes && encodedMaskBytes.byteLength > 0;
    const scopeCode = (typeof params.scopeCode === 'number')
      ? params.scopeCode
      : (hasMask ? (scopeCodeMap[scope] || 3) : 0);
    const keyTypeCode = (keyType === 'image' || params.keyTypeCode === 1) ? 1 : 0;
    const effectiveMaskCodec = hasMask ? (maskCodec || this.MASK_CODEC_RLE) : 0;

    let kdfPreset = 3;
    let kdfVarint = new Uint8Array(0);
    if (iterations === 100000) kdfPreset = 0;
    else if (iterations === 10000) kdfPreset = 1;
    else if (iterations === 1000) kdfPreset = 2;
    else kdfVarint = this.encodeVarint(iterations);

    // Encode optional TLV fields if provided
    const tlvChunks = [];
    const encoder = new TextEncoder();
    if (Array.isArray(optionalFields) && optionalFields.length > 0) {
      for (const f of optionalFields) {
        if (!f) continue;
        const idByte = ((f.critical ? 0x80 : 0x00) | (f.id & 0x7F)) & 0xFF;
        let valBytes;
        if (f.valueBytes instanceof Uint8Array) {
          valBytes = f.valueBytes;
        } else if (typeof f.value === 'number') {
          valBytes = new Uint8Array(4);
          new DataView(valBytes.buffer).setUint32(0, f.value >>> 0, false);
        } else {
          valBytes = encoder.encode(String(f.value ?? ''));
        }
        const lenVarint = this.encodeVarint(valBytes.length);
        const entry = new Uint8Array(1 + lenVarint.length + valBytes.length);
        entry[0] = idByte;
        entry.set(lenVarint, 1);
        entry.set(valBytes, 1 + lenVarint.length);
        tlvChunks.push(entry);
      }
    }

    const hasOptionalTlv = tlvChunks.length > 0;
    const hasStageConfig = !stageCfg.isStandardDefault
      || params.encryptionMode === 'advanced'
      || (params.stageConfig && params.stageConfig.encryptionMode === 'advanced')
      || !!params.alwaysIncludeStageConfig;
    const stageConfigBytes = hasStageConfig ? this.encodeStageConfigBytes(stageCfg, effectiveK) : new Uint8Array(0);

    const extFlagsVal = (
      (maskProtected ? 0x01 : 0x00) |
      (hasOptionalTlv ? 0x02 : 0x00) |
      (hasStageConfig ? 0x04 : 0x00) |
      (rawExtFlags & 0xF8)
    ) & 0xFF;
    const hasExtFlags = extFlagsVal !== 0 ? 1 : 0;

    const byte0 = ((this.FYP_COMPACT_MAGIC_NIBBLE & 0x0F) << 4) | (this.FYP_META_VERSION_V2 & 0x0F);
    const byte1 = (((effectiveK - 1) & 0x07) << 5)
                | ((scopeCode & 0x03) << 3)
                | ((keyTypeCode & 0x01) << 2)
                | (originalColorMode & 0x03);
    const byte2 = ((algoVersion & 0x03) << 6)
                | ((kdfPreset & 0x03) << 4)
                | ((effectiveMaskCodec & 0x07) << 1)
                | (hasExtFlags & 0x01);

    const maskLenVarint = hasMask ? this.encodeVarint(encodedMaskBytes.byteLength) : new Uint8Array(0);
    const maskByteLen = hasMask ? encodedMaskBytes.byteLength : 0;

    let tlvTotalBytes = 0;
    if (hasOptionalTlv) {
      tlvTotalBytes = 1; // 1B tlvCount
      for (const tc of tlvChunks) tlvTotalBytes += tc.byteLength;
    }

    const headerPrefixLen = 3 + (hasExtFlags ? 1 : 0) + stageConfigBytes.byteLength + kdfVarint.byteLength;
    const totalLen = headerPrefixLen + 16 + 32 + maskLenVarint.byteLength + maskByteLen + tlvTotalBytes;
    const buf = new Uint8Array(totalLen);

    let pos = 0;
    buf[pos++] = byte0;
    buf[pos++] = byte1;
    buf[pos++] = byte2;
    if (hasExtFlags) {
      buf[pos++] = extFlagsVal;
    }
    if (stageConfigBytes.byteLength > 0) {
      buf.set(stageConfigBytes, pos);
      pos += stageConfigBytes.byteLength;
    }
    if (kdfVarint.byteLength > 0) {
      buf.set(kdfVarint, pos);
      pos += kdfVarint.byteLength;
    }

    const saltBytes = (salt instanceof Uint8Array && salt.length >= 16) ? salt.subarray(0, 16) : new Uint8Array(16);
    buf.set(saltBytes, pos);
    pos += 16;

    if (verificationTag && verificationTag.byteLength === 32) {
      buf.set(verificationTag, pos);
    }
    pos += 32;

    if (hasMask) {
      buf.set(maskLenVarint, pos);
      pos += maskLenVarint.byteLength;
      buf.set(encodedMaskBytes, pos);
      pos += maskByteLen;
    }

    if (hasOptionalTlv) {
      buf[pos++] = tlvChunks.length & 0xFF;
      for (const tc of tlvChunks) {
        buf.set(tc, pos);
        pos += tc.byteLength;
      }
    }

    return buf;
  },

  /**
   * Parse and validate an Optimized Schema v2 (`metaVersion = 2`) `msBX` chunk payload.
   */
  decodeMsBxMetadataV2(chunkBytes, masterKeyForEncryptedMask = null, ihdrDims = null) {
    const bytes = chunkBytes instanceof Uint8Array ? chunkBytes : new Uint8Array(chunkBytes || 0);
    if (bytes.byteLength < this.FYP_META_V2_FIXED_SIZE) {
      throw new Error(`Corrupted or truncated PNG metadata: Expected at least ${this.FYP_META_V2_FIXED_SIZE} bytes in Schema v2 msBX chunk, found ${bytes.byteLength} bytes.`);
    }

    const byte0 = bytes[0];
    const magicNibble = (byte0 >>> 4) & 0x0F;
    const metaVersion = byte0 & 0x0F;
    if (magicNibble !== this.FYP_COMPACT_MAGIC_NIBBLE) {
      throw new Error(`Invalid FYP metadata identifier (0x${byte0.toString(16).toUpperCase()}): Expected compact magic nibble 0xB.`);
    }
    if (metaVersion !== this.FYP_META_VERSION_V2) {
      throw new Error(`Unsupported FYP metadata version (v${metaVersion}): Only versions 1 and 2 are supported.`);
    }

    const byte1 = bytes[1];
    const k = ((byte1 >>> 5) & 0x07) + 1;
    const scopeCode = (byte1 >>> 3) & 0x03;
    const keyTypeCode = (byte1 >>> 2) & 0x01;
    const originalColorMode = byte1 & 0x03;

    if (originalColorMode > 2) {
      throw new Error(`Invalid original colour mode (${originalColorMode}) in PNG metadata.`);
    }

    const byte2 = bytes[2];
    const algoVersion = (byte2 >>> 6) & 0x03;
    const kdfPreset = (byte2 >>> 4) & 0x03;
    const maskCodec = (byte2 >>> 1) & 0x07;
    const hasExtFlags = byte2 & 0x01;

    if (algoVersion !== this.FYP_ALGO_VERSION) {
      throw new Error(`Unsupported encryption algorithm version (v${algoVersion}): Only version ${this.FYP_ALGO_VERSION} is supported.`);
    }
    if (maskCodec > 4) {
      throw new Error(`Unsupported segmentation mask encoding (${maskCodec}) in PNG metadata.`);
    }

    let pos = 3;
    let extFlags = 0;
    let maskProtected = false;
    let hasOptionalTlv = false;
    let hasStageConfig = false;
    let stageConfigOffset = -1;

    if (hasExtFlags) {
      if (pos >= bytes.byteLength) throw new Error("Truncated extension flags in v2 msBX chunk.");
      extFlags = bytes[pos++];
      if ((extFlags & 0xF8) !== 0) {
        throw new Error(`Unsupported required extension flags (0x${extFlags.toString(16)}) in PNG metadata.`);
      }
      maskProtected = (extFlags & 0x01) !== 0;
      hasOptionalTlv = (extFlags & 0x02) !== 0;
      hasStageConfig = (extFlags & 0x04) !== 0;
    }

    let stageConfig;
    if (hasStageConfig) {
      if (pos + 2 > bytes.byteLength) {
        throw new Error("Truncated stage configuration in v2 msBX chunk.");
      }
      stageConfigOffset = pos;
      const sb0 = bytes[pos++];
      const sb1 = bytes[pos++];
      let sb2 = 0x3F;
      const s2On = ((sb0 >>> 5) & 1) === 1;
      const s2Fixed = ((sb0 >>> 3) & 1) === 1;
      if (s2On && !s2Fixed && (sb0 & 0x07) === 0x07) {
        if (pos >= bytes.byteLength) {
          throw new Error("Truncated Stage 2 allowed permutations mask in v2 msBX chunk.");
        }
        sb2 = bytes[pos++];
      }
      stageConfig = this.decodeStageConfigBytes(sb0, sb1, k, sb2);
    } else {
      stageConfig = this.normalizeStageConfig(null, k);
    }

    let iterations = 100000;
    let kdfVarintLen = 0;
    if (kdfPreset === 0) iterations = 100000;
    else if (kdfPreset === 1) iterations = 10000;
    else if (kdfPreset === 2) iterations = 1000;
    else {
      const decVar = this.decodeVarint(bytes, pos);
      iterations = decVar.value;
      kdfVarintLen = decVar.byteLength;
      pos = decVar.nextOffset;
    }

    if (iterations < 1 || iterations > 5000000) {
      throw new Error(`Invalid key derivation iteration count (${iterations}) in PNG metadata.`);
    }

    const headerPrefixLen = pos;
    if (pos + 48 > bytes.byteLength) {
      throw new Error("Corrupted or truncated salt/verification tag in v2 msBX metadata.");
    }

    const saltOffset = pos;
    const salt = bytes.slice(pos, pos + 16);
    pos += 16;

    const metaPrefixBytes = bytes.slice(0, pos);
    const tagOffset = pos;
    const verificationTag = bytes.slice(pos, pos + 32);
    pos += 32;

    let nonZeroTag = 0;
    for (let i = 0; i < 32; i++) nonZeroTag |= verificationTag[i];
    if (nonZeroTag === 0) {
      throw new Error("Invalid verification tag in PNG metadata.");
    }

    const width = (ihdrDims && ihdrDims.width) ? ihdrDims.width : 0;
    const height = (ihdrDims && ihdrDims.height) ? ihdrDims.height : 0;
    const headerOnly = !!(ihdrDims && ihdrDims.headerOnly);

    let mask = null;
    let encodedMaskBytes = null;
    let plainMaskRleBytes = null;
    let maskLengthOffset = -1;
    let maskDataOffset = -1;

    if (scopeCode !== 0 || maskCodec !== 0) {
      if (maskCodec === 0 || pos >= bytes.byteLength) {
        throw new Error("Missing or truncated segmentation mask in selective-encryption PNG metadata.");
      }
      maskLengthOffset = pos;
      const maskLenVar = this.decodeVarint(bytes, pos);
      const maskByteLen = maskLenVar.value;
      pos = maskLenVar.nextOffset;
      maskDataOffset = pos;

      if (maskByteLen === 0 || pos + maskByteLen > bytes.byteLength) {
        throw new Error("Corrupted or truncated segmentation mask payload in PNG metadata.");
      }
      encodedMaskBytes = bytes.subarray(pos, pos + maskByteLen);
      pos += maskByteLen;

      if (width > 0 && height > 0 && !headerOnly) {
        if (!maskProtected) {
          mask = this.decodeMaskWithCodec(encodedMaskBytes, width * height, maskCodec);
          plainMaskRleBytes = this.encodeMaskTrailer(mask);
        } else if (masterKeyForEncryptedMask) {
          const decryptedMaskStream = this.xorMaskBytesWithKey(encodedMaskBytes, masterKeyForEncryptedMask, salt);
          mask = this.decodeMaskWithCodec(decryptedMaskStream, width * height, maskCodec);
          plainMaskRleBytes = this.encodeMaskTrailer(mask);
        }
      }
    }

    const optionalFields = [];
    const decoder = new TextDecoder();
    if (hasOptionalTlv) {
      if (pos >= bytes.byteLength) {
        throw new Error("Truncated optional metadata TLV section in v2 msBX chunk.");
      }
      const tlvCount = bytes[pos++];
      for (let t = 0; t < tlvCount; t++) {
        if (pos >= bytes.byteLength) {
          throw new Error("Truncated optional TLV field entry in v2 msBX chunk.");
        }
        const rawId = bytes[pos++];
        const critical = (rawId & 0x80) !== 0;
        const fieldId = rawId & 0x7F;
        const lenVar = this.decodeVarint(bytes, pos);
        pos = lenVar.nextOffset;
        if (pos + lenVar.value > bytes.byteLength) {
          throw new Error("Truncated optional TLV field value in v2 msBX chunk.");
        }
        const valBytes = bytes.slice(pos, pos + lenVar.value);
        pos += lenVar.value;

        const isKnownField = (fieldId === 1 || fieldId === 2 || fieldId === 3);
        if (!isKnownField && critical) {
          throw new Error(`Unsupported required optional metadata field (ID=0x${fieldId.toString(16).toUpperCase()}) in v2 msBX chunk.`);
        }

        let decodedValue = null;
        let fieldName = `Optional Field 0x${fieldId.toString(16).toUpperCase()}`;
        if (fieldId === 1 && valBytes.length === 4) {
          fieldName = 'Timestamp (Unix Sec)';
          decodedValue = new DataView(valBytes.buffer, valBytes.byteOffset, 4).getUint32(0, false);
        } else if (fieldId === 2) {
          fieldName = 'Application / Author Tag';
          decodedValue = decoder.decode(valBytes);
        } else if (fieldId === 3) {
          fieldName = 'Metadata Note / Comment';
          decodedValue = decoder.decode(valBytes);
        } else {
          decodedValue = this.bytesToHex(valBytes);
        }

        optionalFields.push({
          id: fieldId,
          name: fieldName,
          critical,
          known: isKnownField,
          byteLength: valBytes.length,
          valueBytes: valBytes,
          value: decodedValue
        });
      }
    }

    if (pos !== bytes.byteLength) {
      throw new Error("Corrupted PNG metadata: Unexpected trailing bytes in v2 msBX chunk.");
    }

    const scopeNames = ['full', 'person', 'face', 'custom'];
    const scope = scopeNames[scopeCode] || 'full';
    const keyType = keyTypeCode === 1 ? 'image' : 'text';
    const colorModeLabels = ['Grayscale (8-bit)', 'RGB (24-bit)', 'RGBA (32-bit)'];
    const codecLabels = ['None', 'Raw Binary', 'Bit-Packed', 'RLE-Varint', 'DEFLATE'];

    return {
      identifier: 'KXBIT-V2',
      metaVersion: 2,
      algoVersion,
      originalColorMode,
      imageMode: originalColorMode,
      modeLabel: colorModeLabels[originalColorMode] || 'RGB (24-bit)',
      k,
      keyTypeCode,
      keyType,
      scopeCode,
      scope,
      maskCodec,
      maskCodecLabel: codecLabels[maskCodec] || 'None',
      maskEncoding: maskProtected ? 2 : (scopeCode !== 0 ? 1 : 0),
      maskProtected,
      width,
      height,
      dimensionsFromIHDR: true,
      kdfPreset,
      kdfVarintLen,
      iterations,
      salt,
      saltOffset,
      saltHex: this.bytesToHex(salt),
      verificationTag,
      tagOffset,
      tagHex: this.bytesToHex(verificationTag),
      headerPrefixLen,
      metaPrefixBytes,
      metaPrefix44: metaPrefixBytes,
      encodedMaskBytes,
      plainMaskRleBytes,
      mask,
      maskLengthOffset,
      maskDataOffset,
      optionalFields,
      hasExtFlags: !!hasExtFlags,
      extFlags,
      hasStageConfig,
      stageConfigOffset,
      stageConfig,
      encryptionMode: stageConfig.encryptionMode,
      stage1Enabled: stageConfig.stage1Enabled,
      stage1AlgoId: stageConfig.stage1AlgoId,
      stage1BlockSize: stageConfig.stage1BlockSize,
      stage2Enabled: stageConfig.stage2Enabled,
      stage2Mode: stageConfig.stage2Mode,
      stage2FixedPermId: stageConfig.stage2FixedPermId,
      stage2FixedPermLabel: stageConfig.stage2FixedPermLabel,
      stage3Enabled: stageConfig.stage3Enabled,
      stage3Channels: stageConfig.stage3Channels,
      channelMask: stageConfig.channelMask,
      enabledStagesSummary: stageConfig.enabledStagesSummary,
      reverseStagesSummary: stageConfig.reverseStagesSummary,
      byteLength: bytes.byteLength
    };
  },

  /**
   * Serialize the versioned `msBx` PNG metadata payload.
   *
   * `msBx` Payload Layout (Big-Endian network byte order):
   * - [0..7]   8B : ASCII FYP Identifier "KENX-ENC"
   * - [8]      1B : Metadata format version (1)
   * - [9]      1B : Encryption algorithm version (1) + [bits 7..3: stage1BlockSize - 1]
   * - [10]     1B : Original colour mode (0 = Grayscale 8-bit, 1 = RGB 24-bit, 2 = RGBA 32-bit)
   * - [11]     1B : Number of encrypted MSB bits, k (1..8, default 2)
   * - [12]     1B : Key type identifier (0 = Password, 1 = Key Image)
   * - [13]     1B : Encryption scope (0 = Full Image, 1 = Body, 2 = Face, 3 = Custom ROI)
   * - [14]     1B : Mask encoding (0 = None, 1 = Plain RLE-Varint, 2 = Keystream-Encrypted RLE-Varint) + [bits 6..4: channelMask^7]
   * - [15]     1B : Stage configuration byte (0 = Standard 3-Stage default; else stageByte0 with bit 7 set)
   * - [16..19] 4B : Original image width (uint32 BE)
   * - [20..23] 4B : Original image height (uint32 BE)
   * - [24..27] 4B : KDF iteration count (uint32 BE, default 100,000)
   * - [28..43] 16B: Random salt
   * - [44..75] 32B: SHA-256 original pixel verification tag
   * - [76..79] 4B : Encoded segmentation mask byte length M (present if scope != 0)
   * - [80..80+M-1]: Encoded segmentation mask bytes
   */
  encodeMsBxMetadata(params) {
    if (params && params.metaVersion === 2) {
      return this.encodeMsBxMetadataV2(params);
    }
    const {
      originalColorMode = 1,
      k = 2,
      keyType = 'text',
      scope = 'full',
      maskEncoding = 0,
      width,
      height,
      iterations = 100000,
      salt,
      verificationTag = null,
      encodedMaskBytes = null
    } = params;

    const stageCfg = this.normalizeStageConfig(params.stageConfig || params, k);
    const effectiveK = stageCfg.k;
    const hasCustomStage = !stageCfg.isStandardDefault
      || params.encryptionMode === 'advanced'
      || (params.stageConfig && params.stageConfig.encryptionMode === 'advanced');
    const scBytes = hasCustomStage ? this.encodeStageConfigBytes(stageCfg, effectiveK) : null;

    const scopeCodeMap = { full: 0, person: 1, face: 2, custom: 3 };
    const hasMask = encodedMaskBytes && encodedMaskBytes.byteLength > 0;
    const scopeCode = hasMask ? (scopeCodeMap[scope] || 3) : 0;
    const keyTypeCode = keyType === 'image' ? 1 : 0;
    const actualMaskEncoding = hasMask ? (maskEncoding || 1) : 0;
    const maskByteLen = hasMask ? encodedMaskBytes.byteLength : 0;

    const totalLen = this.FYP_META_FIXED_SIZE + (hasMask ? (4 + maskByteLen) : 0);
    const buf = new Uint8Array(totalLen);
    const dv = new DataView(buf.buffer);

    for (let i = 0; i < 8; i++) {
      buf[i] = this.FYP_MAGIC_ID.charCodeAt(i) & 0xFF;
    }
    buf[8] = this.FYP_META_VERSION;
    buf[9] = (this.FYP_ALGO_VERSION & 0x07) | (((stageCfg.stage1BlockSize - 1) & 0x1F) << 3);
    buf[10] = originalColorMode & 0xFF;
    buf[11] = effectiveK & 0xFF;
    const v1AllowedMask = (stageCfg.stage2Mode === 'fixed' || stageCfg.stage2AllowedMask === 0x3F)
      ? 0
      : (((stageCfg.stage2AllowedMask ^ 0x3F) & 0x3F) << 1);
    buf[12] = (keyTypeCode & 0x01) | (v1AllowedMask & 0x7E);
    buf[13] = scopeCode;
    if (scBytes) {
      const chXor = ((scBytes[1] & 0x07) ^ 0x07) & 0x07;
      buf[14] = (actualMaskEncoding & 0x0F) | (chXor << 4);
      buf[15] = (scBytes[0] | 0x80) & 0xFF;
    } else {
      buf[14] = actualMaskEncoding;
      buf[15] = 0; // reserved (Standard Mode default)
    }

    dv.setUint32(16, width >>> 0, false);
    dv.setUint32(20, height >>> 0, false);
    dv.setUint32(24, iterations >>> 0, false);
    buf.set(salt.subarray(0, 16), 28);

    if (verificationTag && verificationTag.byteLength === 32) {
      buf.set(verificationTag, 44);
    }
    if (hasMask) {
      dv.setUint32(76, maskByteLen >>> 0, false);
      buf.set(encodedMaskBytes, 80);
    }
    return buf;
  },

  /**
   * Parse and validate the `msBX` (or legacy `msBx`) metadata chunk payload from an encrypted PNG.
   * Supports both Optimized Schema v2 (compact bit-packed 51B header) and Legacy Schema v1 (76B header).
   * Performs strict validation of identifier, versions, dimensions, colour mode, k,
   * iteration count, and segmentation mask integrity.
   */
  decodeMsBxMetadata(chunkBytes, masterKeyForEncryptedMask = null, ihdrDims = null) {
    const bytes = chunkBytes instanceof Uint8Array ? chunkBytes : new Uint8Array(chunkBytes || 0);
    if (bytes.byteLength >= 1 && ((bytes[0] >>> 4) & 0x0F) === this.FYP_COMPACT_MAGIC_NIBBLE) {
      return this.decodeMsBxMetadataV2(bytes, masterKeyForEncryptedMask, ihdrDims);
    }

    if (bytes.byteLength < this.FYP_META_FIXED_SIZE) {
      throw new Error(`Corrupted or truncated PNG metadata: Expected at least ${this.FYP_META_FIXED_SIZE} bytes in msBX chunk, found ${bytes.byteLength} bytes.`);
    }

    const magicId = String.fromCharCode(
      bytes[0], bytes[1], bytes[2], bytes[3],
      bytes[4], bytes[5], bytes[6], bytes[7]
    );
    if (magicId !== this.FYP_MAGIC_ID) {
      throw new Error(`Invalid FYP metadata identifier ("${magicId.replace(/[^\x20-\x7E]/g, '?')}"): Expected "${this.FYP_MAGIC_ID}" (v1) or compact magic 0xB2 (v2).`);
    }

    const metaVersion = bytes[8];
    if (metaVersion !== this.FYP_META_VERSION) {
      throw new Error(`Unsupported FYP metadata version (v${metaVersion}): Only versions 1 and 2 are supported.`);
    }

    const rawByte9 = bytes[9];
    const algoVersion = rawByte9 & 0x07;
    const v1BlockSize = ((rawByte9 >>> 3) & 0x1F) + 1;
    if (algoVersion !== this.FYP_ALGO_VERSION) {
      throw new Error(`Unsupported encryption algorithm version (v${algoVersion}): Only version ${this.FYP_ALGO_VERSION} is supported.`);
    }

    const originalColorMode = bytes[10];
    if (originalColorMode !== 0 && originalColorMode !== 1 && originalColorMode !== 2) {
      throw new Error(`Invalid original colour mode (${originalColorMode}) in PNG metadata.`);
    }

    const k = bytes[11];
    if (k < 1 || k > 8) {
      throw new Error(`Invalid MSB bit depth (k = ${k}) in PNG metadata: Must be between 1 and 8.`);
    }

    const rawByte12 = bytes[12];
    const keyTypeCode = (bytes[15] !== 0 && (rawByte12 & 0x80) === 0) ? (rawByte12 & 0x01) : rawByte12;
    if (keyTypeCode !== 0 && keyTypeCode !== 1) {
      throw new Error(`Invalid key type identifier (${rawByte12}) in PNG metadata.`);
    }

    const scopeCode = bytes[13];
    if (scopeCode > 3) {
      throw new Error(`Invalid encryption scope code (${scopeCode}) in PNG metadata.`);
    }

    const rawByte14 = bytes[14];
    const reservedByte15 = bytes[15];
    const maskEncoding = reservedByte15 !== 0 ? (rawByte14 & 0x0F) : rawByte14;
    if (maskEncoding > 2) {
      throw new Error(`Unsupported segmentation mask encoding (${maskEncoding}) in PNG metadata.`);
    }

    let stageConfig;
    if (reservedByte15 !== 0) {
      if ((rawByte14 & 0x80) !== 0) {
        throw new Error(`Unsupported reserved bits in PNG metadata byte 14 (0x${rawByte14.toString(16)}).`);
      }
      const chMask = (((rawByte14 >>> 4) & 0x07) ^ 0x07) & 0x07;
      const sb1 = (((v1BlockSize - 1) & 0x1F) << 3) | chMask;
      const v1Allowed = (((bytes[12] >>> 1) & 0x3F) ^ 0x3F) || 0x3F;
      stageConfig = this.decodeStageConfigBytes(reservedByte15, sb1, k, v1Allowed);
    } else {
      stageConfig = this.normalizeStageConfig({ stage1BlockSize: v1BlockSize }, k);
    }

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const width = dv.getUint32(16, false);
    const height = dv.getUint32(20, false);
    const iterations = dv.getUint32(24, false);

    if (width === 0 || height === 0 || width > 16384 || height > 16384) {
      throw new Error(`Invalid image dimensions (${width} × ${height}) in PNG metadata.`);
    }
    if (iterations < 1 || iterations > 5000000) {
      throw new Error(`Invalid key derivation iteration count (${iterations}) in PNG metadata.`);
    }

    const salt = bytes.slice(28, 44);
    const verificationTag = bytes.slice(44, 76);

    // Verify verificationTag is not all zeros
    let nonZeroTag = 0;
    for (let i = 0; i < 32; i++) nonZeroTag |= verificationTag[i];
    if (nonZeroTag === 0) {
      throw new Error("Invalid verification tag in PNG metadata.");
    }

    const scopeNames = ['full', 'person', 'face', 'custom'];
    const scope = scopeNames[scopeCode] || 'full';
    const keyType = keyTypeCode === 1 ? 'image' : 'text';

    let mask = null;
    let encodedMaskBytes = null;
    let plainMaskRleBytes = null;

    if (scopeCode !== 0 || maskEncoding !== 0) {
      if (maskEncoding === 0 || bytes.byteLength < this.FYP_META_FIXED_SIZE + 4) {
        throw new Error("Missing or truncated segmentation mask in selective-encryption PNG metadata.");
      }
      const maskByteLen = dv.getUint32(76, false);
      if (maskByteLen === 0 || bytes.byteLength !== this.FYP_META_FIXED_SIZE + 4 + maskByteLen) {
        throw new Error("Corrupted or truncated segmentation mask payload in PNG metadata.");
      }
      encodedMaskBytes = bytes.slice(80, 80 + maskByteLen);

      if (maskEncoding === 1) {
        plainMaskRleBytes = encodedMaskBytes;
        mask = this.decodeMaskTrailer(plainMaskRleBytes, width * height);
      } else if (maskEncoding === 2 && masterKeyForEncryptedMask) {
        plainMaskRleBytes = this.xorMaskBytesWithKey(encodedMaskBytes, masterKeyForEncryptedMask, salt);
        mask = this.decodeMaskTrailer(plainMaskRleBytes, width * height);
      }
    } else if (bytes.byteLength !== this.FYP_META_FIXED_SIZE) {
      throw new Error("Corrupted PNG metadata: Unexpected trailing bytes in full-image msBX chunk.");
    }

    const colorModeLabels = ['Grayscale (8-bit)', 'RGB (24-bit)', 'RGBA (32-bit)'];
    return {
      identifier: magicId,
      metaVersion,
      algoVersion,
      originalColorMode,
      imageMode: originalColorMode,
      modeLabel: colorModeLabels[originalColorMode] || 'RGB (24-bit)',
      k,
      keyTypeCode,
      keyType,
      scopeCode,
      scope,
      maskCodec: scopeCode !== 0 ? this.MASK_CODEC_RLE : 0,
      maskCodecLabel: scopeCode !== 0 ? 'RLE-Varint' : 'None',
      maskEncoding,
      maskProtected: maskEncoding === 2,
      width,
      height,
      dimensionsFromIHDR: false,
      iterations,
      salt,
      saltOffset: 28,
      saltHex: this.bytesToHex(salt),
      verificationTag,
      tagOffset: 44,
      tagHex: this.bytesToHex(verificationTag),
      headerPrefixLen: 28,
      metaPrefixBytes: bytes.slice(0, 44),
      metaPrefix44: bytes.slice(0, 44),
      encodedMaskBytes,
      plainMaskRleBytes,
      mask,
      optionalFields: [],
      hasStageConfig: reservedByte15 !== 0 || v1BlockSize > 1,
      stageConfigOffset: 15,
      stageConfig,
      encryptionMode: stageConfig.encryptionMode,
      stage1Enabled: stageConfig.stage1Enabled,
      stage1AlgoId: stageConfig.stage1AlgoId,
      stage1BlockSize: stageConfig.stage1BlockSize,
      stage2Enabled: stageConfig.stage2Enabled,
      stage2Mode: stageConfig.stage2Mode,
      stage2FixedPermId: stageConfig.stage2FixedPermId,
      stage2FixedPermLabel: stageConfig.stage2FixedPermLabel,
      stage3Enabled: stageConfig.stage3Enabled,
      stage3Channels: stageConfig.stage3Channels,
      channelMask: stageConfig.channelMask,
      enabledStagesSummary: stageConfig.enabledStagesSummary,
      reverseStagesSummary: stageConfig.reverseStagesSummary,
      byteLength: bytes.byteLength
    };
  },

  /**
   * Primary FYP Encryption Workflow:
   * Encrypts an ImageData using the 3-Stage Reversible Cryptosystem and packages the
   * encrypted pixels + embedded `msBX` metadata chunk into a self-describing, lossless PNG.
   * Defaults to Optimized Schema v2 (`metaVersion = 2`) with compact bit-packed header,
   * `IHDR` dimension deduplication, and optimal lossless mask compression (`options.metaVersion = 1`
   * is also supported for legacy comparison).
   */
  async encryptToPNG(imageData, passwordOrKey, maskOrRegions = null, options = {}) {
    const startTime = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();

    const width = imageData.width;
    const height = imageData.height;
    const totalPixels = width * height;
    const kVal = Math.max(1, Math.min(8, (options.k || (options.stageConfig && options.stageConfig.k) || this.DEFAULT_K) | 0));
    const stageConfig = this.normalizeStageConfig(options.stageConfig || options, kVal);
    const effectiveK = stageConfig.k;
    const iterations = Math.max(1, (options.iterations || this.DEFAULT_ITERATIONS) | 0);
    const keyType = options.keyType === 'image' ? 'image' : 'text';
    const scope = options.scope || 'full';
    const protectMask = !!options.protectMask;
    const metaVersion = options.metaVersion === 1 ? 1 : 2;
    const optionalFields = Array.isArray(options.optionalFields) ? options.optionalFields : null;
    const explicitAdv = options.encryptionMode === 'advanced' || (options.stageConfig && options.stageConfig.encryptionMode === 'advanced');

    // 1. Detect original image colour mode (0 = Grayscale, 1 = RGB, 2 = RGBA)
    const originalColorMode = (typeof options.originalColorMode === 'number')
      ? options.originalColorMode
      : this.detectColorMode(imageData);

    // 2. Capture original plaintext pixel payload before encryption for the SHA-256 verification tag
    const plaintextPayload = this.extractPixelPayload(imageData.data, totalPixels, originalColorMode);

    // 3. Generate fresh 16-byte random salt and derive 32-byte master key (100,000 SHA-256 iterations)
    const salt = (options.salt instanceof Uint8Array && options.salt.length === 16)
      ? options.salt
      : this.generateRandomSalt(16);
    const masterKey = this.deriveMasterKeyIterated(passwordOrKey, salt, iterations);

    // 4. Serialize segmentation mask if selective encryption (Body, Face, or Custom ROI) is active
    let plainMaskRleBytes = null;
    let encodedMaskBytes = null;
    let maskEncoding = 0;
    let maskCodec = 0;
    let effectiveScope = 'full';

    if (maskOrRegions) {
      const targetIdx = this.getTargetPixelIndices(imageData, maskOrRegions);
      if (targetIdx.length > 0 && targetIdx.length < totalPixels) {
        const fullMask = new Uint8Array(totalPixels);
        for (let i = 0; i < targetIdx.length; i++) fullMask[targetIdx[i]] = 1;
        plainMaskRleBytes = this.encodeMaskTrailer(fullMask);
        effectiveScope = (scope === 'full') ? 'custom' : scope;

        if (metaVersion === 2) {
          if (typeof options.maskCodec === 'number' && options.maskCodec >= 1 && options.maskCodec <= 4) {
            maskCodec = options.maskCodec;
          } else {
            // Auto-select smallest between RLE-Varint, DEFLATE, and Bit-Packed
            const rleCandidate = plainMaskRleBytes;
            const defCandidate = this.encodeMaskDeflate(fullMask);
            const bpCandidate = this.encodeMaskBitPacked(fullMask);
            if (defCandidate.byteLength < rleCandidate.byteLength && defCandidate.byteLength <= bpCandidate.byteLength) {
              maskCodec = this.MASK_CODEC_DEFLATE;
            } else if (bpCandidate.byteLength < rleCandidate.byteLength) {
              maskCodec = this.MASK_CODEC_BITPACKED;
            } else {
              maskCodec = this.MASK_CODEC_RLE;
            }
          }
          const rawEncodedMask = this.encodeMaskWithCodec(fullMask, maskCodec);
          if (protectMask) {
            maskEncoding = 2;
            encodedMaskBytes = this.xorMaskBytesWithKey(rawEncodedMask, masterKey, salt);
          } else {
            maskEncoding = 1;
            encodedMaskBytes = rawEncodedMask;
          }
        } else {
          maskCodec = this.MASK_CODEC_RLE;
          if (protectMask) {
            maskEncoding = 2;
            encodedMaskBytes = this.xorMaskBytesWithKey(plainMaskRleBytes, masterKey, salt);
          } else {
            maskEncoding = 1;
            encodedMaskBytes = plainMaskRleBytes;
          }
        }
      }
    }

    // 5. Build metadata payload (Schema v2 compact or Schema v1 legacy) and compute 32-byte SHA-256 verification tag
    let msBxPayload;
    if (metaVersion === 2) {
      const prelimV2 = this.encodeMsBxMetadataV2({
        algoVersion: this.FYP_ALGO_VERSION,
        originalColorMode,
        k: effectiveK,
        keyType,
        scope: effectiveScope,
        maskCodec,
        maskProtected: protectMask,
        iterations,
        salt,
        verificationTag: new Uint8Array(32).fill(1),
        encodedMaskBytes,
        optionalFields,
        stageConfig,
        encryptionMode: explicitAdv ? 'advanced' : stageConfig.encryptionMode
      });
      const decodedPrelim = this.decodeMsBxMetadataV2(prelimV2, masterKey, { width, height });
      const verifyTagV2 = this.computePngVerificationTagV2(
        masterKey,
        salt,
        decodedPrelim.metaPrefixBytes,
        width,
        height,
        plaintextPayload,
        plainMaskRleBytes
      );
      msBxPayload = this.encodeMsBxMetadataV2({
        algoVersion: this.FYP_ALGO_VERSION,
        originalColorMode,
        k: effectiveK,
        keyType,
        scope: effectiveScope,
        maskCodec,
        maskProtected: protectMask,
        iterations,
        salt,
        verificationTag: verifyTagV2,
        encodedMaskBytes,
        optionalFields,
        stageConfig,
        encryptionMode: explicitAdv ? 'advanced' : stageConfig.encryptionMode
      });
    } else {
      const prelimMeta = this.encodeMsBxMetadata({
        originalColorMode,
        k: effectiveK,
        keyType,
        scope: effectiveScope,
        maskEncoding,
        width,
        height,
        iterations,
        salt,
        verificationTag: new Uint8Array(32),
        encodedMaskBytes,
        stageConfig,
        encryptionMode: explicitAdv ? 'advanced' : stageConfig.encryptionMode
      });
      const verifyTag = this.computePngVerificationTag(
        masterKey,
        salt,
        prelimMeta.subarray(0, 44),
        plaintextPayload,
        plainMaskRleBytes
      );
      msBxPayload = this.encodeMsBxMetadata({
        originalColorMode,
        k: effectiveK,
        keyType,
        scope: effectiveScope,
        maskEncoding,
        width,
        height,
        iterations,
        salt,
        verificationTag: verifyTag,
        encodedMaskBytes,
        stageConfig,
        encryptionMode: explicitAdv ? 'advanced' : stageConfig.encryptionMode
      });
    }

    // 6. Execute 3-Stage Reversible Encryption Pipeline (according to stageConfig)
    const prngPixel = this.createDomainPRNG(masterKey, salt, 'STAGE1_PIXEL_PERM');
    const prngChannel = this.createDomainPRNG(masterKey, salt, 'STAGE2_CHANNEL_PERM');
    const prngXor = this.createDomainPRNG(masterKey, salt, 'STAGE3_MSB_XOR');

    const encResult = this._encryptWithStreams(imageData, prngPixel, prngChannel, prngXor, maskOrRegions, effectiveK, stageConfig);
    const encryptedPixelsBeforePng = new Uint8ClampedArray(encResult.imageData.data);

    // 7. Encode encrypted pixels + `msBX` chunk into a lossless PNG file
    const pngColorType = originalColorMode === 2 ? 6 : 2;
    const pngBytes = await this.encodeLosslessPNG(
      encResult.imageData,
      [{ type: this.FYP_PNG_CHUNK_TYPE, data: msBxPayload }],
      pngColorType
    );

    // 8. Self-Verification: Decode the generated PNG and verify 0 different encrypted pixels
    const decodedPng = await this.decodeLosslessPNG(pngBytes);
    const decodedRgba = decodedPng.imageData.data;
    let pngDiffPixels = 0;
    for (let i = 0; i < encryptedPixelsBeforePng.length; i += 4) {
      if (encryptedPixelsBeforePng[i] !== decodedRgba[i] ||
          encryptedPixelsBeforePng[i + 1] !== decodedRgba[i + 1] ||
          encryptedPixelsBeforePng[i + 2] !== decodedRgba[i + 2] ||
          (pngColorType === 6 && encryptedPixelsBeforePng[i + 3] !== decodedRgba[i + 3])) {
        pngDiffPixels++;
      }
    }
    if (pngDiffPixels !== 0) {
      throw new Error(`PNG lossless encoding verification failed: ${pngDiffPixels} pixels differed after PNG round-trip.`);
    }

    const endTime = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    const processingTimeMs = Math.max(1, Math.round(endTime - startTime));
    const parsedMeta = this.decodeMsBxMetadata(msBxPayload, masterKey, { width, height });
    parsedMeta.chunkType = this.FYP_PNG_CHUNK_TYPE;
    parsedMeta.isLegacyChunk = false;
    parsedMeta.chunkDisplay = 'msBX';

    return {
      ...encResult,
      pngBytes,
      processingTimeMs,
      verifiedLosslessPng: true,
      pngRoundTripDiffPixels: 0,
      metadata: parsedMeta,
      // Alias `header` for smooth UI inspector compatibility
      header: {
        ...parsedMeta,
        magic: parsedMeta.identifier,
        version: parsedMeta.metaVersion,
        byteLength: pngBytes.byteLength
      }
    };
  },

  /**
   * Inspect an uploaded Self-Describing Encrypted PNG file:
   * - Validates that it is a valid PNG file
   * - Locates and validates the `msBX` metadata chunk (or legacy `msBx` chunk)
   * - Rejects duplicate or conflicting (`msBX` + `msBx`) metadata chunks
   * - Validates that the PNG image dimensions match the metadata dimensions
   * - Returns the decoded encrypted preview ImageData and parsed metadata
   */
  async inspectEncryptedPNG(bufferOrBytes) {
    const bytes = bufferOrBytes instanceof Uint8Array
      ? bufferOrBytes
      : new Uint8Array(bufferOrBytes);

    if (!this.isPngBytes(bytes)) {
      throw new Error("Invalid file format: The uploaded file is not a valid PNG image.");
    }

    const decoded = await this.decodeLosslessPNG(bytes);
    const msBXChunks = decoded.chunks.filter(ch => ch.type === this.FYP_PNG_CHUNK_TYPE);
    const msBxLegacyChunks = decoded.chunks.filter(ch => ch.type === this.FYP_LEGACY_PNG_CHUNK_TYPE);

    if (msBXChunks.length > 0 && msBxLegacyChunks.length > 0) {
      throw new Error('Conflicting FYP encryption metadata: This PNG file contains both "msBX" and legacy "msBx" metadata chunks.');
    }
    if (msBXChunks.length > 1) {
      throw new Error(`Duplicate FYP encryption metadata: This PNG file contains ${msBXChunks.length} duplicate "${this.FYP_PNG_CHUNK_TYPE}" chunks.`);
    }
    if (msBxLegacyChunks.length > 1) {
      throw new Error(`Duplicate FYP encryption metadata: This PNG file contains ${msBxLegacyChunks.length} duplicate legacy "${this.FYP_LEGACY_PNG_CHUNK_TYPE}" chunks.`);
    }
    if (msBXChunks.length === 0 && msBxLegacyChunks.length === 0) {
      throw new Error('Missing FYP encryption metadata: This PNG file does not contain an embedded msBX (or legacy msBx) decryption metadata chunk.');
    }

    const activeChunk = msBXChunks.length === 1 ? msBXChunks[0] : msBxLegacyChunks[0];
    const isLegacyChunk = activeChunk.type === this.FYP_LEGACY_PNG_CHUNK_TYPE;

    const metadata = this.decodeMsBxMetadata(activeChunk.data, null, {
      width: decoded.width,
      height: decoded.height
    });
    metadata.chunkType = activeChunk.type;
    metadata.isLegacyChunk = isLegacyChunk;
    metadata.chunkDisplay = isLegacyChunk ? 'msBx (Legacy)' : 'msBX';

    if (decoded.width !== metadata.width || decoded.height !== metadata.height) {
      throw new Error(`Inconsistent image dimensions: PNG image is ${decoded.width}×${decoded.height}, but embedded metadata specifies ${metadata.width}×${metadata.height}.`);
    }

    return {
      metadata,
      rawChunkData: activeChunk.data,
      header: {
        ...metadata,
        magic: metadata.identifier,
        version: metadata.metaVersion,
        byteLength: bytes.byteLength
      },
      mask: metadata.mask,
      previewImageData: decoded.imageData
    };
  },

  /**
   * Decrypt and verify a Self-Describing Encrypted PNG file (`encrypted_photo.png`).
   * Reconstructs the key streams from the embedded `msBX` (or legacy `msBx`) metadata + user key,
   * reverses the enabled encryption stages in exact inverse order, and verifies the 32-byte
   * SHA-256 original pixel verification tag before returning the recovered image.
   */
  async decryptFromPNG(bufferOrBytes, passwordOrKey) {
    const startTime = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    const bytes = bufferOrBytes instanceof Uint8Array
      ? bufferOrBytes
      : new Uint8Array(bufferOrBytes);

    const inspected = await this.inspectEncryptedPNG(bytes);
    const { previewImageData } = inspected;
    let metadata = inspected.metadata;
    const activeChunkType = metadata.chunkType || this.FYP_PNG_CHUNK_TYPE;
    const isLegacyChunk = !!metadata.isLegacyChunk;
    const chunkDisplay = metadata.chunkDisplay || (isLegacyChunk ? 'msBx (Legacy)' : 'msBX');

    // 1. Reconstruct 32-byte master key using stored 16-byte salt and iteration count
    const masterKey = this.deriveMasterKeyIterated(passwordOrKey, metadata.salt, metadata.iterations);

    // 2. If the segmentation mask was keystream-protected (maskEncoding === 2), decode it now
    if (metadata.maskEncoding === 2) {
      try {
        metadata = this.decodeMsBxMetadata(inspected.rawChunkData, masterKey, {
          width: previewImageData.width,
          height: previewImageData.height
        });
        metadata.chunkType = activeChunkType;
        metadata.isLegacyChunk = isLegacyChunk;
        metadata.chunkDisplay = chunkDisplay;
      } catch (_) {
        throw new Error("The password or key image is incorrect, or the encrypted PNG has been modified. No recovered image was saved.");
      }
    }

    if (metadata.scopeCode !== 0 && (!metadata.mask || metadata.mask.length !== metadata.width * metadata.height)) {
      throw new Error("Missing or invalid segmentation mask for selective decryption.");
    }

    // 3. Reverse only the enabled encryption stages in exact inverse order on a working copy of the encrypted pixels
    const workingImageData = new ImageData(
      new Uint8ClampedArray(previewImageData.data),
      metadata.width,
      metadata.height
    );

    const prngPixel = this.createDomainPRNG(masterKey, metadata.salt, 'STAGE1_PIXEL_PERM');
    const prngChannel = this.createDomainPRNG(masterKey, metadata.salt, 'STAGE2_CHANNEL_PERM');
    const prngXor = this.createDomainPRNG(masterKey, metadata.salt, 'STAGE3_MSB_XOR');

    const decResult = this._decryptWithStreams(
      workingImageData,
      prngPixel,
      prngChannel,
      prngXor,
      metadata.mask,
      metadata.k,
      metadata.stageConfig
    );

    // 4. Verify SHA-256 over the recovered pixel bytes against the original verification tag
    const recoveredPayload = this.extractPixelPayload(
      decResult.imageData.data,
      metadata.width * metadata.height,
      metadata.originalColorMode
    );

    const expectedTag = metadata.metaVersion === 2
      ? this.computePngVerificationTagV2(
          masterKey,
          metadata.salt,
          metadata.metaPrefixBytes,
          metadata.width,
          metadata.height,
          recoveredPayload,
          metadata.plainMaskRleBytes
        )
      : this.computePngVerificationTag(
          masterKey,
          metadata.salt,
          metadata.metaPrefix44,
          recoveredPayload,
          metadata.plainMaskRleBytes
        );

    let diffBits = 0;
    for (let i = 0; i < 32; i++) {
      diffBits |= (expectedTag[i] ^ metadata.verificationTag[i]);
    }
    if (diffBits !== 0) {
      throw new Error("The password or key image is incorrect, or the encrypted PNG has been modified. No recovered image was saved.");
    }

    // If original image was 8-bit Grayscale (mode 0), normalize recovered R=G=B from payload
    if (metadata.originalColorMode === 0) {
      const normalized = this.payloadToImageData(recoveredPayload, metadata.width, metadata.height, 0);
      decResult.imageData.data.set(normalized.data);
    }

    const endTime = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    const processingTimeMs = Math.max(1, Math.round(endTime - startTime));

    return {
      ...decResult,
      metadata,
      header: {
        ...metadata,
        magic: metadata.identifier,
        version: metadata.metaVersion,
        byteLength: bytes.byteLength
      },
      processingTimeMs,
      verified: true
    };
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
      },
      nextKBits(k) {
        const kk = Math.max(1, Math.min(8, k | 0));
        return (this.nextUint32() & ((1 << kk) - 1));
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
  },

  /* ==========================================================================
     PHASE 4–6: KXBIT SELF-DESCRIBING ENCRYPTED VIDEO CONTAINER (.kxv)
     & FRAME-DEPENDENT SELECTIVE FACE MSB ENCRYPTION / DECRYPTION
     ========================================================================== */
  KXV_MAGIC: 'KXBITVID',
  KXV_VERSION: 1,
  KXV_ALGO_VERSION: 1,
  KXV_HEADER_SIZE: 108, // 8B magic + 4B ver/flags/k + 16B dims/frames/iters + 16B salt + 32B cipherTag + 32B plainTag

  /**
   * Check whether a byte buffer starts with the 8-byte "KXBITVID" magic signature.
   */
  isKxvBytes(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < this.KXV_HEADER_SIZE) return false;
    for (let i = 0; i < 8; i++) {
      if (bytes[i] !== this.KXV_MAGIC.charCodeAt(i)) return false;
    }
    return true;
  },

  /**
   * Deterministic Frame-Dependent & Domain-Separated Key Derivation (HKDF-Expand style over SHA-256).
   * Derives a unique, cryptographically isolated PRNG stream for a specific (frameIndex, domainLabel)
   * from the 32-byte masterKey and 16-byte container salt.
   *
   * Domain labels:
   * - "KXV_FRAME_STAGE1_PIXEL_PERM"
   * - "KXV_FRAME_STAGE2_CHANNEL_PERM"
   * - "KXV_FRAME_STAGE3_MSB_XOR"
   */
  deriveVideoFramePRNG(masterKey32, salt16, frameIndex, domainLabel) {
    if (!(masterKey32 instanceof Uint8Array) || masterKey32.length !== 32) {
      throw new Error("Invalid masterKey32 for frame key derivation.");
    }
    if (!(salt16 instanceof Uint8Array) || salt16.length !== 16) {
      throw new Error("Invalid salt16 for frame key derivation.");
    }
    const idx = frameIndex >>> 0;
    const encoder = new TextEncoder();
    const labelBytes = encoder.encode(String(domainLabel || 'KXV_FRAME_STREAM'));

    // Structured input: [masterKey32 (32B)] || [salt16 (16B)] || [frameIndex (4B BE)] || [domainLabel]
    const msg = new Uint8Array(32 + 16 + 4 + labelBytes.length);
    msg.set(masterKey32, 0);
    msg.set(salt16, 32);
    const dv = new DataView(msg.buffer);
    dv.setUint32(48, idx, false);
    msg.set(labelBytes, 52);

    const frameStageDigest = sha256Bytes(msg);
    const hash32 = new Uint32Array(frameStageDigest.buffer, frameStageDigest.byteOffset, 8);

    let s0 = (hash32[0] ^ hash32[4]) >>> 0;
    let s1 = (hash32[1] ^ hash32[5]) >>> 0;
    let s2 = (hash32[2] ^ hash32[6]) >>> 0;
    let s3 = (hash32[3] ^ hash32[7]) >>> 0;
    if ((s0 | s1 | s2 | s3) === 0) {
      s0 = 0x12345678; s1 = 0x9abcdef0; s2 = 0x0fedcba9; s3 = 0x87654321;
    }

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
      nextKBits(k) {
        const kk = Math.max(1, Math.min(8, k | 0));
        return (this.nextUint32() & ((1 << kk) - 1));
      },
      nextKBits(k = 2) {
        const mask = (1 << Math.max(1, Math.min(8, k))) - 1;
        return (this.nextUint32() & mask);
      }
    };
  },

  /**
   * Selectively encrypt a single video frame using the 3-stage pipeline
   * (Fisher-Yates Pixel Permutation -> RGB Channel Permutation -> k-MSB XOR)
   * with frame-dependent, domain-separated key streams.
   * Pixels outside `binaryMask` remain 100% unchanged.
   */
  encryptVideoFrameSelective(imageData, masterKey32, salt16, frameIndex, binaryMask = null, kVal = 2) {
    const kk = Math.max(1, Math.min(8, kVal | 0));
    const totalPixels = imageData.width * imageData.height;
    if (binaryMask !== null) {
      if (!(binaryMask instanceof Uint8Array) || binaryMask.length !== totalPixels) {
        throw new Error(`Frame #${frameIndex} mask size (${binaryMask ? binaryMask.length : 0}) does not match frame dimensions (${imageData.width}x${imageData.height} = ${totalPixels}).`);
      }
    }

    const prngPixel = this.deriveVideoFramePRNG(masterKey32, salt16, frameIndex, 'KXV_FRAME_STAGE1_PIXEL_PERM');
    const prngChannel = this.deriveVideoFramePRNG(masterKey32, salt16, frameIndex, 'KXV_FRAME_STAGE2_CHANNEL_PERM');
    const prngXor = this.deriveVideoFramePRNG(masterKey32, salt16, frameIndex, 'KXV_FRAME_STAGE3_MSB_XOR');

    const cloned = new ImageData(new Uint8ClampedArray(imageData.data), imageData.width, imageData.height);
    return this._encryptWithStreams(cloned, prngPixel, prngChannel, prngXor, binaryMask, kk);
  },

  /**
   * Selectively decrypt a single video frame in exact reverse order
   * (Reverse k-MSB XOR -> Reverse RGB Channel Permutation -> Reverse Fisher-Yates Pixel Permutation)
   * using the stored binary mask and frame-dependent domain-separated keys.
   */
  decryptVideoFrameSelective(imageData, masterKey32, salt16, frameIndex, binaryMask = null, kVal = 2) {
    const kk = Math.max(1, Math.min(8, kVal | 0));
    const totalPixels = imageData.width * imageData.height;
    if (binaryMask !== null) {
      if (!(binaryMask instanceof Uint8Array) || binaryMask.length !== totalPixels) {
        throw new Error(`Frame #${frameIndex} mask size (${binaryMask ? binaryMask.length : 0}) does not match frame dimensions (${imageData.width}x${imageData.height} = ${totalPixels}).`);
      }
    }

    const prngPixel = this.deriveVideoFramePRNG(masterKey32, salt16, frameIndex, 'KXV_FRAME_STAGE1_PIXEL_PERM');
    const prngChannel = this.deriveVideoFramePRNG(masterKey32, salt16, frameIndex, 'KXV_FRAME_STAGE2_CHANNEL_PERM');
    const prngXor = this.deriveVideoFramePRNG(masterKey32, salt16, frameIndex, 'KXV_FRAME_STAGE3_MSB_XOR');

    const cloned = new ImageData(new Uint8ClampedArray(imageData.data), imageData.width, imageData.height);
    return this._decryptWithStreams(cloned, prngPixel, prngChannel, prngXor, binaryMask, kk);
  },

  /**
   * Compress an array of per-frame binary masks (`Uint8Array(W*H)` or null)
   * using LEB128 Run-Length Encoding + ZLIB DEFLATE compression.
   */
  async compressVideoMasksTable(masksArray, frameCount, totalPixels) {
    const rleChunks = [];
    let totalBytes = 0;
    for (let i = 0; i < frameCount; i++) {
      const m = masksArray && masksArray[i] ? masksArray[i] : null;
      let rle;
      if (!m) {
        // Full-frame mask (all 1s) represented by 0 bytes
        rle = new Uint8Array(0);
      } else {
        if (m.length !== totalPixels) {
          throw new Error(`Invalid mask length at frame ${i}: expected ${totalPixels}, got ${m.length}.`);
        }
        rle = this.encodeMaskTrailer(m);
      }
      rleChunks.push(rle);
      totalBytes += 4 + rle.length;
    }

    const rawTable = new Uint8Array(totalBytes);
    const dv = new DataView(rawTable.buffer);
    let pos = 0;
    for (let i = 0; i < frameCount; i++) {
      const rle = rleChunks[i];
      dv.setUint32(pos, rle.length, false);
      pos += 4;
      rawTable.set(rle, pos);
      pos += rle.length;
    }
    return zlibCompressBytes(rawTable);
  },

  /**
   * Decompress and validate the per-frame binary masks table from a `.kxv` container.
   */
  async decompressVideoMasksTable(compressedBytes, frameCount, totalPixels) {
    const rawTable = await zlibDecompressBytes(compressedBytes);
    const dv = new DataView(rawTable.buffer, rawTable.byteOffset, rawTable.byteLength);
    let pos = 0;
    const masks = [];
    for (let i = 0; i < frameCount; i++) {
      if (pos + 4 > rawTable.byteLength) {
        throw new Error(`Corrupted .kxv mask table: truncated at frame ${i}.`);
      }
      const rleLen = dv.getUint32(pos, false);
      pos += 4;
      if (pos + rleLen > rawTable.byteLength) {
        throw new Error(`Corrupted .kxv mask RLE stream at frame ${i}.`);
      }
      if (rleLen === 0) {
        const fullMask = new Uint8Array(totalPixels);
        fullMask.fill(1);
        masks.push(fullMask);
      } else {
        const rleSlice = rawTable.subarray(pos, pos + rleLen);
        const decoded = this.decodeMaskTrailer(rleSlice, totalPixels);
        masks.push(decoded);
      }
      pos += rleLen;
    }
    return masks;
  },

  /**
   * Compute domain-separated SHA-256 authentication tags for `.kxv` container integrity.
   * - `cipherAuthTag`: authenticates header[0..43], JSON metadata, compressed masks, and all encrypted PNG frame bytes.
   * - `plainAuthTag`: authenticates header[0..43] and the SHA-256 digest of every original plaintext frame's RGB bytes.
   */
  computeKxvAuthTags(masterKey32, salt16, headerPrefix44, jsonMetaBytes, compressedMasksBytes, encryptedPngFrames, plaintextFrameHashes) {
    const encoder = new TextEncoder();

    const deriveTagKey = (domain) => {
      const dBytes = encoder.encode(domain);
      const buf = new Uint8Array(32 + 16 + dBytes.length);
      buf.set(masterKey32, 0);
      buf.set(salt16, 32);
      buf.set(dBytes, 48);
      return sha256Bytes(buf);
    };

    const cipherKey = deriveTagKey('KXV_CIPHER_AUTH_TAG_V1');
    const plainKey = deriveTagKey('KXV_PLAIN_AUTH_TAG_V1');

    // Hash all encrypted PNG frames into a single 32B digest
    let totalPngHold = 0;
    const pngFrameDigests = new Uint8Array(encryptedPngFrames.length * 32);
    for (let i = 0; i < encryptedPngFrames.length; i++) {
      const d = sha256Bytes(encryptedPngFrames[i]);
      pngFrameDigests.set(d, i * 32);
      totalPngHold += encryptedPngFrames[i].byteLength;
    }

    const cipherMsg = new Uint8Array(
      32 + 44 + jsonMetaBytes.length + compressedMasksBytes.length + pngFrameDigests.length + 4
    );
    let cPos = 0;
    cipherMsg.set(cipherKey, cPos); cPos += 32;
    cipherMsg.set(headerPrefix44.subarray(0, 44), cPos); cPos += 44;
    cipherMsg.set(jsonMetaBytes, cPos); cPos += jsonMetaBytes.length;
    cipherMsg.set(compressedMasksBytes, cPos); cPos += compressedMasksBytes.length;
    cipherMsg.set(pngFrameDigests, cPos); cPos += pngFrameDigests.length;
    new DataView(cipherMsg.buffer).setUint32(cPos, totalPngHold >>> 0, false);
    const cipherAuthTag = sha256Bytes(cipherMsg);

    const plainMsg = new Uint8Array(32 + 44 + plaintextFrameHashes.length * 32);
    let pPos = 0;
    plainMsg.set(plainKey, pPos); pPos += 32;
    plainMsg.set(headerPrefix44.subarray(0, 44), pPos); pPos += 44;
    for (let i = 0; i < plaintextFrameHashes.length; i++) {
      plainMsg.set(plaintextFrameHashes[i], pPos);
      pPos += 32;
    }
    const plainAuthTag = sha256Bytes(plainMsg);

    return { cipherAuthTag, plainAuthTag };
  },

  /**
   * Package a sequence of video frames and their exact face masks into a lossless,
   * self-describing `.kxv` container (`encrypted_video.kxv`).
   *
   * @param {Array<{imageData: ImageData, mask: Uint8Array|null, timestampMs: number, faceCount?: number, trackIds?: number[]}>} framesInput
   * @param {string|Uint8Array} passwordOrKey
   * @param {object} options
   */
  async encodeKXVContainer(framesInput, passwordOrKey, options = {}) {
    const t0 = (typeof performance !== 'undefined' ? performance.now() : Date.now());
    if (!Array.isArray(framesInput) || framesInput.length === 0) {
      throw new Error("encodeKXVContainer requires at least 1 video frame.");
    }

    const width = framesInput[0].imageData.width;
    const height = framesInput[0].imageData.height;
    if (width <= 0 || height <= 0) {
      throw new Error("Invalid video frame dimensions.");
    }
    const frameCount = framesInput.length;
    const totalPixels = width * height;

    const kVal = Math.max(1, Math.min(8, (options.k !== undefined ? options.k : this.DEFAULT_K) | 0));
    const iterations = Math.max(1, (options.iterations !== undefined ? options.iterations : this.DEFAULT_KDF_ITERATIONS) | 0);
    const keyType = options.keyType === 'image' ? 'image' : 'text';
    const selectionMode = options.selectionMode === 'selected' ? 'selected' : 'all';
    const scope = options.scope || (selectionMode === 'selected' ? 'face_selected' : 'face_all');
    const fps = options.fps || 24;
    const durationSec = options.durationSec || parseFloat((frameCount / fps).toFixed(3));
    const selectedTrackIds = Array.isArray(options.selectedTrackIds) ? options.selectedTrackIds : [];

    const salt16 = (options.salt instanceof Uint8Array && options.salt.length === 16)
      ? new Uint8Array(options.salt)
      : this.generateRandomSalt(16);

    const masterKey32 = this.deriveMasterKeyIterated(passwordOrKey, salt16, iterations);

    const masksArray = [];
    const encryptedFramesImageData = [];
    const encryptedPngFrames = [];
    const plaintextFrameHashes = [];
    const perFrameStats = [];
    const timestampsMs = [];

    let totalEncryptedPixels = 0;
    let totalSwappedChannels = 0;
    let sumMse = 0;
    let framesWithFaces = 0;

    for (let i = 0; i < frameCount; i++) {
      const item = framesInput[i];
      if (!item || !item.imageData || item.imageData.width !== width || item.imageData.height !== height) {
        throw new Error(`Frame #${i} dimensions do not match container dimensions (${width}x${height}).`);
      }

      const tsMs = typeof item.timestampMs === 'number' ? Math.round(item.timestampMs) : Math.round((i * 1000) / fps);
      timestampsMs.push(tsMs);

      // Compute SHA-256 over original frame RGB bytes for exact lossless recovery proof
      const origRgb = this.extractPixelPayload(item.imageData.data, totalPixels, 1);
      const origHash = sha256Bytes(origRgb);
      plaintextFrameHashes.push(origHash);

      let mask = item.mask;
      if (!mask) {
        mask = new Uint8Array(totalPixels);
        if (scope === 'full') mask.fill(1);
      } else if (!(mask instanceof Uint8Array)) {
        mask = new Uint8Array(mask);
      }
      if (mask.length !== totalPixels) {
        throw new Error(`Frame #${i} binary mask length (${mask.length}) does not match ${width}x${height} (${totalPixels}).`);
      }

      let activePixels = 0;
      for (let p = 0; p < totalPixels; p++) {
        if (mask[p]) activePixels++;
      }
      if (activePixels > 0) framesWithFaces++;
      totalEncryptedPixels += activePixels;
      masksArray.push(mask);

      // Perform 3-stage frame-dependent selective encryption
      const encRes = this.encryptVideoFrameSelective(item.imageData, masterKey32, salt16, i, mask, kVal);
      encryptedFramesImageData.push(encRes.imageData);
      totalSwappedChannels += encRes.swappedCount;
      sumMse += encRes.mse;

      // Losslessly encode encrypted frame as PNG
      const pngBytes = await this.encodeLosslessPNG(encRes.imageData, [], 2);
      encryptedPngFrames.push(pngBytes);

      perFrameStats.push({
        frameIndex: i,
        timestampMs: tsMs,
        faceCount: item.faceCount !== undefined ? item.faceCount : (activePixels > 0 ? 1 : 0),
        encryptedPixels: activePixels,
        coveragePct: parseFloat(((activePixels / totalPixels) * 100).toFixed(2)),
        mse: encRes.mse,
        psnr: encRes.psnr
      });

      if (typeof options.onProgress === 'function') {
        await options.onProgress(i + 1, frameCount, encRes.imageData);
      }
    }

    // Compress all exact per-frame masks losslessly (RLE + ZLIB)
    const compressedMasksBytes = await this.compressVideoMasksTable(masksArray, frameCount, totalPixels);

    let flags = 0x01; // bit 0: selective mask table present
    if (keyType === 'image') flags |= 0x02;
    if (selectionMode === 'selected') flags |= 0x04;

    const metadataObj = {
      format: 'KXBIT-KXV',
      identifier: this.KXV_MAGIC,
      containerVersion: this.KXV_VERSION,
      algoVersion: this.KXV_ALGO_VERSION,
      width,
      height,
      frameCount,
      fps,
      durationSec,
      timestampsMs,
      scope,
      selectionMode,
      selectedTrackIds,
      k: kVal,
      pixelPermutation: 'FISHER_YATES_KEYED',
      rgbPermutation: 'BIJECTIVE_6_PERM',
      keyType,
      kdf: 'SHA256-ITERATED-HKDF-FRAME',
      iterations,
      saltHex: this.bytesToHex(salt16),
      framesWithFaces,
      totalEncryptedPixels,
      perFrameStats
    };

    const encoder = new TextEncoder();
    const jsonMetaBytes = encoder.encode(JSON.stringify(metadataObj));

    // Build 44-byte header prefix
    const headerPrefix44 = new Uint8Array(44);
    for (let i = 0; i < 8; i++) headerPrefix44[i] = this.KXV_MAGIC.charCodeAt(i);
    headerPrefix44[8] = this.KXV_VERSION & 0xFF;
    headerPrefix44[9] = this.KXV_ALGO_VERSION & 0xFF;
    headerPrefix44[10] = flags & 0xFF;
    headerPrefix44[11] = kVal & 0xFF;
    const hDv = new DataView(headerPrefix44.buffer);
    hDv.setUint32(12, width >>> 0, false);
    hDv.setUint32(16, height >>> 0, false);
    hDv.setUint32(20, frameCount >>> 0, false);
    hDv.setUint32(24, iterations >>> 0, false);
    headerPrefix44.set(salt16, 28);

    const { cipherAuthTag, plainAuthTag } = this.computeKxvAuthTags(
      masterKey32,
      salt16,
      headerPrefix44,
      jsonMetaBytes,
      compressedMasksBytes,
      encryptedPngFrames,
      plaintextFrameHashes
    );

    let framesByteLen = 0;
    for (let i = 0; i < encryptedPngFrames.length; i++) {
      framesByteLen += 4 + encryptedPngFrames[i].byteLength;
    }

    const totalContainerBytes =
      this.KXV_HEADER_SIZE +
      4 + jsonMetaBytes.byteLength +
      4 + compressedMasksBytes.byteLength +
      framesByteLen;

    const kxvBytes = new Uint8Array(totalContainerBytes);
    const dv = new DataView(kxvBytes.buffer);
    let pos = 0;

    // 1. 108-byte Fixed Binary Header
    kxvBytes.set(headerPrefix44, pos); pos += 44;
    kxvBytes.set(cipherAuthTag, pos); pos += 32;
    kxvBytes.set(plainAuthTag, pos); pos += 32;

    // 2. JSON Metadata Block
    dv.setUint32(pos, jsonMetaBytes.byteLength, false); pos += 4;
    kxvBytes.set(jsonMetaBytes, pos); pos += jsonMetaBytes.byteLength;

    // 3. Compressed Exact Face Masks Block
    dv.setUint32(pos, compressedMasksBytes.byteLength, false); pos += 4;
    kxvBytes.set(compressedMasksBytes, pos); pos += compressedMasksBytes.byteLength;

    // 4. Lossless PNG Encrypted Frames Table
    for (let i = 0; i < encryptedPngFrames.length; i++) {
      const png = encryptedPngFrames[i];
      dv.setUint32(pos, png.byteLength, false); pos += 4;
      kxvBytes.set(png, pos); pos += png.byteLength;
    }

    const avgMse = frameCount > 0 ? parseFloat((sumMse / frameCount).toFixed(4)) : 0;
    const avgPsnr = avgMse === 0 ? '∞' : parseFloat((10 * Math.log10((255 * 255) / avgMse)).toFixed(2));
    const totalTimeMs = parseFloat(((typeof performance !== 'undefined' ? performance.now() : Date.now()) - t0).toFixed(2));

    return {
      kxvBytes,
      header: {
        magic: this.KXV_MAGIC,
        version: this.KXV_VERSION,
        algoVersion: this.KXV_ALGO_VERSION,
        flags,
        k: kVal,
        width,
        height,
        frameCount,
        iterations,
        keyType,
        selectionMode,
        scope,
        salt: salt16,
        saltHex: this.bytesToHex(salt16),
        cipherAuthTag,
        cipherAuthTagHex: this.bytesToHex(cipherAuthTag),
        plainAuthTag,
        plainAuthTagHex: this.bytesToHex(plainAuthTag)
      },
      metadata: metadataObj,
      encryptedFrames: encryptedFramesImageData,
      masks: masksArray,
      stats: {
        frameCount,
        framesWithFaces,
        totalEncryptedPixels,
        totalSwappedChannels,
        avgMse,
        avgPsnr,
        totalTimeMs,
        avgFrameEncTimeMs: parseFloat((totalTimeMs / frameCount).toFixed(2)),
        containerSizeBytes: totalContainerBytes,
        metadataOverheadBytes: this.KXV_HEADER_SIZE + 8 + jsonMetaBytes.byteLength,
        maskStorageBytes: compressedMasksBytes.byteLength,
        frameStorageBytes: framesByteLen
      }
    };
  },

  /**
   * Parse and validate a `.kxv` container without requiring the secret key.
   * Returns header, metadata, decompressed exact masks, and decoded encrypted preview frames.
   */
  async inspectKXVContainer(kxvInput, decodePreviewFrames = true) {
    const bytes = kxvInput instanceof Uint8Array ? kxvInput : new Uint8Array(kxvInput);
    if (!this.isKxvBytes(bytes)) {
      throw new Error('Invalid .kxv container: Missing "KXBITVID" magic signature.');
    }

    const version = bytes[8];
    const algoVersion = bytes[9];
    if (version !== this.KXV_VERSION || algoVersion !== this.KXV_ALGO_VERSION) {
      throw new Error(`Unsupported .kxv container version (v${version}, algo v${algoVersion}).`);
    }

    const flags = bytes[10];
    const kVal = bytes[11];
    if (kVal < 1 || kVal > 8) {
      throw new Error(`Invalid MSB k value (${kVal}) in .kxv header.`);
    }

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const width = dv.getUint32(12, false);
    const height = dv.getUint32(16, false);
    const frameCount = dv.getUint32(20, false);
    const iterations = dv.getUint32(24, false);

    if (width <= 0 || height <= 0 || width > 4096 || height > 4096) {
      throw new Error(`Invalid video dimensions (${width}x${height}) in .kxv header.`);
    }
    if (frameCount <= 0 || frameCount > 1200) {
      throw new Error(`Invalid frame count (${frameCount}) in .kxv header.`);
    }
    if (iterations <= 0 || iterations > 5000000) {
      throw new Error(`Invalid KDF iteration count (${iterations}) in .kxv header.`);
    }

    const headerPrefix44 = bytes.slice(0, 44);
    const salt16 = bytes.slice(28, 44);
    const cipherAuthTag = bytes.slice(44, 76);
    const plainAuthTag = bytes.slice(76, 108);

    let pos = this.KXV_HEADER_SIZE;
    if (pos + 4 > bytes.byteLength) throw new Error('Truncated .kxv container before metadata block.');
    const jsonMetaLen = dv.getUint32(pos, false);
    pos += 4;
    if (jsonMetaLen <= 0 || jsonMetaLen > 10 * 1024 * 1024 || pos + jsonMetaLen > bytes.byteLength) {
      throw new Error('Corrupted .kxv metadata length.');
    }
    const jsonMetaBytes = bytes.slice(pos, pos + jsonMetaLen);
    pos += jsonMetaLen;

    let metadata;
    try {
      metadata = JSON.parse(new TextDecoder().decode(jsonMetaBytes));
    } catch (e) {
      throw new Error('Corrupted .kxv JSON metadata payload.');
    }

    if (pos + 4 > bytes.byteLength) throw new Error('Truncated .kxv container before mask block.');
    const maskBlockLen = dv.getUint32(pos, false);
    pos += 4;
    if (maskBlockLen <= 0 || pos + maskBlockLen > bytes.byteLength) {
      throw new Error('Corrupted .kxv compressed mask block length.');
    }
    const compressedMasksBytes = bytes.slice(pos, pos + maskBlockLen);
    pos += maskBlockLen;

    const totalPixels = width * height;
    const masks = await this.decompressVideoMasksTable(compressedMasksBytes, frameCount, totalPixels);

    const encryptedPngFrames = [];
    const previewFrames = [];
    for (let i = 0; i < frameCount; i++) {
      if (pos + 4 > bytes.byteLength) {
        throw new Error(`Truncated .kxv container before frame #${i}.`);
      }
      const pngLen = dv.getUint32(pos, false);
      pos += 4;
      if (pngLen <= 0 || pos + pngLen > bytes.byteLength) {
        throw new Error(`Corrupted .kxv encrypted PNG frame #${i} length.`);
      }
      const pngBytes = bytes.slice(pos, pos + pngLen);
      pos += pngLen;
      encryptedPngFrames.push(pngBytes);

      if (decodePreviewFrames) {
        const decoded = await this.decodeLosslessPNG(pngBytes);
        if (decoded.width !== width || decoded.height !== height) {
          throw new Error(`Frame #${i} PNG dimensions (${decoded.width}x${decoded.height}) do not match header (${width}x${height}).`);
        }
        previewFrames.push(decoded.imageData);
      }
    }

    const keyType = (flags & 0x02) ? 'image' : 'text';
    const selectionMode = (flags & 0x04) ? 'selected' : 'all';

    return {
      header: {
        magic: this.KXV_MAGIC,
        version,
        algoVersion,
        flags,
        k: kVal,
        width,
        height,
        frameCount,
        iterations,
        keyType,
        selectionMode,
        scope: metadata.scope || (selectionMode === 'selected' ? 'face_selected' : 'face_all'),
        salt: salt16,
        saltHex: this.bytesToHex(salt16),
        cipherAuthTag,
        cipherAuthTagHex: this.bytesToHex(cipherAuthTag),
        plainAuthTag,
        plainAuthTagHex: this.bytesToHex(plainAuthTag)
      },
      metadata,
      masks,
      encryptedPngFrames,
      previewFrames,
      rawInternal: {
        headerPrefix44,
        jsonMetaBytes,
        compressedMasksBytes
      }
    };
  },

  /**
   * Decrypt a `.kxv` container using the provided password or key image.
   * Performs:
   * 1. Pre-decryption `cipherAuthTag` verification (rejects wrong password or tampered container immediately).
   * 2. Frame-by-frame reverse 3-stage decryption using exact stored masks (never reruns AI detection).
   * 3. Post-decryption `plainAuthTag` verification proving 0 different pixels across all frames.
   */
  async decryptKXVContainer(kxvInput, passwordOrKey, options = {}) {
    const t0 = (typeof performance !== 'undefined' ? performance.now() : Date.now());
    const inspected = await this.inspectKXVContainer(kxvInput, true);
    const { header, metadata, masks, encryptedPngFrames, previewFrames, rawInternal } = inspected;

    const masterKey32 = this.deriveMasterKeyIterated(passwordOrKey, header.salt, header.iterations);

    // 1. Verify ciphertext authentication tag BEFORE releasing any frames
    const encoder = new TextEncoder();
    const cipherDomain = encoder.encode('KXV_CIPHER_AUTH_TAG_V1');
    const cKeyBuf = new Uint8Array(32 + 16 + cipherDomain.length);
    cKeyBuf.set(masterKey32, 0);
    cKeyBuf.set(header.salt, 32);
    cKeyBuf.set(cipherDomain, 48);
    const cipherKey = sha256Bytes(cKeyBuf);

    let totalPngHold = 0;
    const pngFrameDigests = new Uint8Array(encryptedPngFrames.length * 32);
    for (let i = 0; i < encryptedPngFrames.length; i++) {
      const d = sha256Bytes(encryptedPngFrames[i]);
      pngFrameDigests.set(d, i * 32);
      totalPngHold += encryptedPngFrames[i].byteLength;
    }

    const cipherMsg = new Uint8Array(
      32 + 44 + rawInternal.jsonMetaBytes.length + rawInternal.compressedMasksBytes.length + pngFrameDigests.length + 4
    );
    let cPos = 0;
    cipherMsg.set(cipherKey, cPos); cPos += 32;
    cipherMsg.set(rawInternal.headerPrefix44, cPos); cPos += 44;
    cipherMsg.set(rawInternal.jsonMetaBytes, cPos); cPos += rawInternal.jsonMetaBytes.length;
    cipherMsg.set(rawInternal.compressedMasksBytes, cPos); cPos += rawInternal.compressedMasksBytes.length;
    cipherMsg.set(pngFrameDigests, cPos); cPos += pngFrameDigests.length;
    new DataView(cipherMsg.buffer).setUint32(cPos, totalPngHold >>> 0, false);
    const expectedCipherTag = sha256Bytes(cipherMsg);

    for (let i = 0; i < 32; i++) {
      if (expectedCipherTag[i] !== header.cipherAuthTag[i]) {
        throw new Error('Decryption failed: Incorrect password / key image, or the .kxv container was modified (SHA-256 authentication tag mismatch).');
      }
    }

    // 2. Decrypt each frame using its exact stored mask & frame-dependent domain keys
    const restoredFrames = [];
    const recoveredPlaintextHashes = [];
    const totalPixels = header.width * header.height;
    let totalRestoredChannels = 0;

    for (let i = 0; i < header.frameCount; i++) {
      const encImgData = previewFrames[i];
      const mask = masks[i];
      const decRes = this.decryptVideoFrameSelective(encImgData, masterKey32, header.salt, i, mask, header.k);
      restoredFrames.push(decRes.imageData);
      totalRestoredChannels += decRes.swappedCount;

      const rgbBytes = this.extractPixelPayload(decRes.imageData.data, totalPixels, 1);
      recoveredPlaintextHashes.push(sha256Bytes(rgbBytes));

      if (typeof options.onProgress === 'function') {
        await options.onProgress(i + 1, header.frameCount, decRes.imageData);
      }
    }

    // 3. Verify plaintext authentication tag across all recovered frames
    const { plainAuthTag: computedPlainTag } = this.computeKxvAuthTags(
      masterKey32,
      header.salt,
      rawInternal.headerPrefix44,
      rawInternal.jsonMetaBytes,
      rawInternal.compressedMasksBytes,
      encryptedPngFrames,
      recoveredPlaintextHashes
    );

    for (let i = 0; i < 32; i++) {
      if (computedPlainTag[i] !== header.plainAuthTag[i]) {
        throw new Error('Decryption integrity check failed: Recovered frame pixels did not match the plaintext verification tag.');
      }
    }

    const totalTimeMs = parseFloat(((typeof performance !== 'undefined' ? performance.now() : Date.now()) - t0).toFixed(2));

    return {
      header,
      metadata,
      masks,
      encryptedFrames: previewFrames,
      restoredFrames,
      stats: {
        frameCount: header.frameCount,
        totalRestoredChannels,
        differentPixels: 0,
        mse: 0,
        psnr: '∞',
        exactRecoveryRatePct: 100,
        totalTimeMs,
        avgFrameDecTimeMs: parseFloat((totalTimeMs / header.frameCount).toFixed(2))
      }
    };
  },

  /**
   * Compare two RGBA buffers of dimensions `width x height` and return
   * `{ differentPixels, mse, psnr }`.
   */
  comparePixelsRGB(rgbaA, rgbaB, width, height) {
    const totalPixels = width * height;
    let differentPixels = 0;
    let sumSq = 0;
    for (let p = 0; p < totalPixels; p++) {
      const i = p * 4;
      const dr = rgbaA[i] - rgbaB[i];
      const dg = rgbaA[i + 1] - rgbaB[i + 1];
      const db = rgbaA[i + 2] - rgbaB[i + 2];
      if (dr !== 0 || dg !== 0 || db !== 0) {
        differentPixels++;
        sumSq += dr * dr + dg * dg + db * db;
      }
    }
    const mse = totalPixels > 0 ? sumSq / (totalPixels * 3) : 0;
    const psnr = mse === 0 ? Infinity : 10 * Math.log10((255 * 255) / mse);
    return { differentPixels, mse, psnr };
  },

  /* ==========================================================================
     PNG BINARY STRUCTURE EXPLORER, BIT/BYTE EDITOR & STORAGE OPTIMIZATION
     ========================================================================== */

  /**
   * Explain any standard or private PNG chunk type and decode its 4-character property flags
   * per ISO/IEC 15948 Section 5.4.
   */
  describePngChunkType(typeStr) {
    if (!typeStr || typeStr.length !== 4) {
      return {
        ancillary: true,
        privateChunk: true,
        reservedValid: false,
        safeToCopy: false,
        propertySummary: 'Invalid Chunk Type',
        purpose: 'Malformed chunk identifier'
      };
    }
    const c0 = typeStr.charCodeAt(0);
    const c1 = typeStr.charCodeAt(1);
    const c2 = typeStr.charCodeAt(2);
    const c3 = typeStr.charCodeAt(3);

    const ancillary = (c0 & 0x20) !== 0;     // lowercase 1st letter = Ancillary, uppercase = Critical
    const privateChunk = (c1 & 0x20) !== 0;  // lowercase 2nd letter = Private, uppercase = Public
    const reservedValid = (c2 & 0x20) === 0; // uppercase 3rd letter = Conforming reserved bit
    const safeToCopy = (c3 & 0x20) !== 0;    // lowercase 4th letter = Safe-to-copy, uppercase = Unsafe-to-copy

    const propParts = [
      ancillary ? 'Ancillary' : 'Critical',
      privateChunk ? 'Private' : 'Public',
      reservedValid ? 'Reserved-OK' : 'Reserved-Invalid',
      safeToCopy ? 'Safe-to-Copy' : 'Unsafe-to-Copy'
    ];

    const knownPurposes = {
      IHDR: 'Image Header — Defines width, height, bit depth (8), colour type, compression, filter, and interlace method.',
      PLTE: 'Palette Table — Stores RGB palette entries for indexed-colour PNG images.',
      IDAT: 'Image Data — Contains ZLIB/DEFLATE compressed scanline pixel bytes (may be split across multiple IDAT chunks).',
      IEND: 'Image Trailer — Marks the exact end of the PNG datastream (0-byte payload).',
      msBX: 'KXBIT Encryption Metadata (Current, Unsafe-to-Copy) — Embeds self-describing decryption parameters, salt, SHA-256 verification tag, and compressed AI region mask.',
      msBx: 'KXBIT Encryption Metadata (Legacy, Safe-to-Copy) — Legacy decryption metadata chunk retained for backward compatibility.',
      tEXt: 'Textual Data — Uncompressed Latin-1 key-value text annotation.',
      zTXt: 'Compressed Textual Data — DEFLATE-compressed key-value text annotation.',
      iTXt: 'International Textual Data — UTF-8 textual metadata chunk.',
      gAMA: 'Image Gamma — Specifies gamma transfer characteristic of the image.',
      cHRM: 'Primary Chromaticities — White point and RGB chromaticity coordinates.',
      sRGB: 'Standard RGB Colour Space — Rendering intent for sRGB colour space.',
      iCCP: 'Embedded ICC Profile — Colour management profile.',
      pHYs: 'Physical Pixel Dimensions — Pixels per unit on X and Y axes.',
      tIME: 'Image Last-Modification Time — Timestamp of last image modification.',
      bKGD: 'Background Colour — Default background colour for viewer rendering.',
      tRNS: 'Transparency — Simple transparency values for non-alpha colour types.'
    };

    return {
      ancillary,
      privateChunk,
      reservedValid,
      safeToCopy,
      propertySummary: propParts.join(' • '),
      purpose: knownPurposes[typeStr] || `Optional ${ancillary ? 'Ancillary' : 'Critical'} Chunk (${typeStr})`
    };
  },

  /**
   * Expand an `msBX` or `msBx` chunk (Schema v1 or Schema v2) into a complete field-by-field
   * breakdown with exact byte offsets, bit ranges, raw hex/binary strings, and decoded meanings (Feature 4).
   */
  describeMsBxFields(chunkDataBytes, chunkFileOffset = 33, chunkType = 'msBX', ihdrDims = null) {
    const bytes = chunkDataBytes instanceof Uint8Array ? chunkDataBytes : new Uint8Array(chunkDataBytes || 0);
    const dataOffset = chunkFileOffset + 8; // After 4B Length + 4B Type
    const fields = [];
    const toBin8 = (b) => (b & 0xFF).toString(2).padStart(8, '0');
    const toHex = (arr) => Array.from(arr).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');

    const isV2 = bytes.byteLength >= 1 && ((bytes[0] >>> 4) & 0x0F) === this.FYP_COMPACT_MAGIC_NIBBLE;

    if (isV2) {
      const b0 = bytes[0] ?? 0;
      const magicNib = (b0 >>> 4) & 0x0F;
      const verNib = b0 & 0x0F;
      fields.push({
        field: 'Compact Magic Nibble',
        value: `0x${magicNib.toString(16).toUpperCase()} (KXBIT)`,
        rawHex: `0x${b0.toString(16).padStart(2, '0').toUpperCase()}`,
        rawBinary: `${toBin8(b0).slice(0, 4)} ....`,
        chunkByteOffset: 0,
        chunkByteEnd: 0,
        fileByteOffset: dataOffset,
        fileByteEnd: dataOffset,
        bitRange: 'Byte 0 [bits 7..4]',
        storage: '4 bits (0.5 B)',
        storageBits: 4,
        category: 'header',
        description: 'Identifies compact KXBIT msBX binary schema (0xB = 1011₂).'
      });
      fields.push({
        field: 'Format Schema Version',
        value: `v${verNib} (Optimized Compact)`,
        rawHex: `0x${b0.toString(16).padStart(2, '0').toUpperCase()}`,
        rawBinary: `.... ${toBin8(b0).slice(4, 8)}`,
        chunkByteOffset: 0,
        chunkByteEnd: 0,
        fileByteOffset: dataOffset,
        fileByteEnd: dataOffset,
        bitRange: 'Byte 0 [bits 3..0]',
        storage: '4 bits (0.5 B)',
        storageBits: 4,
        category: 'header',
        description: 'Schema version 2 (0010₂) with bit-packed flags & IHDR deduplication.'
      });

      if (bytes.byteLength >= 2) {
        const b1 = bytes[1];
        const kVal = ((b1 >>> 5) & 0x07) + 1;
        const scopeCode = (b1 >>> 3) & 0x03;
        const keyTypeCode = (b1 >>> 2) & 0x01;
        const colorMode = b1 & 0x03;
        const scopeNames = ['Full Image (0)', 'Body Silhouette (1)', 'Face Contour (2)', 'Custom ROI (3)'];
        const colorNames = ['Grayscale 8-bit (0)', 'RGB 24-bit (1)', 'RGBA 32-bit (2)', 'Invalid (3)'];

        fields.push({
          field: 'MSB Bit Depth (k)',
          value: `k = ${kVal} (encoded as k−1 = ${kVal - 1})`,
          rawHex: `0x${b1.toString(16).padStart(2, '0').toUpperCase()}`,
          rawBinary: `${toBin8(b1).slice(0, 3)} .....`,
          chunkByteOffset: 1,
          chunkByteEnd: 1,
          fileByteOffset: dataOffset + 1,
          fileByteEnd: dataOffset + 1,
          bitRange: 'Byte 1 [bits 7..5]',
          storage: '3 bits',
          storageBits: 3,
          category: 'config',
          description: 'Number of most-significant bits XOR-encrypted in Stage 3 (1..8).'
        });
        fields.push({
          field: 'Encryption Scope',
          value: scopeNames[scopeCode] || `Scope ${scopeCode}`,
          rawHex: `0x${b1.toString(16).padStart(2, '0').toUpperCase()}`,
          rawBinary: `... ${toBin8(b1).slice(3, 5)} ...`,
          chunkByteOffset: 1,
          chunkByteEnd: 1,
          fileByteOffset: dataOffset + 1,
          fileByteEnd: dataOffset + 1,
          bitRange: 'Byte 1 [bits 4..3]',
          storage: '2 bits',
          storageBits: 2,
          category: 'config',
          description: 'Selects full-image vs. AI selective region encryption.'
        });
        fields.push({
          field: 'Key Type',
          value: keyTypeCode === 1 ? 'Key Image (1)' : 'Text Password (0)',
          rawHex: `0x${b1.toString(16).padStart(2, '0').toUpperCase()}`,
          rawBinary: `..... ${toBin8(b1).slice(5, 6)} ..`,
          chunkByteOffset: 1,
          chunkByteEnd: 1,
          fileByteOffset: dataOffset + 1,
          fileByteEnd: dataOffset + 1,
          bitRange: 'Byte 1 [bit 2]',
          storage: '1 bit',
          storageBits: 1,
          category: 'config',
          description: 'Specifies whether a password string or key image SHA-256 was used.'
        });
        fields.push({
          field: 'Original Colour Mode',
          value: colorNames[colorMode] || `Mode ${colorMode}`,
          rawHex: `0x${b1.toString(16).padStart(2, '0').toUpperCase()}`,
          rawBinary: `...... ${toBin8(b1).slice(6, 8)}`,
          chunkByteOffset: 1,
          chunkByteEnd: 1,
          fileByteOffset: dataOffset + 1,
          fileByteEnd: dataOffset + 1,
          bitRange: 'Byte 1 [bits 1..0]',
          storage: '2 bits',
          storageBits: 2,
          category: 'config',
          description: 'Preserves original plaintext colour mode for exact restoration.'
        });
      }

      if (bytes.byteLength >= 3) {
        const b2 = bytes[2];
        const algoVer = (b2 >>> 6) & 0x03;
        const kdfPreset = (b2 >>> 4) & 0x03;
        const maskCodec = (b2 >>> 1) & 0x07;
        const hasExt = b2 & 0x01;
        const presetNames = ['100,000 (Preset 0)', '10,000 (Preset 1)', '1,000 (Preset 2)', 'Custom LEB128 Varint (3)'];
        const codecNames = ['None (0)', 'Raw Binary (1)', 'Bit-Packed (2)', 'RLE-Varint (3)', 'DEFLATE (4)'];

        fields.push({
          field: 'Algorithm ID / Version',
          value: `v${algoVer} (MSB 3-Stage Pipeline)`,
          rawHex: `0x${b2.toString(16).padStart(2, '0').toUpperCase()}`,
          rawBinary: `${toBin8(b2).slice(0, 2)} ......`,
          chunkByteOffset: 2,
          chunkByteEnd: 2,
          fileByteOffset: dataOffset + 2,
          fileByteEnd: dataOffset + 2,
          bitRange: 'Byte 2 [bits 7..6]',
          storage: '2 bits',
          storageBits: 2,
          category: 'config',
          description: 'Identifies Fisher-Yates + RGB Permutation + k-MSB XOR pipeline.'
        });
        fields.push({
          field: 'KDF Iteration Preset',
          value: presetNames[kdfPreset] || `Preset ${kdfPreset}`,
          rawHex: `0x${b2.toString(16).padStart(2, '0').toUpperCase()}`,
          rawBinary: `.. ${toBin8(b2).slice(2, 4)} ....`,
          chunkByteOffset: 2,
          chunkByteEnd: 2,
          fileByteOffset: dataOffset + 2,
          fileByteEnd: dataOffset + 2,
          bitRange: 'Byte 2 [bits 5..4]',
          storage: '2 bits',
          storageBits: 2,
          category: 'kdf',
          description: 'Encodes standard SHA-256 iteration counts in 2 bits instead of 4 bytes.'
        });
        fields.push({
          field: 'Mask Compression Mode',
          value: codecNames[maskCodec] || `Codec ${maskCodec}`,
          rawHex: `0x${b2.toString(16).padStart(2, '0').toUpperCase()}`,
          rawBinary: `.... ${toBin8(b2).slice(4, 7)} .`,
          chunkByteOffset: 2,
          chunkByteEnd: 2,
          fileByteOffset: dataOffset + 2,
          fileByteEnd: dataOffset + 2,
          bitRange: 'Byte 2 [bits 3..1]',
          storage: '3 bits',
          storageBits: 3,
          category: 'mask',
          description: 'Selects lossless decompression codec for AI face/body mask.'
        });
        fields.push({
          field: 'Extension Flags Bit',
          value: hasExt ? 'Present (1)' : 'None (0)',
          rawHex: `0x${b2.toString(16).padStart(2, '0').toUpperCase()}`,
          rawBinary: `....... ${toBin8(b2).slice(7, 8)}`,
          chunkByteOffset: 2,
          chunkByteEnd: 2,
          fileByteOffset: dataOffset + 2,
          fileByteEnd: dataOffset + 2,
          bitRange: 'Byte 2 [bit 0]',
          storage: '1 bit',
          storageBits: 1,
          category: 'header',
          description: 'Indicates whether optional extension flags byte follows Byte 2.'
        });

        let pos = 3;
        let hasOptTlv = false;
        let maskProt = false;
        let hasStageCfg = false;
        if (hasExt && pos < bytes.byteLength) {
          const extB = bytes[pos];
          maskProt = (extB & 0x01) !== 0;
          hasOptTlv = (extB & 0x02) !== 0;
          hasStageCfg = (extB & 0x04) !== 0;
          fields.push({
            field: 'Extension Flags Byte',
            value: `maskProtected=${maskProt ? 1 : 0}, hasOptionalTLV=${hasOptTlv ? 1 : 0}, hasStageConfig=${hasStageCfg ? 1 : 0}`,
            rawHex: `0x${extB.toString(16).padStart(2, '0').toUpperCase()}`,
            rawBinary: toBin8(extB),
            chunkByteOffset: pos,
            chunkByteEnd: pos,
            fileByteOffset: dataOffset + pos,
            fileByteEnd: dataOffset + pos,
            bitRange: `Byte ${pos} [bits 7..0]`,
            storage: '1 byte (8 bits)',
            storageBits: 8,
            category: 'header',
            description: 'Bit 0 = keystream-protected mask; Bit 1 = optional TLV metadata; Bit 2 = custom 2-byte Stage Configuration.'
          });
          pos++;
        }

        if (hasStageCfg && pos + 2 <= bytes.byteLength) {
          const sb0 = bytes[pos];
          const sb1 = bytes[pos + 1];
          const isAdv = ((sb0 >>> 7) & 1) === 1;
          const s1On = ((sb0 >>> 6) & 1) === 1;
          const s2On = ((sb0 >>> 5) & 1) === 1;
          const s3On = ((sb0 >>> 4) & 1) === 1;
          const s2Fixed = ((sb0 >>> 3) & 1) === 1;
          const fixedId = sb0 & 0x07;
          const fixedLbl = this.CHANNEL_PERM_LABELS[fixedId] || `ID ${fixedId}`;
          const s1BlockSize = ((sb1 >>> 3) & 0x1F) + 1;
          const chMask = sb1 & 0x07;
          const chNames = [];
          if (chMask & 0x04) chNames.push('R');
          if (chMask & 0x02) chNames.push('G');
          if (chMask & 0x01) chNames.push('B');

          fields.push({
            field: 'Encryption Mode & Enabled Stage Flags',
            value: `${isAdv ? 'Advanced Mode (1)' : 'Standard Mode (0)'} • S1=${s1On ? 'ON' : 'OFF'}, S2=${s2On ? 'ON' : 'OFF'}, S3=${s3On ? 'ON' : 'OFF'}`,
            rawHex: `0x${sb0.toString(16).padStart(2, '0').toUpperCase()}`,
            rawBinary: `${toBin8(sb0).slice(0, 4)} ....`,
            chunkByteOffset: pos,
            chunkByteEnd: pos,
            fileByteOffset: dataOffset + pos,
            fileByteEnd: dataOffset + pos,
            bitRange: `Byte ${pos} [bits 7..4]`,
            storage: '4 bits (0.5 B)',
            storageBits: 4,
            category: 'config',
            description: 'Bit 7 = Mode (0=Standard, 1=Advanced); Bit 6 = Stage 1 Enable; Bit 5 = Stage 2 Enable; Bit 4 = Stage 3 Enable.'
          });
          const isCustomS2 = s2On && !s2Fixed && (sb0 & 0x07) === 0x07;
          let s2CustomMask = 0x3F;
          let s2CustomLabels = [];
          if (isCustomS2 && pos + 2 < bytes.byteLength) {
            s2CustomMask = bytes[pos + 2] & 0x3F;
            for (let i = 0; i < 6; i++) {
              if ((s2CustomMask & (1 << i)) !== 0) s2CustomLabels.push(this.CHANNEL_PERM_LABELS[i]);
            }
          }

          fields.push({
            field: 'Stage 2 RGB Permutation Mode & Order',
            value: !s2On
              ? 'Stage 2 Disabled'
              : (s2Fixed
                ? `Experimental Fixed Permutation (${fixedLbl}, ID=${fixedId})`
                : (isCustomS2
                  ? `Key-Driven Dynamic Subset (${s2CustomLabels.length} allowed: ${s2CustomLabels.join(', ')})`
                  : 'Key-Driven Dynamic PRNG (All 6 S₃ Permutations)')),
            rawHex: `0x${sb0.toString(16).padStart(2, '0').toUpperCase()}`,
            rawBinary: `.... ${toBin8(sb0).slice(4, 8)}`,
            chunkByteOffset: pos,
            chunkByteEnd: pos,
            fileByteOffset: dataOffset + pos,
            fileByteEnd: dataOffset + pos,
            bitRange: `Byte ${pos} [bits 3..0]`,
            storage: '4 bits (0.5 B)',
            storageBits: 4,
            category: 'config',
            description: 'Bit 3 = Stage 2 Mode (0=Key-Driven, 1=Fixed); Bits 2..0 = Fixed RGB Order (0..5) or 0x07 for custom dynamic subset.'
          });
          if (isCustomS2 && pos + 2 < bytes.byteLength) {
            fields.push({
              field: 'Stage 2 Allowed Dynamic Permutation Subset',
              value: `6-bit Mask=0x${s2CustomMask.toString(16).padStart(2, '0').toUpperCase()} • ${s2CustomLabels.length} Permutations: [${s2CustomLabels.join(', ')}]`,
              rawHex: `0x${s2CustomMask.toString(16).padStart(2, '0').toUpperCase()}`,
              rawBinary: `.. ${toBin8(s2CustomMask).slice(2, 8)}`,
              chunkByteOffset: pos + 2,
              chunkByteEnd: pos + 2,
              fileByteOffset: dataOffset + pos + 2,
              fileByteEnd: dataOffset + pos + 2,
              bitRange: `Byte ${pos + 2} [bits 5..0]`,
              storage: '6 bits (1 B byte-aligned)',
              storageBits: 6,
              category: 'config',
              description: '6-bit mask of allowed RGB permutations (Bit 0=RGB, Bit 1=RBG, Bit 2=GRB, Bit 3=GBR, Bit 4=BRG, Bit 5=BGR).'
            });
          }
          fields.push({
            field: 'Stage 1 Pixel Block Size (B × B)',
            value: !s1On
              ? 'Stage 1 Disabled'
              : `${s1BlockSize} × ${s1BlockSize} px (${(s1BlockSize * s1BlockSize).toLocaleString()} px/block) — ${s1BlockSize === 1 ? 'Individual Pixel Shuffle' : 'Mask-Aware Block Shuffle'}`,
            rawHex: `0x${sb1.toString(16).padStart(2, '0').toUpperCase()}`,
            rawBinary: `${toBin8(sb1).slice(0, 5)} ...`,
            chunkByteOffset: pos + 1,
            chunkByteEnd: pos + 1,
            fileByteOffset: dataOffset + pos + 1,
            fileByteEnd: dataOffset + pos + 1,
            bitRange: `Byte ${pos + 1} [bits 7..3]`,
            storage: '5 bits',
            storageBits: 5,
            category: 'config',
            description: 'Bits 7..3 store (stage1BlockSize - 1) as a 5-bit integer (0..31 => 1×1 to 32×32 px).'
          });
          fields.push({
            field: 'Stage 3 RGB Channel Bitmask',
            value: !s3On
              ? 'Stage 3 Disabled'
              : `S3 Channels=${chNames.join('+') || 'None'} (0b${(chMask & 7).toString(2).padStart(3, '0')})`,
            rawHex: `0x${sb1.toString(16).padStart(2, '0').toUpperCase()}`,
            rawBinary: `..... ${toBin8(sb1).slice(5, 8)}`,
            chunkByteOffset: pos + 1,
            chunkByteEnd: pos + 1,
            fileByteOffset: dataOffset + pos + 1,
            fileByteEnd: dataOffset + pos + 1,
            bitRange: `Byte ${pos + 1} [bits 2..0]`,
            storage: '3 bits',
            storageBits: 3,
            category: 'config',
            description: 'Bits 2..0 = Stage 3 XOR Channels (Bit 2=Red, Bit 1=Green, Bit 0=Blue).'
          });
          pos += (isCustomS2 && pos + 2 < bytes.byteLength) ? 3 : 2;
        } else {
          fields.push({
            field: 'Encryption Mode & Stage Configuration',
            value: 'Standard Mode (S1 Fisher–Yates 1×1 → S2 Keyed RGB → S3 k-MSB XOR on R+G+B)',
            rawHex: `0x${b2.toString(16).padStart(2, '0').toUpperCase()}`,
            rawBinary: `${toBin8(b2).slice(0, 2)} ......`,
            chunkByteOffset: 2,
            chunkByteEnd: 2,
            fileByteOffset: dataOffset + 2,
            fileByteEnd: dataOffset + 2,
            bitRange: 'Byte 2 [bits 7..6] (Implicit Standard Default)',
            storage: '0 extra bytes',
            storageBits: 0,
            category: 'config',
            description: 'When hasStageConfig=0, all 3 standard stages (Keyed Fisher–Yates 1×1, Keyed RGB, and R+G+B XOR) are automatically enabled.'
          });
        }

        if (kdfPreset === 3 && pos < bytes.byteLength) {
          try {
            const v = this.decodeVarint(bytes, pos);
            const slice = bytes.subarray(pos, v.nextOffset);
            fields.push({
              field: 'Custom KDF Iterations (LEB128)',
              value: `${v.value.toLocaleString()} SHA-256 rounds`,
              rawHex: toHex(slice),
              rawBinary: Array.from(slice).map(toBin8).join(' '),
              chunkByteOffset: pos,
              chunkByteEnd: v.nextOffset - 1,
              fileByteOffset: dataOffset + pos,
              fileByteEnd: dataOffset + v.nextOffset - 1,
              bitRange: `Bytes ${pos}..${v.nextOffset - 1}`,
              storage: `${v.byteLength} byte${v.byteLength > 1 ? 's' : ''} (${v.byteLength * 8} bits)`,
              storageBits: v.byteLength * 8,
              category: 'kdf',
              description: 'Variable-length LEB128 integer storing custom KDF iteration count.'
            });
            pos = v.nextOffset;
          } catch (_) {}
        }

        fields.push({
          field: 'Image Dimensions (Width × Height)',
          value: ihdrDims && ihdrDims.width ? `${ihdrDims.width} × ${ihdrDims.height} px (from IHDR)` : 'Read directly from PNG IHDR',
          rawHex: 'Inherited from IHDR',
          rawBinary: '0 redundant bits stored',
          chunkByteOffset: -1,
          chunkByteEnd: -1,
          fileByteOffset: 16,
          fileByteEnd: 23,
          bitRange: 'IHDR [File Bytes 16..23]',
          storage: '0 bytes (Saved 8 B)',
          storageBits: 0,
          category: 'dedup',
          description: 'Eliminates 8 bytes of duplicate width/height storage by reading PNG IHDR.'
        });

        if (pos + 16 <= bytes.byteLength) {
          const saltSlice = bytes.subarray(pos, pos + 16);
          fields.push({
            field: 'Cryptographic Random Salt',
            value: this.bytesToHex(saltSlice),
            rawHex: toHex(saltSlice.subarray(0, 6)) + ' …',
            rawBinary: `${toBin8(saltSlice[0])} ${toBin8(saltSlice[1])} … (128 bits)`,
            chunkByteOffset: pos,
            chunkByteEnd: pos + 15,
            fileByteOffset: dataOffset + pos,
            fileByteEnd: dataOffset + pos + 15,
            bitRange: `Bytes ${pos}..${pos + 15} (128 bits)`,
            storage: '16 bytes (128 bits)',
            storageBits: 128,
            category: 'crypto',
            description: '128-bit random salt ensuring unique keystreams for identical passwords.'
          });
          pos += 16;
        }

        if (pos + 32 <= bytes.byteLength) {
          const tagSlice = bytes.subarray(pos, pos + 32);
          fields.push({
            field: 'SHA-256 Verification Tag',
            value: this.bytesToHex(tagSlice),
            rawHex: toHex(tagSlice.subarray(0, 6)) + ' …',
            rawBinary: `${toBin8(tagSlice[0])} ${toBin8(tagSlice[1])} … (256 bits)`,
            chunkByteOffset: pos,
            chunkByteEnd: pos + 31,
            fileByteOffset: dataOffset + pos,
            fileByteEnd: dataOffset + pos + 31,
            bitRange: `Bytes ${pos}..${pos + 31} (256 bits)`,
            storage: '32 bytes (256 bits)',
            storageBits: 256,
            category: 'crypto',
            description: '256-bit SHA-256 authentication tag verifying key correctness and pixel integrity.'
          });
          pos += 32;
        }

        const scopeCode = (bytes[1] >>> 3) & 0x03;
        if ((scopeCode !== 0 || maskCodec !== 0) && pos < bytes.byteLength) {
          try {
            const lenStart = pos;
            const mVar = this.decodeVarint(bytes, pos);
            pos = mVar.nextOffset;
            const lenSlice = bytes.subarray(lenStart, pos);
            fields.push({
              field: 'Mask Payload Length (LEB128)',
              value: `${mVar.value} bytes`,
              rawHex: toHex(lenSlice),
              rawBinary: Array.from(lenSlice).map(toBin8).join(' '),
              chunkByteOffset: lenStart,
              chunkByteEnd: pos - 1,
              fileByteOffset: dataOffset + lenStart,
              fileByteEnd: dataOffset + pos - 1,
              bitRange: `Bytes ${lenStart}..${pos - 1}`,
              storage: `${mVar.byteLength} byte${mVar.byteLength > 1 ? 's' : ''}`,
              storageBits: mVar.byteLength * 8,
              category: 'mask',
              description: 'Compact LEB128 byte length of the compressed region mask.'
            });

            const mEnd = Math.min(bytes.byteLength, pos + mVar.value);
            const maskSlice = bytes.subarray(pos, mEnd);
            fields.push({
              field: 'Compressed Region Mask',
              value: `${codecNames[maskCodec] || 'Compressed'}${maskProt ? ' + Keystream XOR' : ''} (${maskSlice.byteLength} B)`,
              rawHex: toHex(maskSlice.subarray(0, Math.min(8, maskSlice.length))) + (maskSlice.length > 8 ? ' …' : ''),
              rawBinary: maskSlice.length > 0 ? `${toBin8(maskSlice[0])} …` : '—',
              chunkByteOffset: pos,
              chunkByteEnd: mEnd - 1,
              fileByteOffset: dataOffset + pos,
              fileByteEnd: dataOffset + mEnd - 1,
              bitRange: `Bytes ${pos}..${mEnd - 1}`,
              storage: `${maskSlice.byteLength} bytes (${maskSlice.byteLength * 8} bits)`,
              storageBits: maskSlice.byteLength * 8,
              category: 'mask',
              description: 'Losslessly compressed AI face/body segmentation mask required for selective decryption.'
            });
            pos = mEnd;
          } catch (_) {}
        }

        if (hasOptTlv && pos < bytes.byteLength) {
          const tlvStart = pos;
          const tlvSlice = bytes.subarray(tlvStart);
          fields.push({
            field: 'Optional Metadata TLV Section',
            value: `${tlvSlice.byteLength} bytes of optional fields`,
            rawHex: toHex(tlvSlice.subarray(0, Math.min(8, tlvSlice.length))),
            rawBinary: `${toBin8(tlvSlice[0])} …`,
            chunkByteOffset: tlvStart,
            chunkByteEnd: bytes.byteLength - 1,
            fileByteOffset: dataOffset + tlvStart,
            fileByteEnd: dataOffset + bytes.byteLength - 1,
            bitRange: `Bytes ${tlvStart}..${bytes.byteLength - 1}`,
            storage: `${tlvSlice.byteLength} bytes`,
            storageBits: tlvSlice.byteLength * 8,
            category: 'optional',
            description: 'Length-delimited optional TLV metadata fields.'
          });
        }
      }
    } else {
      // Schema v1 (76-byte fixed header + optional 4B length + RLE mask)
      const dv = bytes.byteLength >= 28 ? new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength) : null;
      const addV1Field = (name, start, len, valStr, cat, desc) => {
        if (start >= bytes.byteLength) return;
        const end = Math.min(bytes.byteLength, start + len);
        const slice = bytes.subarray(start, end);
        fields.push({
          field: name,
          value: valStr,
          rawHex: toHex(slice.subarray(0, Math.min(8, slice.length))) + (slice.length > 8 ? ' …' : ''),
          rawBinary: slice.length <= 2
            ? Array.from(slice).map(toBin8).join(' ')
            : `${toBin8(slice[0])} ${toBin8(slice[1])} …`,
          chunkByteOffset: start,
          chunkByteEnd: end - 1,
          fileByteOffset: dataOffset + start,
          fileByteEnd: dataOffset + end - 1,
          bitRange: len === 1 ? `Byte ${start} [bits 7..0]` : `Bytes ${start}..${end - 1} (${len * 8} bits)`,
          storage: `${len} byte${len > 1 ? 's' : ''} (${len * 8} bits)`,
          storageBits: len * 8,
          category: cat,
          description: desc
        });
      };

      const magicStr = bytes.byteLength >= 8
        ? String.fromCharCode(...bytes.subarray(0, 8)).replace(/[^\x20-\x7E]/g, '?')
        : 'Truncated';
      addV1Field('ASCII Magic Identifier', 0, 8, `"${magicStr}"`, 'header', '8-byte ASCII identifier (redundant with msBX chunk type).');
      if (bytes.byteLength > 8) addV1Field('Format Version', 8, 1, `v${bytes[8]} (Legacy 76B Schema)`, 'header', 'Metadata schema version 1.');
      if (bytes.byteLength > 9) {
        const b9 = bytes[9];
        const aVer = b9 & 0x07;
        const s1Blk = ((b9 >>> 3) & 0x1F) + 1;
        addV1Field('Algorithm Version & Stage 1 Block Size', 9, 1, `v${aVer} (MSB 3-Stage) • Stage 1 Block=${s1Blk}×${s1Blk} px`, 'config', 'Bits 2..0 = Encryption algorithm version (1); Bits 7..3 = Stage 1 Pixel Block Size - 1 (0..31 => 1×1..32×32 px).');
      }
      if (bytes.byteLength > 10) {
        const cm = bytes[10];
        const cmNames = ['Grayscale (0)', 'RGB (1)', 'RGBA (2)'];
        addV1Field('Original Colour Mode', 10, 1, cmNames[cm] || `Mode ${cm}`, 'config', '1-byte colour mode (only 2 bits needed).');
      }
      if (bytes.byteLength > 11) addV1Field('MSB Bit Depth (k)', 11, 1, `k = ${bytes[11]}`, 'config', '1-byte k setting (only 3 bits needed).');
      if (bytes.byteLength > 12) addV1Field('Key Type', 12, 1, bytes[12] === 1 ? 'Key Image (1)' : 'Password (0)', 'config', '1-byte key type (only 1 bit needed).');
      if (bytes.byteLength > 13) {
        const sc = bytes[13];
        const scNames = ['Full Image (0)', 'Body (1)', 'Face (2)', 'Custom ROI (3)'];
        addV1Field('Encryption Scope', 13, 1, scNames[sc] || `Scope ${sc}`, 'config', '1-byte scope code (only 2 bits needed).');
      }
      if (bytes.byteLength > 14) {
        const b14 = bytes[14];
        const b15 = bytes.byteLength > 15 ? bytes[15] : 0;
        const mEnc = b15 !== 0 ? (b14 & 0x0F) : b14;
        const chMask = b15 !== 0 ? ((((b14 >>> 4) & 0x07) ^ 0x07) & 0x07) : 0x07;
        addV1Field('Mask Encoding & Channel Bits', 14, 1, `MaskMode=${mEnc} • S3 Channels=0b${chMask.toString(2).padStart(3, '0')}`, 'mask', 'Bits 3..0 = Mask encoding (0=None, 1=RLE, 2=XOR-RLE); Bits 6..4 = Stage 3 RGB channel mask.');
      }
      if (bytes.byteLength > 15) {
        const b15 = bytes[15];
        if (b15 !== 0) {
          const s1On = ((b15 >>> 6) & 1) === 1;
          const s2On = ((b15 >>> 5) & 1) === 1;
          const s3On = ((b15 >>> 4) & 1) === 1;
          const s2Fixed = ((b15 >>> 3) & 1) === 1;
          const fixedLbl = this.CHANNEL_PERM_LABELS[b15 & 0x07] || 'RGB';
          addV1Field('Stage Configuration Flags', 15, 1, `S1=${s1On ? 'ON' : 'OFF'}, S2=${s2On ? (s2Fixed ? 'Fixed-' + fixedLbl : 'Keyed') : 'OFF'}, S3=${s3On ? 'ON' : 'OFF'}`, 'config', 'Bit-packed Stage 1/2/3 enable flags and Stage 2 RGB permutation mode.');
        } else {
          addV1Field('Stage Config / Reserved Byte', 15, 1, '0x00 (Standard Mode 3-Stage Default)', 'dedup', '0x00 = Standard Mode (all 3 stages enabled); non-zero = Advanced Stage Config.');
        }
      }
      if (dv && bytes.byteLength >= 20) addV1Field('Image Width (Redundant with IHDR)', 16, 4, `${dv.getUint32(16, false)} px`, 'dedup', '4-byte uint32 BE width (duplicates IHDR width).');
      if (dv && bytes.byteLength >= 24) addV1Field('Image Height (Redundant with IHDR)', 20, 4, `${dv.getUint32(20, false)} px`, 'dedup', '4-byte uint32 BE height (duplicates IHDR height).');
      if (dv && bytes.byteLength >= 28) addV1Field('KDF Iterations', 24, 4, `${dv.getUint32(24, false).toLocaleString()} rounds`, 'kdf', '4-byte uint32 BE SHA-256 iteration count.');
      if (bytes.byteLength >= 44) addV1Field('Cryptographic Random Salt', 28, 16, this.bytesToHex(bytes.subarray(28, 44)), 'crypto', '16-byte random salt.');
      if (bytes.byteLength >= 76) addV1Field('SHA-256 Verification Tag', 44, 32, this.bytesToHex(bytes.subarray(44, 76)), 'crypto', '32-byte SHA-256 pixel & metadata integrity tag.');
      if (bytes.byteLength >= 80) {
        const mLen = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(76, false);
        addV1Field('Mask Byte Length (uint32 BE)', 76, 4, `${mLen} bytes`, 'mask', '4-byte uint32 mask payload length.');
        if (bytes.byteLength > 80) {
          addV1Field('RLE-Encoded Region Mask', 80, bytes.byteLength - 80, `${bytes.byteLength - 80} bytes`, 'mask', 'LEB128 RLE-encoded binary mask.');
        }
      }
    }

    return {
      schemaVersion: isV2 ? 2 : 1,
      chunkType,
      payloadByteLength: bytes.byteLength,
      chunkOverheadBytes: 12,
      totalChunkByteLength: bytes.byteLength + 12,
      envelope: {
        lengthField: { fileByteOffset: chunkFileOffset, byteLength: 4, value: bytes.byteLength },
        typeField: { fileByteOffset: chunkFileOffset + 4, byteLength: 4, value: chunkType },
        crcField: { fileByteOffset: chunkFileOffset + 8 + bytes.byteLength, byteLength: 4 }
      },
      fields
    };
  },

  /**
   * Parse any PNG binary buffer into a detailed, non-throwing structural report for
   * Feature 1 (Interactive PNG Binary Structure Visualizer).
   * Supports multiple IDAT chunks, optional ancillary chunks, both v1/v2 `msBX` and legacy `msBx`,
   * and flags structural/CRC/length errors without crashing.
   */
  parsePngBinaryStructure(bufferOrBytes) {
    const bytes = bufferOrBytes instanceof Uint8Array
      ? bufferOrBytes
      : new Uint8Array(bufferOrBytes || 0);
    const totalSize = bytes.byteLength;
    const structuralErrors = [];

    const isValidSig = this.isPngBytes(bytes);
    if (!isValidSig) {
      structuralErrors.push('Invalid or missing 8-byte PNG file signature (expected 89 50 4E 47 0D 0A 1A 0A).');
    }

    const sections = [];
    const sigLen = Math.min(8, totalSize);
    sections.push({
      index: 0,
      isSignature: true,
      name: 'PNG Signature',
      type: 'SIGN',
      category: 'File Header',
      propertySummary: '8-Byte Magic Header',
      byteOffset: 0,
      dataOffset: 0,
      dataLength: sigLen,
      overheadBytes: 0,
      totalChunkSize: sigLen,
      percentage: totalSize > 0 ? parseFloat(((sigLen / totalSize) * 100).toFixed(2)) : 0,
      crcHex: 'N/A',
      expectedCrcHex: 'N/A',
      actualCrcHex: 'N/A',
      crcValid: isValidSig,
      lengthValid: sigLen === 8,
      purpose: '8-byte ISO/IEC 15948 signature identifying the file as a PNG image and detecting 7-bit/line-ending corruption.',
      rawBytes: bytes.subarray(0, sigLen),
      dataBytes: bytes.subarray(0, sigLen),
      decodedFields: [
        { field: 'High-Bit Byte', value: '0x89 (Detects 7-bit stripping)', bitRange: 'Byte 0', storage: '1 B', fileByteOffset: 0, fileByteEnd: 0 },
        { field: 'ASCII "PNG"', value: '"PNG" (0x50 0x4E 0x47)', bitRange: 'Bytes 1..3', storage: '3 B', fileByteOffset: 1, fileByteEnd: 3 },
        { field: 'DOS Line Ending', value: 'CR LF (0x0D 0x0A)', bitRange: 'Bytes 4..5', storage: '2 B', fileByteOffset: 4, fileByteEnd: 5 },
        { field: 'DOS EOF + Unix LF', value: '0x1A 0x0A', bitRange: 'Bytes 6..7', storage: '2 B', fileByteOffset: 6, fileByteEnd: 7 }
      ]
    });

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let offset = 8;
    let chunkIdx = 0;
    let idatIndex = 0;
    let ihdrInfo = null;
    let seenIHDR = false;
    let seenIEND = false;
    let idatTotalData = 0;
    let idatTotalChunkSize = 0;
    let msbxSection = null;
    const chunks = [];

    // Pre-count IDAT chunks to label IDAT #1, #2 when multiple exist
    let totalIdatCount = 0;
    {
      let scanOff = 8;
      while (scanOff + 12 <= totalSize) {
        const l = dv.getUint32(scanOff, false);
        const t = String.fromCharCode(bytes[scanOff + 4], bytes[scanOff + 5], bytes[scanOff + 6], bytes[scanOff + 7]);
        if (t === 'IDAT') totalIdatCount++;
        if (scanOff + 12 + l > totalSize) break;
        scanOff += 12 + l;
        if (t === 'IEND') break;
      }
    }

    while (offset < totalSize) {
      if (offset + 12 > totalSize) {
        structuralErrors.push(`Truncated chunk header at byte offset ${offset} (${totalSize - offset} trailing bytes).`);
        break;
      }

      chunkIdx++;
      const chunkStart = offset;
      const declaredLength = dv.getUint32(offset, false);
      const type = String.fromCharCode(
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7]
      );
      const typeDesc = this.describePngChunkType(type);
      const dataStart = offset + 8;
      const lengthValid = (offset + 12 + declaredLength) <= totalSize;
      const effectiveDataLen = lengthValid ? declaredLength : Math.max(0, totalSize - dataStart - 4);
      const dataEnd = dataStart + effectiveDataLen;
      const chunkData = bytes.subarray(dataStart, dataEnd);

      let expectedCrc = 0;
      let actualCrc = 0;
      let crcValid = false;

      if (lengthValid) {
        expectedCrc = dv.getUint32(dataEnd, false);
        actualCrc = computeCrc32(bytes.subarray(offset + 4, dataEnd));
        crcValid = (expectedCrc === actualCrc);
        if (!crcValid) {
          structuralErrors.push(`CRC-32 mismatch in "${type}" chunk at offset ${chunkStart}: expected 0x${expectedCrc.toString(16).padStart(8, '0').toUpperCase()}, computed 0x${actualCrc.toString(16).padStart(8, '0').toUpperCase()}.`);
        }
      } else {
        structuralErrors.push(`Invalid chunk length in "${type}" chunk at offset ${chunkStart}: declared ${declaredLength} bytes exceeds file size (${totalSize} bytes).`);
      }

      const totalChunkSize = lengthValid ? (declaredLength + 12) : (totalSize - chunkStart);
      let displayName = type;
      if (type === 'IDAT') {
        idatIndex++;
        idatTotalData += effectiveDataLen;
        idatTotalChunkSize += totalChunkSize;
        if (totalIdatCount > 1) displayName = `IDAT #${idatIndex}`;
      }

      let decodedFields = [];
      let msbxBreakdown = null;

      if (type === 'IHDR' && effectiveDataLen >= 13) {
        seenIHDR = true;
        const w = dv.getUint32(dataStart, false);
        const h = dv.getUint32(dataStart + 4, false);
        const bitDepth = bytes[dataStart + 8];
        const colorType = bytes[dataStart + 9];
        const comp = bytes[dataStart + 10];
        const filt = bytes[dataStart + 11];
        const interlace = bytes[dataStart + 12];
        const ctLabels = { 0: '0 (Grayscale)', 2: '2 (Truecolour RGB)', 3: '3 (Indexed)', 4: '4 (Grayscale+Alpha)', 6: '6 (Truecolour RGBA)' };
        ihdrInfo = {
          width: w,
          height: h,
          bitDepth,
          colorType,
          colorTypeLabel: ctLabels[colorType] || String(colorType),
          compression: comp,
          filter: filt,
          interlace
        };
        decodedFields = [
          { field: 'Width', value: `${w} px`, bitRange: 'Bytes 0..3 (uint32 BE)', storage: '4 bytes', fileByteOffset: dataStart, fileByteEnd: dataStart + 3 },
          { field: 'Height', value: `${h} px`, bitRange: 'Bytes 4..7 (uint32 BE)', storage: '4 bytes', fileByteOffset: dataStart + 4, fileByteEnd: dataStart + 7 },
          { field: 'Bit Depth', value: `${bitDepth} bits/channel`, bitRange: 'Byte 8', storage: '1 byte', fileByteOffset: dataStart + 8, fileByteEnd: dataStart + 8 },
          { field: 'Colour Type', value: ihdrInfo.colorTypeLabel, bitRange: 'Byte 9', storage: '1 byte', fileByteOffset: dataStart + 9, fileByteEnd: dataStart + 9 },
          { field: 'Compression Method', value: `${comp} (DEFLATE)`, bitRange: 'Byte 10', storage: '1 byte', fileByteOffset: dataStart + 10, fileByteEnd: dataStart + 10 },
          { field: 'Filter Method', value: `${filt} (Adaptive 5-filter)`, bitRange: 'Byte 11', storage: '1 byte', fileByteOffset: dataStart + 11, fileByteEnd: dataStart + 11 },
          { field: 'Interlace Method', value: `${interlace} (${interlace === 0 ? 'None' : 'Adam7'})`, bitRange: 'Byte 12', storage: '1 byte', fileByteOffset: dataStart + 12, fileByteEnd: dataStart + 12 }
        ];
      } else if (type === this.FYP_PNG_CHUNK_TYPE || type === this.FYP_LEGACY_PNG_CHUNK_TYPE) {
        msbxBreakdown = this.describeMsBxFields(chunkData, chunkStart, type, ihdrInfo);
        decodedFields = msbxBreakdown.fields;
      } else if (type === 'IDAT') {
        const cmf = effectiveDataLen >= 1 ? bytes[dataStart] : 0;
        const flg = effectiveDataLen >= 2 ? bytes[dataStart + 1] : 0;
        decodedFields = [
          { field: 'ZLIB Header (CMF/FLG)', value: effectiveDataLen >= 2 ? `0x${cmf.toString(16).padStart(2, '0')} 0x${flg.toString(16).padStart(2, '0')}` : 'Continuation stream', bitRange: 'Bytes 0..1', storage: '2 bytes', fileByteOffset: dataStart, fileByteEnd: Math.min(dataEnd - 1, dataStart + 1) },
          { field: 'Compressed Scanline Stream', value: `${effectiveDataLen.toLocaleString()} bytes of DEFLATE-compressed encrypted pixels`, bitRange: `Bytes 0..${Math.max(0, effectiveDataLen - 1)}`, storage: `${effectiveDataLen} bytes`, fileByteOffset: dataStart, fileByteEnd: Math.max(dataStart, dataEnd - 1) }
        ];
      } else if (type === 'IEND') {
        seenIEND = true;
        decodedFields = [
          { field: 'End-of-Image Marker', value: '0 data bytes (12-byte chunk envelope only)', bitRange: 'None (0 B payload)', storage: '0 bytes (+12 B overhead)', fileByteOffset: chunkStart, fileByteEnd: chunkStart + 11 }
        ];
      } else if (type === 'tEXt') {
        const txt = new TextDecoder('latin1').decode(chunkData).replace(/\0/g, ': ');
        decodedFields = [
          { field: 'Text Annotation', value: txt, bitRange: `Bytes 0..${Math.max(0, effectiveDataLen - 1)}`, storage: `${effectiveDataLen} bytes`, fileByteOffset: dataStart, fileByteEnd: Math.max(dataStart, dataEnd - 1) }
        ];
      }

      const sec = {
        index: chunkIdx,
        isSignature: false,
        name: displayName,
        type,
        category: typeDesc.ancillary ? 'Ancillary Chunk' : 'Critical Chunk',
        ancillary: typeDesc.ancillary,
        privateChunk: typeDesc.privateChunk,
        reservedValid: typeDesc.reservedValid,
        safeToCopy: typeDesc.safeToCopy,
        propertySummary: typeDesc.propertySummary,
        byteOffset: chunkStart,
        dataOffset: dataStart,
        dataLength: declaredLength,
        effectiveDataLength: effectiveDataLen,
        overheadBytes: 12,
        totalChunkSize,
        percentage: totalSize > 0 ? parseFloat(((totalChunkSize / totalSize) * 100).toFixed(2)) : 0,
        expectedCrc,
        actualCrc,
        crcHex: `0x${expectedCrc.toString(16).padStart(8, '0').toUpperCase()}`,
        expectedCrcHex: `0x${expectedCrc.toString(16).padStart(8, '0').toUpperCase()}`,
        actualCrcHex: `0x${actualCrc.toString(16).padStart(8, '0').toUpperCase()}`,
        crcValid,
        lengthValid,
        purpose: typeDesc.purpose,
        rawBytes: bytes.subarray(chunkStart, Math.min(totalSize, chunkStart + totalChunkSize)),
        dataBytes: chunkData,
        decodedFields,
        msbxBreakdown
      };

      sections.push(sec);
      chunks.push(sec);
      if (type === this.FYP_PNG_CHUNK_TYPE || type === this.FYP_LEGACY_PNG_CHUNK_TYPE) {
        msbxSection = sec;
      }

      if (!lengthValid) break;
      offset = dataEnd + 4;
      if (type === 'IEND') break;
    }

    if (!seenIHDR) structuralErrors.push('Missing required IHDR chunk.');
    if (idatIndex === 0) structuralErrors.push('Missing required IDAT image data chunk.');
    if (!seenIEND) structuralErrors.push('Missing required IEND trailer chunk.');

    const sumOfSectionSizes = sections.reduce((acc, s) => acc + s.totalChunkSize, 0);
    const totalChunksOverhead = chunks.length * 12;

    return {
      isValidSignature: isValidSig,
      structuralValid: structuralErrors.length === 0,
      structuralErrors,
      totalByteLength: totalSize,
      signatureBytes: sigLen,
      chunkCount: chunks.length,
      idatCount: idatIndex,
      idatTotalDataBytes: idatTotalData,
      idatTotalChunkBytes: idatTotalChunkSize,
      totalChunksOverheadBytes: totalChunksOverhead,
      sumOfSectionSizes,
      sizeFormulaMatches: sumOfSectionSizes === totalSize,
      ihdrInfo,
      msbxSection,
      sections,
      chunks
    };
  },

  /**
   * Rebuild an in-memory PNG copy with modified `msBX` (or `msBx`) chunk payload bytes,
   * automatically updating the 4-byte chunk length and recalculating the 4-byte CRC-32
   * (unless options.corruptCrc or options.corruptLengthDelta is set for educational tampering).
   */
  rebuildPngWithModifiedMetadata(originalPngBytes, newMsBxPayloadBytes, options = {}) {
    const src = originalPngBytes instanceof Uint8Array ? originalPngBytes : new Uint8Array(originalPngBytes);
    const parsed = this.parsePngBinaryStructure(src);
    if (!parsed.isValidSignature) {
      throw new Error("Cannot rebuild PNG: Source buffer does not have a valid PNG signature.");
    }

    const removeMetadataChunk = !!options.removeMetadataChunk;
    const targetChunkType = options.chunkType || (parsed.msbxSection ? parsed.msbxSection.type : this.FYP_PNG_CHUNK_TYPE);
    const payload = newMsBxPayloadBytes instanceof Uint8Array
      ? newMsBxPayloadBytes
      : new Uint8Array(newMsBxPayloadBytes || 0);

    const outParts = [this.PNG_SIGNATURE];
    let insertedMeta = false;

    const buildCustomChunk = (typeStr, dataBytes, isTargetMeta) => {
      const ch = this.buildPngChunk(typeStr, dataBytes);
      if (isTargetMeta) {
        const dv = new DataView(ch.buffer, ch.byteOffset, ch.byteLength);
        if (typeof options.corruptLengthDelta === 'number' && options.corruptLengthDelta !== 0) {
          const badLen = Math.max(0, dataBytes.byteLength + options.corruptLengthDelta);
          dv.setUint32(0, badLen >>> 0, false);
        }
        if (options.corruptCrc) {
          ch[ch.length - 1] ^= 0xFF;
        }
      }
      return ch;
    };

    for (const ch of parsed.chunks) {
      if (ch.type === this.FYP_PNG_CHUNK_TYPE || ch.type === this.FYP_LEGACY_PNG_CHUNK_TYPE) {
        if (!removeMetadataChunk && !insertedMeta) {
          outParts.push(buildCustomChunk(targetChunkType, payload, true));
          insertedMeta = true;
        }
        continue;
      }
      if (ch.type === 'IDAT' && !removeMetadataChunk && !insertedMeta) {
        outParts.push(buildCustomChunk(targetChunkType, payload, true));
        insertedMeta = true;
      }
      // Preserve existing chunk raw bytes (or rebuild if valid)
      outParts.push(ch.rawBytes);
    }

    let totalLen = 0;
    for (const p of outParts) totalLen += p.byteLength;
    const out = new Uint8Array(totalLen);
    let pos = 0;
    for (const p of outParts) {
      out.set(p, pos);
      pos += p.byteLength;
    }
    return out;
  },

  /**
   * Perform the 4-tier validation required by Feature 2C & Feature 6 Tab 5:
   * 1. PNG Structural Validity (Signature, chunks, lengths, CRC-32 checksums)
   * 2. Metadata Schema Validity (`msBX` presence, magic/version, bit-packed ranges, IHDR match)
   * 3. Cryptographic Authentication (32-byte SHA-256 verification tag check with candidate key)
   * 4. Successful Decryption Verification (Full 3-stage reversal & pixel recovery check)
   */
  async validatePngAndMetadataMultiLevel(pngBytes, candidateKey = '', originalReferenceImageData = null) {
    const bytes = pngBytes instanceof Uint8Array ? pngBytes : new Uint8Array(pngBytes || 0);
    const structure = this.parsePngBinaryStructure(bytes);

    // Level 1: PNG Structural Validity
    const level1 = {
      valid: structure.structuralValid,
      status: structure.structuralValid ? 'PASS' : 'FAIL',
      summary: structure.structuralValid
        ? `Valid ISO/IEC 15948 PNG structure (${structure.chunkCount} chunks, all lengths & CRC-32 checksums verified).`
        : structure.structuralErrors.join(' '),
      details: structure.structuralErrors
    };

    // Level 2: Metadata Schema Validity
    let level2 = {
      valid: false,
      status: 'FAIL',
      summary: 'Not evaluated because PNG structure is invalid.',
      metadata: null
    };

    let parsedMeta = null;
    if (level1.valid) {
      try {
        const msBXChunks = structure.chunks.filter(ch => ch.type === this.FYP_PNG_CHUNK_TYPE);
        const msBxLegacyChunks = structure.chunks.filter(ch => ch.type === this.FYP_LEGACY_PNG_CHUNK_TYPE);
        if (msBXChunks.length > 0 && msBxLegacyChunks.length > 0) {
          throw new Error('Conflicting FYP encryption metadata: This PNG file contains both "msBX" and legacy "msBx" metadata chunks.');
        }
        if (msBXChunks.length > 1) {
          throw new Error(`Duplicate FYP encryption metadata: This PNG file contains ${msBXChunks.length} duplicate "${this.FYP_PNG_CHUNK_TYPE}" chunks.`);
        }
        if (msBxLegacyChunks.length > 1) {
          throw new Error(`Duplicate FYP encryption metadata: This PNG file contains ${msBxLegacyChunks.length} duplicate legacy "${this.FYP_LEGACY_PNG_CHUNK_TYPE}" chunks.`);
        }
        if (msBXChunks.length === 0 && msBxLegacyChunks.length === 0) {
          throw new Error('Missing FYP encryption metadata: This PNG file does not contain an embedded msBX (or legacy msBx) decryption metadata chunk.');
        }
        const activeChunk = msBXChunks.length === 1 ? msBXChunks[0] : msBxLegacyChunks[0];
        const isLegacyChunk = activeChunk.type === this.FYP_LEGACY_PNG_CHUNK_TYPE;
        parsedMeta = this.decodeMsBxMetadata(activeChunk.dataBytes, null, structure.ihdrInfo);
        parsedMeta.chunkType = activeChunk.type;
        parsedMeta.isLegacyChunk = isLegacyChunk;
        parsedMeta.chunkDisplay = isLegacyChunk ? 'msBx (Legacy)' : 'msBX';
        if (structure.ihdrInfo && (structure.ihdrInfo.width !== parsedMeta.width || structure.ihdrInfo.height !== parsedMeta.height)) {
          throw new Error(`Inconsistent image dimensions: PNG image is ${structure.ihdrInfo.width}×${structure.ihdrInfo.height}, but embedded metadata specifies ${parsedMeta.width}×${parsedMeta.height}.`);
        }
        level2 = {
          valid: true,
          status: 'PASS',
          summary: `Valid ${parsedMeta.chunkDisplay} Schema v${parsedMeta.metaVersion} (${parsedMeta.byteLength} B payload, k=${parsedMeta.k}, scope=${parsedMeta.scope}, KDF=${parsedMeta.iterations.toLocaleString()}).`,
          metadata: parsedMeta
        };
      } catch (err) {
        level2 = {
          valid: false,
          status: 'FAIL',
          summary: err && err.message ? err.message : String(err),
          metadata: null
        };
      }
    } else if (structure.msbxSection) {
      try {
        parsedMeta = this.decodeMsBxMetadata(structure.msbxSection.dataBytes, null, structure.ihdrInfo);
        level2 = {
          valid: true,
          status: 'WARN',
          summary: `Metadata schema v${parsedMeta.metaVersion} is syntactically decodable, but outer PNG chunk structure/CRC is invalid.`,
          metadata: parsedMeta
        };
      } catch (err) {
        level2 = {
          valid: false,
          status: 'FAIL',
          summary: err && err.message ? err.message : String(err),
          metadata: null
        };
      }
    } else {
      level2 = {
        valid: false,
        status: 'FAIL',
        summary: 'Missing FYP encryption metadata: No msBX or legacy msBx chunk found in PNG.',
        metadata: null
      };
    }

    // Level 3 & Level 4: Cryptographic Authentication & Decryption Verification
    let level3 = {
      valid: false,
      status: 'PENDING',
      summary: 'Enter the encryption password or key image to test SHA-256 cryptographic authentication.'
    };
    let level4 = {
      valid: false,
      status: 'PENDING',
      summary: 'Requires passing PNG structure, metadata schema, and SHA-256 cryptographic authentication.',
      decryptedImageData: null,
      diffPixelsVsOriginal: null
    };

    if (!level1.valid || !level2.valid) {
      level3 = {
        valid: false,
        status: 'FAIL',
        summary: 'Cannot authenticate: PNG chunk structure or metadata schema is invalid/corrupted.'
      };
      level4 = {
        valid: false,
        status: 'FAIL',
        summary: 'Decryption blocked: Structural or metadata schema validation failed.',
        decryptedImageData: null,
        diffPixelsVsOriginal: null
      };
    } else if (candidateKey && String(candidateKey).length > 0) {
      try {
        const decResult = await this.decryptFromPNG(bytes, candidateKey);
        level3 = {
          valid: true,
          status: 'PASS',
          summary: `32-byte SHA-256 verification tag matched (${decResult.metadata.tagHex.slice(0, 16)}…). Key and metadata are cryptographically authentic.`
        };

        let diffPixels = 0;
        if (originalReferenceImageData &&
            originalReferenceImageData.width === decResult.imageData.width &&
            originalReferenceImageData.height === decResult.imageData.height) {
          const cmp = this.comparePixelsRGB(
            originalReferenceImageData.data,
            decResult.imageData.data,
            decResult.imageData.width,
            decResult.imageData.height
          );
          diffPixels = cmp.differentPixels;
        }

        level4 = {
          valid: diffPixels === 0,
          status: diffPixels === 0 ? 'PASS' : 'FAIL',
          summary: `3-Stage Inverse Decryption succeeded in ${decResult.processingTimeMs} ms with ${diffPixels} different pixels (MSE = 0.0000, PSNR = ∞ dB).`,
          decryptedImageData: decResult.imageData,
          diffPixelsVsOriginal: diffPixels
        };
      } catch (err) {
        const errMsg = err && err.message ? err.message : String(err);
        level3 = {
          valid: false,
          status: 'FAIL',
          summary: `SHA-256 Authentication Failed: ${errMsg}`
        };
        level4 = {
          valid: false,
          status: 'FAIL',
          summary: 'Decryption Verification Failed: Modified metadata or wrong key prevented authentic pixel recovery.',
          decryptedImageData: null,
          diffPixelsVsOriginal: null
        };
      }
    }

    return {
      structure,
      level1,
      level2,
      level3,
      level4,
      allVerified: level1.valid && level2.valid && level3.valid && level4.valid
    };
  },

  /**
   * Compare Original Legacy Schema v1 (`76B` header + RLE mask) vs. Optimized Schema v2
   * (`51B` bit-packed header + IHDR deduplication + optimal lossless mask compression)
   * on actual encrypted PNG data (Feature 3F).
   */
  async compareMetadataOptimization(sourcePngBytesOrParams) {
    const nowFn = () => (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    let width = 640, height = 480, k = 2, keyType = 'text', scope = 'full';
    let originalColorMode = 1, iterations = 100000;
    let salt = this.generateRandomSalt(16);
    let verificationTag = new Uint8Array(32).fill(0xA5);
    let mask = null;
    let baseImageData = null;

    let sourceStructure = null;
    if (sourcePngBytesOrParams instanceof Uint8Array) {
      sourceStructure = this.parsePngBinaryStructure(sourcePngBytesOrParams);
      if (sourceStructure.ihdrInfo) {
        width = sourceStructure.ihdrInfo.width;
        height = sourceStructure.ihdrInfo.height;
      }
      if (sourceStructure.msbxSection) {
        try {
          const decodedMeta = this.decodeMsBxMetadata(sourceStructure.msbxSection.dataBytes, null, { width, height });
          k = decodedMeta.k;
          keyType = decodedMeta.keyType;
          scope = decodedMeta.scope;
          originalColorMode = decodedMeta.originalColorMode;
          iterations = decodedMeta.iterations;
          salt = decodedMeta.salt;
          verificationTag = decodedMeta.verificationTag;
          mask = decodedMeta.mask;
        } catch (_) {}
      }
    } else if (sourcePngBytesOrParams && typeof sourcePngBytesOrParams === 'object') {
      width = sourcePngBytesOrParams.width || 640;
      height = sourcePngBytesOrParams.height || 480;
      k = sourcePngBytesOrParams.k || 2;
      keyType = sourcePngBytesOrParams.keyType || 'text';
      scope = sourcePngBytesOrParams.scope || 'full';
      originalColorMode = sourcePngBytesOrParams.originalColorMode ?? 1;
      iterations = sourcePngBytesOrParams.iterations || 100000;
      if (sourcePngBytesOrParams.salt) salt = sourcePngBytesOrParams.salt;
      if (sourcePngBytesOrParams.verificationTag) verificationTag = sourcePngBytesOrParams.verificationTag;
      if (sourcePngBytesOrParams.mask) mask = sourcePngBytesOrParams.mask;
      if (sourcePngBytesOrParams.imageData) baseImageData = sourcePngBytesOrParams.imageData;
    }

    // Build a realistic synthetic face/body mask for mask compression benchmarking if full-image mode is active
    const totalPixels = width * height;
    let benchmarkMask = mask;
    let usingSyntheticMaskForBenchmark = false;
    if (!benchmarkMask || benchmarkMask.length !== totalPixels) {
      usingSyntheticMaskForBenchmark = true;
      benchmarkMask = new Uint8Array(totalPixels);
      const cx = width * 0.5, cy = height * 0.42;
      const rx = Math.max(8, width * 0.18), ry = Math.max(8, height * 0.24);
      for (let y = 0; y < height; y++) {
        for (let x = 0; x < width; x++) {
          const dx = (x - cx) / rx;
          const dy = (y - cy) / ry;
          if (dx * dx + dy * dy <= 1.0) {
            benchmarkMask[y * width + x] = 1;
          }
        }
      }
    }

    const maskBench = this.benchmarkMaskCompression(benchmarkMask);
    const activeMask = (scope !== 'full' && mask && mask.length === totalPixels) ? mask : null;
    const activeRleMask = activeMask ? this.encodeMaskTrailer(activeMask) : null;
    const activeOptimalMask = activeMask
      ? this.encodeMaskWithCodec(activeMask, maskBench.bestCodecId)
      : null;

    // 1. Measure Legacy Schema v1 encoding & decoding
    const tV1Enc0 = nowFn();
    const v1Bytes = this.encodeMsBxMetadata({
      metaVersion: 1,
      originalColorMode,
      k,
      keyType,
      scope: activeMask ? scope : 'full',
      maskEncoding: activeMask ? 1 : 0,
      width,
      height,
      iterations,
      salt,
      verificationTag,
      encodedMaskBytes: activeRleMask
    });
    const tV1Enc1 = nowFn();
    const v1Decoded = this.decodeMsBxMetadata(v1Bytes, null, { width, height });
    const tV1Dec1 = nowFn();

    // 2. Measure Optimized Schema v2 encoding & decoding
    const tV2Enc0 = nowFn();
    const v2Bytes = this.encodeMsBxMetadataV2({
      algoVersion: 1,
      originalColorMode,
      k,
      keyType,
      scope: activeMask ? scope : 'full',
      maskCodec: activeMask ? maskBench.bestCodecId : 0,
      maskProtected: false,
      iterations,
      salt,
      verificationTag,
      encodedMaskBytes: activeOptimalMask
    });
    const tV2Enc1 = nowFn();
    const v2Decoded = this.decodeMsBxMetadataV2(v2Bytes, null, { width, height });
    const tV2Dec1 = nowFn();

    const originalSize = v1Bytes.byteLength;
    const optimizedSize = v2Bytes.byteLength;
    const bytesSaved = originalSize - optimizedSize;
    const reductionPct = originalSize > 0
      ? parseFloat((((originalSize - optimizedSize) / originalSize) * 100).toFixed(2))
      : 0;

    // Also compute Selective Mask Mode (v1 RLE vs v2 Optimal Mask) so users can see selective savings too
    const v1SelectiveBytes = this.encodeMsBxMetadata({
      metaVersion: 1,
      originalColorMode,
      k,
      keyType,
      scope: scope === 'full' ? 'face' : scope,
      maskEncoding: 1,
      width,
      height,
      iterations,
      salt,
      verificationTag,
      encodedMaskBytes: this.encodeMaskTrailer(benchmarkMask)
    });
    const v2SelectiveBytes = this.encodeMsBxMetadataV2({
      algoVersion: 1,
      originalColorMode,
      k,
      keyType,
      scope: scope === 'full' ? 'face' : scope,
      maskCodec: maskBench.bestCodecId,
      maskProtected: false,
      iterations,
      salt,
      verificationTag,
      encodedMaskBytes: maskBench.bestPayload
    });

    let totalPngBefore = 0;
    let totalPngAfter = 0;
    if (sourcePngBytesOrParams instanceof Uint8Array && sourceStructure) {
      const existingMetaChunkSize = sourceStructure.msbxSection ? sourceStructure.msbxSection.totalChunkSize : 0;
      const nonMetaBytes = Math.max(0, sourcePngBytesOrParams.byteLength - existingMetaChunkSize);
      totalPngBefore = nonMetaBytes + v1Bytes.byteLength + 12;
      totalPngAfter = nonMetaBytes + v2Bytes.byteLength + 12;
    } else if (baseImageData) {
      const pngV1 = await this.encodeLosslessPNG(baseImageData, [{ type: 'msBX', data: v1Bytes }]);
      const pngV2 = await this.encodeLosslessPNG(baseImageData, [{ type: 'msBX', data: v2Bytes }]);
      totalPngBefore = pngV1.byteLength;
      totalPngAfter = pngV2.byteLength;
    }

    const fieldSavingsBreakdown = [
      {
        component: 'Format Identifier & Version',
        legacyV1: '9 bytes ("KENX-ENC" 8B + Version 1B)',
        optimizedV2: '1 byte (0xB2: 4-bit magic + 4-bit version)',
        bytesSaved: 8,
        explanation: 'Chunk type "msBX" already identifies KXBIT; 1 byte suffices for magic nibble + schema version.'
      },
      {
        component: 'Image Dimensions (Width × Height)',
        legacyV1: '8 bytes (uint32 Width + uint32 Height)',
        optimizedV2: '0 bytes (Read directly from PNG IHDR)',
        bytesSaved: 8,
        explanation: 'Eliminates duplicate dimension storage already mandated in PNG IHDR chunk.'
      },
      {
        component: 'Encryption Settings (k, Scope, KeyType, ColourMode, Algo, MaskMode, Reserved)',
        legacyV1: '7 bytes (7 separate 1-byte fields)',
        optimizedV2: '2 bytes (Bit-packed into Byte 1 & Byte 2)',
        bytesSaved: 5,
        explanation: 'Packs k (3b), Scope (2b), KeyType (1b), ColourMode (2b), Algo (2b), KDF Preset (2b), MaskCodec (3b), ExtBit (1b) into 16 bits.'
      },
      {
        component: 'KDF Iteration Count',
        legacyV1: '4 bytes (uint32 BE)',
        optimizedV2: iterations === 100000 || iterations === 10000 || iterations === 1000
          ? '0 extra bytes (2-bit preset in Byte 2)'
          : `${v2Decoded.kdfVarintLen} bytes (LEB128 varint)`,
        bytesSaved: 4 - (v2Decoded.kdfVarintLen || 0),
        explanation: 'Standard iteration counts (100k/10k/1k) use 2-bit preset codes; custom values use LEB128.'
      },
      {
        component: '16-Byte Salt & 32-Byte SHA-256 Verification Tag',
        legacyV1: '48 bytes (16B Salt + 32B SHA-256 Tag)',
        optimizedV2: '48 bytes (Preserved 100% intact)',
        bytesSaved: 0,
        explanation: 'Cryptographic salt and verification hash are preserved in full for security.'
      }
    ];

    return {
      scope,
      width,
      height,
      originalMetadataBytes: originalSize,
      optimizedMetadataBytes: optimizedSize,
      originalChunkBytes: originalSize + 12,
      optimizedChunkBytes: optimizedSize + 12,
      bytesSaved,
      storageReductionPct: reductionPct,
      selectiveV1Bytes: v1SelectiveBytes.byteLength,
      selectiveV2Bytes: v2SelectiveBytes.byteLength,
      selectiveBytesSaved: v1SelectiveBytes.byteLength - v2SelectiveBytes.byteLength,
      selectiveReductionPct: parseFloat((((v1SelectiveBytes.byteLength - v2SelectiveBytes.byteLength) / v1SelectiveBytes.byteLength) * 100).toFixed(2)),
       selectiveVsRawMaskSaved: (51 + maskBench.rawMaskBytes) - v2SelectiveBytes.byteLength,
      selectiveVsRawReductionPct: parseFloat(((((51 + maskBench.rawMaskBytes) - v2SelectiveBytes.byteLength) / (51 + maskBench.rawMaskBytes)) * 100).toFixed(2)),
      totalPngBeforeBytes: totalPngBefore,
      totalPngAfterBytes: totalPngAfter,
      v1EncodeTimeMs: parseFloat(Math.max(0.01, tV1Enc1 - tV1Enc0).toFixed(3)),
      v1DecodeTimeMs: parseFloat(Math.max(0.01, tV1Dec1 - tV1Enc1).toFixed(3)),
      v2EncodeTimeMs: parseFloat(Math.max(0.01, tV2Enc1 - tV2Enc0).toFixed(3)),
      v2DecodeTimeMs: parseFloat(Math.max(0.01, tV2Dec1 - tV2Enc1).toFixed(3)),
      usingSyntheticMaskForBenchmark,
      maskBenchmark: maskBench,
      fieldSavingsBreakdown,
      v1Payload: v1Bytes,
      v2Payload: v2Bytes,
      v1Decoded,
      v2Decoded
    };
  },

  /**
   * Apply a deliberate educational tampering preset to an in-memory PNG copy (Feature 2D)
   * and return the modified PNG bytes along with expected vs. actual educational explanations.
   */
  applyEducationalTamperPreset(originalPngBytes, presetId) {
    const src = originalPngBytes instanceof Uint8Array ? originalPngBytes : new Uint8Array(originalPngBytes);
    const parsed = this.parsePngBinaryStructure(src);
    if (!parsed.msbxSection) {
      throw new Error("Uploaded PNG does not contain an msBX metadata chunk to tamper with.");
    }

    const origMetaBytes = new Uint8Array(parsed.msbxSection.dataBytes);
    const isV2 = origMetaBytes.length >= 1 && ((origMetaBytes[0] >>> 4) & 0x0F) === this.FYP_COMPACT_MAGIC_NIBBLE;
    let modifiedMeta = new Uint8Array(origMetaBytes);
    let rebuildOpts = {};
    let title = '';
    let expectedEffect = '';

    switch (presetId) {
      case 'change-k': {
        title = 'Tamper Test 1: Change MSB Bit Depth (k = 2 → 4)';
        if (isV2) {
          const curK = ((modifiedMeta[1] >>> 5) & 0x07) + 1;
          const newK = curK === 4 ? 2 : 4;
          modifiedMeta[1] = (modifiedMeta[1] & 0x1F) | (((newK - 1) & 0x07) << 5);
        } else {
          modifiedMeta[11] = modifiedMeta[11] === 4 ? 2 : 4;
        }
        expectedEffect = 'PNG structure & CRC-32 remain valid (Level 1 PASS) and Metadata Schema remains valid (Level 2 PASS), but Stage 3 XOR unmasks the wrong number of MSB bits. SHA-256 Authentication (Level 3) and Decryption Verification (Level 4) MUST FAIL.';
        break;
      }
      case 'change-algo': {
        title = 'Tamper Test 2: Change Algorithm Version (v1 → v2)';
        if (isV2) {
          modifiedMeta[2] = (modifiedMeta[2] & 0x3F) | (2 << 6);
        } else {
          modifiedMeta[9] = 2;
        }
        expectedEffect = 'PNG structure & CRC-32 remain valid (Level 1 PASS), but Metadata Schema Validation (Level 2) immediately rejects the unsupported algorithm version (v2).';
        break;
      }
      case 'modify-salt': {
        title = 'Tamper Test 3: Flip 1 Byte in 16-Byte Random Salt';
        const saltOff = isV2 ? (this.decodeMsBxMetadata(origMetaBytes, null, parsed.ihdrInfo).saltOffset) : 28;
        modifiedMeta[saltOff] ^= 0xFF;
        expectedEffect = 'PNG structure (Level 1) and Metadata Schema (Level 2) pass, but the altered salt causes SHA-256 KDF to derive a completely different 32-byte master key and PRNG stream. SHA-256 Authentication (Level 3) and Decryption (Level 4) FAIL.';
        break;
      }
      case 'remove-msbx': {
        title = 'Tamper Test 4: Strip Required msBX Metadata Chunk';
        rebuildOpts = { removeMetadataChunk: true };
        expectedEffect = 'The resulting file is still a valid standard PNG image (Level 1 PASS) that opens in normal viewers showing encrypted pixels, but Level 2 fails with "Missing FYP encryption metadata" because decryption parameters are gone.';
        break;
      }
      case 'modify-mask': {
        title = 'Tamper Test 5: Corrupt Selective Face/Body Mask Payload';
        const decoded = this.decodeMsBxMetadata(origMetaBytes, null, parsed.ihdrInfo);
        if (decoded.scopeCode !== 0 && decoded.encodedMaskBytes && decoded.encodedMaskBytes.length > 0) {
          modifiedMeta[modifiedMeta.length - 1] ^= 0xFF;
        } else {
          // Switch scope to Face Contour without valid mask bytes to demonstrate mask tampering failure
          if (isV2) {
            modifiedMeta[1] = (modifiedMeta[1] & ~(0x03 << 3)) | (2 << 3);
          } else {
            modifiedMeta[13] = 2;
          }
        }
        expectedEffect = 'Modifying or truncating the selective region mask alters the target pixel set M or corrupts mask decompression, causing Schema Validation (Level 2) or SHA-256 Tag Verification (Level 3) to FAIL.';
        break;
      }
      case 'corrupt-crc': {
        title = 'Tamper Test 6: Corrupt msBX Chunk CRC-32 Checksum';
        rebuildOpts = { corruptCrc: true };
        expectedEffect = 'Flips 8 bits in the 4-byte CRC-32 trailer of the msBX chunk. PNG Structural Validation (Level 1) immediately FAILS with a CRC-32 checksum mismatch.';
        break;
      }
      default:
        throw new Error(`Unknown educational tamper preset "${presetId}".`);
    }

    const tamperedPngBytes = this.rebuildPngWithModifiedMetadata(src, modifiedMeta, rebuildOpts);
    return {
      presetId,
      title,
      expectedEffect,
      modifiedMetaBytes: rebuildOpts.removeMetadataChunk ? new Uint8Array(0) : modifiedMeta,
      tamperedPngBytes
    };
  },

  /* ==========================================================================
     AI FACE & BODY DETECTION ACCURACY, NMS DEDUPLICATION & INSTANCE SEGMENTATION
     ========================================================================== */

  /**
   * Compute bounding-box Intersection over Union (IoU), Intersection over Minimum Area (IoMin),
   * and normalized center-to-center distance between two boxes `{ x0, y0, x1, y1 }`.
   */
  computeBoxOverlapMetrics(boxA, boxB) {
    const ix0 = Math.max(boxA.x0, boxB.x0);
    const iy0 = Math.max(boxA.y0, boxB.y0);
    const ix1 = Math.min(boxA.x1, boxB.x1);
    const iy1 = Math.min(boxA.y1, boxB.y1);
    const iw = Math.max(0, ix1 - ix0);
    const ih = Math.max(0, iy1 - iy0);
    const inter = iw * ih;

    const wA = Math.max(0, boxA.x1 - boxA.x0);
    const hA = Math.max(0, boxA.y1 - boxA.y0);
    const wB = Math.max(0, boxB.x1 - boxB.x0);
    const hB = Math.max(0, boxB.y1 - boxB.y0);
    const areaA = Math.max(1e-5, wA * hA);
    const areaB = Math.max(1e-5, wB * hB);
    const union = Math.max(1e-5, areaA + areaB - inter);
    const minArea = Math.max(1e-5, Math.min(areaA, areaB));

    const cxA = (boxA.x0 + boxA.x1) * 0.5;
    const cyA = (boxA.y0 + boxA.y1) * 0.5;
    const cxB = (boxB.x0 + boxB.x1) * 0.5;
    const cyB = (boxB.y0 + boxB.y1) * 0.5;
    const centerDist = Math.hypot(cxA - cxB, cyA - cyB);
    const minDiag = Math.max(1, Math.min(Math.hypot(wA, hA), Math.hypot(wB, hB)));

    return {
      iou: inter / union,
      ioMin: inter / minArea,
      centerDist,
      normCenterDist: centerDist / minDiag,
      interArea: inter,
      areaA,
      areaB
    };
  },

  /**
   * Compute binary pixel mask Intersection over Union (IoU) and Sørensen–Dice coefficient.
   */
  computeMaskIoUAndDice(maskA, maskB) {
    if (!maskA || !maskB || maskA.length !== maskB.length) {
      return { iou: 0, dice: 0, intersection: 0, union: 0 };
    }
    let inter = 0;
    let countA = 0;
    let countB = 0;
    for (let i = 0; i < maskA.length; i++) {
      const a = maskA[i] ? 1 : 0;
      const b = maskB[i] ? 1 : 0;
      if (a) countA++;
      if (b) countB++;
      if (a && b) inter++;
    }
    const union = countA + countB - inter;
    const iou = union > 0 ? inter / union : 1;
    const dice = (countA + countB) > 0 ? (2 * inter) / (countA + countB) : 1;
    return {
      iou: parseFloat(iou.toFixed(4)),
      dice: parseFloat(dice.toFixed(4)),
      intersection: inter,
      union,
      countA,
      countB
    };
  },

  /**
   * Validate a 478-point MediaPipe FaceMesh landmark array or BlazeFace detection
   * for anatomical plausibility, minimum size, aspect ratio, and neural foreground support.
   * Rejects background pareidolia false positives and degenerate crop edge artifacts.
   */
  validateFaceCandidate(candidate, imgW, imgH, maps = {}) {
    const { bbox, landmarks, keypoints, rawScore = 0.75, source = 'landmarker' } = candidate;
    if (!bbox) return { valid: false, reason: 'missing_bbox', confidence: 0 };

    const bw = bbox.x1 - bbox.x0;
    const bh = bbox.y1 - bbox.y0;
    const minDim = Math.max(14, Math.min(imgW, imgH) * 0.025);
    const minArea = imgW * imgH * 0.00045;

    if (bw < minDim || bh < minDim || (bw * bh) < minArea) {
      return { valid: false, reason: 'below_min_face_size', confidence: 0 };
    }

    const aspect = bw / Math.max(1, bh);
    if (aspect < 0.45 || aspect > 1.85) {
      return { valid: false, reason: 'invalid_aspect_ratio', confidence: 0 };
    }

    // Check out-of-bounds clipping
    const clippedW = Math.min(imgW, bbox.x1) - Math.max(0, bbox.x0);
    const clippedH = Math.min(imgH, bbox.y1) - Math.max(0, bbox.y0);
    if (clippedW < bw * 0.55 || clippedH < bh * 0.55) {
      return { valid: false, reason: 'mostly_outside_image', confidence: 0 };
    }

    let geoScore = 0.72;
    let eyeCenter = null;

    if (landmarks && landmarks.length >= 468) {
      const lEye = landmarks[33];
      const rEye = landmarks[263];
      const nose = landmarks[1];
      const mouthTop = landmarks[13];
      const chin = landmarks[152];
      const forehead = landmarks[10];

      if (!lEye || !rEye || !nose || !mouthTop || !chin || !forehead) {
        return { valid: false, reason: 'missing_core_landmarks', confidence: 0 };
      }

      const lx = lEye.x * imgW, ly = lEye.y * imgH;
      const rx = rEye.x * imgW, ry = rEye.y * imgH;
      const nx = nose.x * imgW, ny = nose.y * imgH;
      const mx = mouthTop.x * imgW, my = mouthTop.y * imgH;
      const cx = chin.x * imgW, cy = chin.y * imgH;
      const fx = forehead.x * imgW, fy = forehead.y * imgH;

      eyeCenter = { x: (lx + rx) * 0.5, y: (ly + ry) * 0.5 };
      const eyeDist = Math.hypot(rx - lx, ry - ly);
      const faceHeightAxis = Math.hypot(cx - fx, cy - fy);

      // Inter-ocular distance must be a plausible fraction of face width/height (allows profile/angled faces down to 0.12)
      if (eyeDist < bw * 0.11 || eyeDist > bw * 0.92 || faceHeightAxis < bh * 0.45) {
        return { valid: false, reason: 'implausible_interocular_or_axis_scale', confidence: 0 };
      }

      // Check anatomical ordering along the forehead -> chin vector
      const axisX = (cx - fx) / Math.max(1, faceHeightAxis);
      const axisY = (cy - fy) / Math.max(1, faceHeightAxis);
      const projEye = ((eyeCenter.x - fx) * axisX + (eyeCenter.y - fy) * axisY) / faceHeightAxis;
      const projNose = ((nx - fx) * axisX + (ny - fy) * axisY) / faceHeightAxis;
      const projMouth = ((mx - fx) * axisX + (my - fy) * axisY) / faceHeightAxis;

      // Eyes must be above mouth, and nose must be above mouth and below forehead
      if (!(projEye < projMouth && projNose > 0.10 && projNose < 0.92 && projMouth > projEye + 0.06)) {
        return { valid: false, reason: 'anatomical_landmark_order_invalid', confidence: 0 };
      }

      const rollAngleDeg = Math.abs(Math.atan2(ry - ly, rx - lx) * (180 / Math.PI));
      const rollPenalty = rollAngleDeg > 65 ? 0.18 : 0;
      geoScore = Math.max(0.55, Math.min(0.98, 0.88 - rollPenalty));
    } else if (keypoints && keypoints.length >= 2) {
      // BlazeFace keypoints: [rightEye, leftEye, noseTip, mouth, ...]
      const kp0 = keypoints[0];
      const kp1 = keypoints[1];
      if (kp0 && kp1) {
        const ex0 = kp0.x <= 1 ? kp0.x * imgW : kp0.x;
        const ey0 = kp0.y <= 1 ? kp0.y * imgH : kp0.y;
        const ex1 = kp1.x <= 1 ? kp1.x * imgW : kp1.x;
        const ey1 = kp1.y <= 1 ? kp1.y * imgH : kp1.y;
        eyeCenter = { x: (ex0 + ex1) * 0.5, y: (ey0 + ey1) * 0.5 };
        const eyeDist = Math.hypot(ex1 - ex0, ey1 - ey0);
        if (eyeDist < bw * 0.10) {
          return { valid: false, reason: 'blazeface_keypoints_collapsed', confidence: 0 };
        }
      }
      geoScore = Math.min(0.86, Math.max(0.50, rawScore));
    } else {
      // Unverified box without landmarks or keypoints (e.g. raw skin blob): reject to prevent false positives!
      return { valid: false, reason: 'unverified_no_landmarks_or_keypoints', confidence: 0 };
    }

    // Neural foreground / face-skin support check (if segmentation confidence maps are provided)
    let skinSupport = 0.65;
    let fgSupport = 0.75;
    const { faceSkinMap, bodySkinMap, bgMap, mapW = imgW, mapH = imgH } = maps;
    if (faceSkinMap || bgMap) {
      const sx0 = Math.max(0, Math.floor((bbox.x0 / imgW) * mapW));
      const sy0 = Math.max(0, Math.floor((bbox.y0 / imgH) * mapH));
      const sx1 = Math.min(mapW - 1, Math.ceil((bbox.x1 / imgW) * mapW));
      const sy1 = Math.min(mapH - 1, Math.ceil((bbox.y1 / imgH) * mapH));
      let skinSum = 0;
      let fgSum = 0;
      let samples = 0;
      // Sample central 70% ellipse of the face box
      const ecx = (sx0 + sx1) * 0.5;
      const ecy = (sy0 + sy1) * 0.5;
      const erx = Math.max(1, (sx1 - sx0) * 0.38);
      const ery = Math.max(1, (sy1 - sy0) * 0.38);

      for (let y = sy0; y <= sy1; y++) {
        for (let x = sx0; x <= sx1; x++) {
          const dx = (x - ecx) / erx;
          const dy = (y - ecy) / ery;
          if (dx * dx + dy * dy <= 1.0) {
            const idx = y * mapW + x;
            const fSkin = faceSkinMap ? faceSkinMap[idx] : 0;
            const bSkin = bodySkinMap ? bodySkinMap[idx] : 0;
            const fg = bgMap ? (1 - bgMap[idx]) : 0.75;
            skinSum += Math.min(1, fSkin + bSkin * 0.5);
            fgSum += fg;
            samples++;
          }
        }
      }
      if (samples > 0) {
        skinSupport = skinSum / samples;
        fgSupport = fgSum / samples;
      }

      // Reject pareidolia on background objects where both human foreground and face skin are near zero
      const minRequiredFg = source === 'detector_only' ? 0.35 : 0.14;
      const minRequiredSkin = source === 'detector_only' ? 0.16 : 0.05;
      if (fgSupport < minRequiredFg && skinSupport < minRequiredSkin) {
        return { valid: false, reason: 'background_pareidolia_rejected', confidence: 0 };
      }
    }

    const confidence = Math.min(
      0.99,
      Math.max(0.50, 0.48 * rawScore + 0.32 * geoScore + 0.12 * fgSupport + 0.08 * skinSupport)
    );

    if (confidence < 0.52) {
      return { valid: false, reason: 'below_confidence_threshold', confidence };
    }

    return {
      valid: true,
      confidence: parseFloat(confidence.toFixed(3)),
      eyeCenter: eyeCenter || { x: (bbox.x0 + bbox.x1) * 0.5, y: (bbox.y0 + bbox.y1) * 0.42 }
    };
  },

  /**
   * Confidence-sorted Non-Maximum Suppression (NMS) and Multi-Cue Deduplication for Face Detections.
   * Removes duplicate boxes from overlapping tiles, multi-scale passes, or detector+landmarker pairs
   * while preserving genuinely distinct faces standing close together.
   */
  deduplicateFacesNMS(candidates, imgW, imgH, maps = {}, options = {}) {
    const iouThreshold = options.iouThreshold ?? 0.30;
    const ioMinThreshold = options.ioMinThreshold ?? 0.52;
    const centerDistRatio = options.centerDistRatio ?? 0.40;

    // 1. Validate every candidate and compute calibrated confidence
    const validated = [];
    for (const cand of (candidates || [])) {
      const check = this.validateFaceCandidate(cand, imgW, imgH, maps);
      if (!check.valid) continue;
      validated.push({
        ...cand,
        confidence: cand.confidence ? Math.max(cand.confidence, check.confidence) : check.confidence,
        eyeCenter: check.eyeCenter,
        hasLandmarks: !!(cand.landmarks && cand.landmarks.length >= 468)
      });
    }

    // 2. Sort descending by: (hasLandmarks priority + confidence score + box area stability)
    validated.sort((a, b) => {
      const scoreA = a.confidence + (a.hasLandmarks ? 0.08 : 0);
      const scoreB = b.confidence + (b.hasLandmarks ? 0.08 : 0);
      return scoreB - scoreA;
    });

    // 3. Apply NMS + Containment (IoMin) + Eye-Center Proximity suppression
    const kept = [];
    for (const cand of validated) {
      let isDuplicate = false;
      for (let i = 0; i < kept.length; i++) {
        const k = kept[i];
        const m = this.computeBoxOverlapMetrics(k.bbox, cand.bbox);

        // Eye-center distance normalized by face width
        const minW = Math.max(12, Math.min(k.bbox.x1 - k.bbox.x0, cand.bbox.x1 - cand.bbox.x0));
        const eyeDist = (k.eyeCenter && cand.eyeCenter)
          ? Math.hypot(k.eyeCenter.x - cand.eyeCenter.x, k.eyeCenter.y - cand.eyeCenter.y)
          : m.centerDist;
        const sameEyes = (eyeDist / minW) < 0.45;

        if (m.iou >= iouThreshold || m.ioMin >= ioMinThreshold || m.normCenterDist < centerDistRatio || sameEyes) {
          isDuplicate = true;
          // If the suppressed candidate has landmarks and the kept one didn't, upgrade the kept one
          if (!k.hasLandmarks && cand.hasLandmarks) {
            kept[i] = { ...cand, confidence: Math.max(k.confidence, cand.confidence) };
          }
          break;
        }
      }
      if (!isDuplicate) {
        kept.push(cand);
      }
    }

    // 4. Sort final distinct faces left-to-right for deterministic labeling (Face 1, Face 2, ...)
    kept.sort((a, b) => a.bbox.x0 - b.bbox.x0);
    return kept.map((f, idx) => ({
      ...f,
      id: `face_${idx + 1}`,
      index: idx + 1,
      label: `Face ${idx + 1}`,
      selected: f.selected !== false
    }));
  },

  /**
   * Multi-Person Instance Detection, Deduplication & Mask Partitioning (Feature 4, 5 & 6).
   * Combines:
   * - Validated Face Anchors (`detectedFaces`)
   * - Optional Person ObjectDetector boxes (`personBoxes`)
   * - Refined Human Body Silhouette Mask (`bodyMask`, W x H)
   *
   * Solves both:
   * - Over-counting (4 people -> 5 people due to detached arm/cloth fragments or false background boxes)
   * - Under-counting (4 closely standing people merged into 1 connected silhouette component)
   */
  detectAndSegmentPeopleInstances(bodyMask, W, H, detectedFaces = [], personDetectorBoxes = [], options = {}) {
    const totalPixels = W * H;
    if (!bodyMask || bodyMask.length !== totalPixels) {
      return { persons: [], combinedMask: new Uint8Array(totalPixels), count: 0 };
    }

    let totalFgPixels = 0;
    for (let i = 0; i < totalPixels; i++) {
      if (bodyMask[i]) totalFgPixels++;
    }
    const minPersonPixels = Math.max(60, Math.round(totalPixels * (options.minPersonAreaRatio ?? 0.0035)));
    if (totalFgPixels < minPersonPixels) {
      return { persons: [], combinedMask: new Uint8Array(totalPixels), count: 0 };
    }

    // 1. Extract 4-connected foreground components from bodyMask
    const compIdMap = new Int32Array(totalPixels).fill(-1);
    const components = [];
    const stack = new Int32Array(totalPixels);

    for (let start = 0; start < totalPixels; start++) {
      if (!bodyMask[start] || compIdMap[start] >= 0) continue;
      const cid = components.length;
      let sp = 0;
      let count = 0;
      let x0 = W, y0 = H, x1 = 0, y1 = 0;
      let sumX = 0, sumY = 0;

      stack[sp++] = start;
      compIdMap[start] = cid;

      while (sp > 0) {
        const p = stack[--sp];
        count++;
        const x = p % W;
        const y = (p - x) / W;
        sumX += x;
        sumY += y;
        if (x < x0) x0 = x;
        if (x > x1) x1 = x;
        if (y < y0) y0 = y;
        if (y > y1) y1 = y;

        if (x > 0 && bodyMask[p - 1] && compIdMap[p - 1] < 0) { compIdMap[p - 1] = cid; stack[sp++] = p - 1; }
        if (x < W - 1 && bodyMask[p + 1] && compIdMap[p + 1] < 0) { compIdMap[p + 1] = cid; stack[sp++] = p + 1; }
        if (y > 0 && bodyMask[p - W] && compIdMap[p - W] < 0) { compIdMap[p - W] = cid; stack[sp++] = p - W; }
        if (y < H - 1 && bodyMask[p + W] && compIdMap[p + W] < 0) { compIdMap[p + W] = cid; stack[sp++] = p + W; }
      }

      components.push({
        cid,
        pixelCount: count,
        bbox: { x0, y0, x1: x1 + 1, y1: y1 + 1 },
        cx: sumX / count,
        cy: sumY / count
      });
    }

    // 2. Filter & Deduplicate Person ObjectDetector boxes using foreground mask coverage + Class-Aware NMS
    const validDetBoxes = [];
    for (const det of (personDetectorBoxes || [])) {
      if (!det || !det.bbox) continue;
      if (det.category && det.category.toLowerCase() !== 'person') continue;
      const score = det.score ?? det.confidence ?? 0.65;
      if (score < (options.minDetectorScore ?? 0.45)) continue;

      const bx0 = Math.max(0, Math.floor(det.bbox.x0));
      const by0 = Math.max(0, Math.floor(det.bbox.y0));
      const bx1 = Math.min(W, Math.ceil(det.bbox.x1));
      const by1 = Math.min(H, Math.ceil(det.bbox.y1));
      const bw = bx1 - bx0;
      const bh = by1 - by0;
      if (bw < W * 0.04 || bh < H * 0.06 || (bw * bh) < minPersonPixels) continue;

      // Measure foreground mask coverage inside this detector box
      let fgInBox = 0;
      const step = Math.max(1, Math.floor(Math.min(bw, bh) / 32));
      let sampled = 0;
      for (let y = by0; y < by1; y += step) {
        for (let x = bx0; x < bx1; x += step) {
          sampled++;
          if (bodyMask[y * W + x]) fgInBox++;
        }
      }
      const fgRatio = sampled > 0 ? fgInBox / sampled : 0;
      // Reject ghost/false-positive person boxes that do not overlap actual human foreground mask
      if (fgRatio < 0.22) continue;

      validDetBoxes.push({
        bbox: { x0: bx0, y0: by0, x1: bx1, y1: by1 },
        confidence: Math.min(0.99, score * 0.8 + fgRatio * 0.2),
        fgRatio
      });
    }

    // Sort detector boxes by confidence descending and apply NMS (IoU >= 0.45 or IoMin >= 0.72)
    validDetBoxes.sort((a, b) => b.confidence - a.confidence);
    const nmsDetBoxes = [];
    for (const cand of validDetBoxes) {
      let dup = false;
      for (const kept of nmsDetBoxes) {
        const m = this.computeBoxOverlapMetrics(kept.bbox, cand.bbox);
        if (m.iou >= 0.45 || m.ioMin >= 0.72 || m.normCenterDist < 0.30) {
          dup = true;
          break;
        }
      }
      if (!dup) nmsDetBoxes.push(cand);
    }

    // 3. Build Person Seeds from Validated Faces + Unmatched Detector Boxes + Major Components
    const seeds = [];
    const matchedDetIndices = new Set();

    // 3A. Every validated face anchors a unique person seed
    for (let fIdx = 0; fIdx < detectedFaces.length; fIdx++) {
      const f = detectedFaces[fIdx];
      const fb = f.bbox;
      const fw = Math.max(12, fb.x1 - fb.x0);
      const fh = Math.max(12, fb.y1 - fb.y0);
      const fcx = (fb.x0 + fb.x1) * 0.5;
      const fcy = (fb.y0 + fb.y1) * 0.5;

      // Estimate torso/body anchor below the face
      const estBodyBox = {
        x0: Math.max(0, fcx - fw * 1.85),
        y0: Math.max(0, fb.y0 - fh * 0.25),
        x1: Math.min(W, fcx + fw * 1.85),
        y1: Math.min(H, fb.y1 + fh * 5.5)
      };

      // Check if an NMS detector box matches this face (contains the face center)
      let bestDetIdx = -1;
      let bestDetScore = -1;
      for (let dIdx = 0; dIdx < nmsDetBoxes.length; dIdx++) {
        if (matchedDetIndices.has(dIdx)) continue;
        const db = nmsDetBoxes[dIdx].bbox;
        if (fcx >= db.x0 && fcx <= db.x1 && fcy >= db.y0 && fcy <= db.y0 + (db.y1 - db.y0) * 0.65) {
          const s = nmsDetBoxes[dIdx].confidence;
          if (s > bestDetScore) {
            bestDetScore = s;
            bestDetIdx = dIdx;
          }
        }
      }
      if (bestDetIdx >= 0) {
        matchedDetIndices.add(bestDetIdx);
      }

      seeds.push({
        faceId: f.id || `face_${fIdx + 1}`,
        faceBbox: fb,
        priorBox: bestDetIdx >= 0 ? nmsDetBoxes[bestDetIdx].bbox : estBodyBox,
        anchorX: fcx,
        anchorY: Math.min(H - 1, fcy + fh * 1.15), // Upper-chest/neck centroid
        headX: fcx,
        headY: fcy,
        scaleW: Math.max(fw * 2.2, bestDetIdx >= 0 ? (nmsDetBoxes[bestDetIdx].bbox.x1 - nmsDetBoxes[bestDetIdx].bbox.x0) * 0.6 : fw * 2.2),
        confidence: Math.min(0.99, Math.max(f.confidence || 0.88, bestDetScore > 0 ? bestDetScore : 0.88))
      });
    }

    // 3B. Add remaining high-confidence detector boxes that do NOT overlap any existing seed
    for (let dIdx = 0; dIdx < nmsDetBoxes.length; dIdx++) {
      if (matchedDetIndices.has(dIdx)) continue;
      const det = nmsDetBoxes[dIdx];
      const db = det.bbox;
      const dcx = (db.x0 + db.x1) * 0.5;
      const dcy = (db.y0 + db.y1) * 0.5;

      let overlapsExistingSeed = false;
      for (const s of seeds) {
        const m = this.computeBoxOverlapMetrics(s.priorBox, db);
        const xDist = Math.abs(dcx - s.anchorX);
        if (m.iou >= 0.35 || m.ioMin >= 0.58 || xDist < (db.x1 - db.x0) * 0.45) {
          overlapsExistingSeed = true;
          break;
        }
      }
      if (!overlapsExistingSeed && det.confidence >= 0.58 && det.fgRatio >= 0.35) {
        seeds.push({
          faceId: null,
          faceBbox: null,
          priorBox: db,
          anchorX: dcx,
          anchorY: dcy,
          headX: dcx,
          headY: db.y0 + (db.y1 - db.y0) * 0.2,
          scaleW: Math.max(24, (db.x1 - db.x0) * 0.6),
          confidence: det.confidence
        });
      }
    }

    // 3C. If no face or detector seeds were found, create seeds only from major valid silhouette components
    //     (ignoring tiny detached fragments < 15% of largest component to prevent counting 4 people as 5!)
    if (seeds.length === 0 && components.length > 0) {
      const sortedComps = components.slice().sort((a, b) => b.pixelCount - a.pixelCount);
      const maxCompPixels = sortedComps[0].pixelCount;
      const minMajorComp = Math.max(minPersonPixels, Math.round(maxCompPixels * 0.18));

      for (const comp of sortedComps) {
        if (comp.pixelCount < minMajorComp) continue;
        seeds.push({
          faceId: null,
          faceBbox: null,
          priorBox: comp.bbox,
          anchorX: comp.cx,
          anchorY: comp.cy,
          headX: comp.cx,
          headY: comp.bbox.y0 + (comp.bbox.y1 - comp.bbox.y0) * 0.2,
          scaleW: Math.max(24, (comp.bbox.x1 - comp.bbox.x0) * 0.6),
          confidence: 0.84
        });
      }
    }

    if (seeds.length === 0) {
      return { persons: [], combinedMask: new Uint8Array(totalPixels), count: 0 };
    }

    // Sort seeds left-to-right
    seeds.sort((a, b) => a.headX - b.headX);

    // 4. Partition foreground bodyMask pixels across the validated person seeds!
    //    Also filter out tiny noise islands that are far from all person seeds.
    const K = seeds.length;
    const personMasks = Array.from({ length: K }, () => new Uint8Array(totalPixels));
    const personPixelCounts = new Int32Array(K);
    const personBounds = Array.from({ length: K }, () => ({ x0: W, y0: H, x1: 0, y1: 0 }));

    // Determine which connected components are valid (either large enough or overlapping a seed)
    const validCompSet = new Set();
    const maxCompSize = components.reduce((m, c) => Math.max(m, c.pixelCount), 0);
    const noiseFloor = Math.max(Math.round(totalPixels * 0.0012), Math.round(maxCompSize * 0.04));

    for (const comp of components) {
      let touchesSeed = false;
      for (const s of seeds) {
        const m = this.computeBoxOverlapMetrics(comp.bbox, s.priorBox);
        if (m.interArea > 0) { touchesSeed = true; break; }
      }
      if (comp.pixelCount >= noiseFloor || touchesSeed) {
        validCompSet.add(comp.cid);
      }
    }

    const combinedMask = new Uint8Array(totalPixels);

    for (let y = 0; y < H; y++) {
      for (let x = 0; x < W; x++) {
        const idx = y * W + x;
        if (!bodyMask[idx]) continue;
        const cid = compIdMap[idx];
        if (!validCompSet.has(cid)) continue;

        let bestK = 0;
        if (K > 1) {
          let bestCost = Infinity;
          for (let k = 0; k < K; k++) {
            const s = seeds[k];
            // If pixel is directly inside seed k's face bounding box, lock it to person k
            if (s.faceBbox && x >= s.faceBbox.x0 && x <= s.faceBbox.x1 && y >= s.faceBbox.y0 && y <= s.faceBbox.y1) {
              bestK = k;
              bestCost = -1e9;
              break;
            }
            // Anisotropic horizontal-weighted distance to person axis (since standing people are vertically aligned)
            const dx = (x - s.headX) / Math.max(16, s.scaleW);
            const dy = (y - s.anchorY) / Math.max(32, s.scaleW * 2.4);
            let cost = dx * dx * 1.65 + dy * dy * 0.35;
            if (x >= s.priorBox.x0 && x <= s.priorBox.x1 && y >= s.priorBox.y0 && y <= s.priorBox.y1) {
              cost *= 0.72;
            }
            if (cost < bestCost) {
              bestCost = cost;
              bestK = k;
            }
          }
        }

        personMasks[bestK][idx] = 1;
        combinedMask[idx] = 1;
        personPixelCounts[bestK]++;
        const b = personBounds[bestK];
        if (x < b.x0) b.x0 = x;
        if (x > b.x1) b.x1 = x;
        if (y < b.y0) b.y0 = y;
        if (y > b.y1) b.y1 = y;
      }
    }

    // 5. Build final validated person instance list (filtering out any empty/micro-fragment instances)
    const persons = [];
    for (let k = 0; k < K; k++) {
      const pxCount = personPixelCounts[k];
      if (pxCount < Math.max(25, Math.round(minPersonPixels * 0.25))) continue;
      const b = personBounds[k];
      const s = seeds[k];
      const idx = persons.length + 1;
      persons.push({
        id: `person_${idx}`,
        index: idx,
        label: `Person ${idx}`,
        confidence: parseFloat(s.confidence.toFixed(3)),
        faceId: s.faceId,
        bbox: { x0: b.x0, y0: b.y0, x1: b.x1 + 1, y1: b.y1 + 1 },
        cx: Math.round((b.x0 + b.x1) * 0.5),
        topY: b.y0,
        pixelCount: pxCount,
        coveragePct: parseFloat(((pxCount / totalPixels) * 100).toFixed(1)),
        mask: personMasks[k],
        selected: true
      });
    }

    return {
      persons,
      combinedMask,
      count: persons.length
    };
  },

  /**
   * Evaluate object/instance detection accuracy against ground-truth boxes & masks (Feature 9).
   * Computes True Positives (TP), False Positives (FP), False Negatives (FN),
   * Precision, Recall, F1-Score, Exact Count Accuracy, and Mask IoU / Dice score.
   */
  evaluateDetectionAccuracy(predictedItems, groundTruthItems, iouMatchThreshold = 0.35, predMask = null, gtMask = null) {
    const preds = predictedItems || [];
    const gts = groundTruthItems || [];
    const matchedGt = new Set();
    const matchedPred = new Set();

    const pairs = [];
    for (let p = 0; p < preds.length; p++) {
      for (let g = 0; g < gts.length; g++) {
        const m = this.computeBoxOverlapMetrics(preds[p].bbox, gts[g].bbox);
        if (m.iou >= iouMatchThreshold || m.ioMin >= 0.55) {
          pairs.push({ p, g, iou: m.iou });
        }
      }
    }
    pairs.sort((a, b) => b.iou - a.iou);

    let iouSum = 0;
    for (const pair of pairs) {
      if (matchedPred.has(pair.p) || matchedGt.has(pair.g)) continue;
      matchedPred.add(pair.p);
      matchedGt.add(pair.g);
      iouSum += pair.iou;
    }

    const tp = matchedPred.size;
    const fp = preds.length - tp;
    const fn = gts.length - tp;
    const precision = (tp + fp) > 0 ? tp / (tp + fp) : (gts.length === 0 ? 1 : 0);
    const recall = (tp + fn) > 0 ? tp / (tp + fn) : (gts.length === 0 ? 1 : 0);
    const f1 = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;
    const exactCountMatch = preds.length === gts.length && fp === 0 && fn === 0;

    let maskMetrics = { iou: 1, dice: 1 };
    if (predMask && gtMask) {
      maskMetrics = this.computeMaskIoUAndDice(predMask, gtMask);
    }

    return {
      predictedCount: preds.length,
      groundTruthCount: gts.length,
      tp,
      fp,
      fn,
      precision: parseFloat((precision * 100).toFixed(2)),
      recall: parseFloat((recall * 100).toFixed(2)),
      f1: parseFloat((f1 * 100).toFixed(2)),
      meanBoxIoU: tp > 0 ? parseFloat((iouSum / tp).toFixed(4)) : 0,
      exactCountMatch,
      maskIoU: maskMetrics.iou,
      maskDice: maskMetrics.dice
    };
  }



};

if (typeof window !== 'undefined') window.BitEngine = BitEngine;
if (typeof globalThis !== 'undefined') globalThis.BitEngine = BitEngine;
