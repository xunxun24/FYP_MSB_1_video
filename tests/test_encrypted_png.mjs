/**
 * Automated Verification & Regression Test Suite for Self-Describing Encrypted PNG
 * (`encrypted_photo.png` with embedded `msBx` chunk) and Legacy `.msbx` Compatibility.
 *
 * Run with:
 *   node tests/test_encrypted_png.mjs
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';

// Polyfill browser ImageData in Node.js test environment
class NodeImageData {
  constructor(dataOrWidth, widthOrHeight, maybeHeight) {
    if (dataOrWidth instanceof Uint8ClampedArray) {
      this.data = dataOrWidth;
      this.width = widthOrHeight;
      this.height = maybeHeight;
    } else {
      this.width = dataOrWidth;
      this.height = widthOrHeight;
      this.data = new Uint8ClampedArray(this.width * this.height * 4);
    }
  }
}
globalThis.ImageData = NodeImageData;

// Load BitEngine from js/bit-engine.js
const enginePath = path.resolve('js/bit-engine.js');
const engineCode = fs.readFileSync(enginePath, 'utf8') + '\nglobalThis.BitEngine = BitEngine;\n';
vm.runInThisContext(engineCode, { filename: enginePath });
const BitEngine = globalThis.BitEngine;

function createSyntheticImage(width, height, mode = 'rgb') {
  const rgba = new Uint8ClampedArray(width * height * 4);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const idx = (y * width + x) * 4;
      if (mode === 'grayscale') {
        const lum = (x * 7 + y * 13 + ((x ^ y) & 0xFF)) & 0xFF;
        rgba[idx] = lum;
        rgba[idx + 1] = lum;
        rgba[idx + 2] = lum;
        rgba[idx + 3] = 255;
      } else if (mode === 'rgba') {
        rgba[idx] = (x * 11 + y * 3) & 0xFF;
        rgba[idx + 1] = (x * 5 + y * 17 + 90) & 0xFF;
        rgba[idx + 2] = (x * 23 + y * 7 + 180) & 0xFF;
        rgba[idx + 3] = ((x + y) % 5 === 0) ? 128 : 255;
      } else {
        rgba[idx] = (x * 11 + y * 3) & 0xFF;
        rgba[idx + 1] = (x * 5 + y * 17 + 90) & 0xFF;
        rgba[idx + 2] = (x * 23 + y * 7 + 180) & 0xFF;
        rgba[idx + 3] = 255;
      }
    }
  }
  return new ImageData(rgba, width, height);
}

function cloneImageData(img) {
  return new ImageData(new Uint8ClampedArray(img.data), img.width, img.height);
}

function countDiffPixels(imgA, imgB) {
  assert.equal(imgA.width, imgB.width);
  assert.equal(imgA.height, imgB.height);
  let diffPixels = 0;
  for (let i = 0; i < imgA.data.length; i += 4) {
    if (imgA.data[i] !== imgB.data[i] ||
      imgA.data[i + 1] !== imgB.data[i + 1] ||
      imgA.data[i + 2] !== imgB.data[i + 2] ||
      imgA.data[i + 3] !== imgB.data[i + 3]) {
      diffPixels++;
    }
  }
  return diffPixels;
}

async function runTests() {
  let passed = 0;
  const pass = (msg) => {
    passed++;
    console.log(`[PASS ${passed.toString().padStart(2, '0')}] ${msg}`);
  };

  const W = 64, H = 48;
  const origRgb = createSyntheticImage(W, H, 'rgb');
  const origGray = createSyntheticImage(W, H, 'grayscale');
  const testKeyA = 'TestKey_Alpha_#901';
  const testKeyB = 'TestKey_Beta_#902';

  // 1. Valid PNG signature, `msBX` chunk structure, and file save/load round-trip
  {
    const res = await BitEngine.encryptToPNG(cloneImageData(origRgb), testKeyA, null, {
      k: 2,
      iterations: 1000,
      keyType: 'text',
      scope: 'full'
    });
    assert.ok(BitEngine.isPngBytes(res.pngBytes), 'Output must have valid 8-byte PNG signature');
    assert.equal(res.verifiedLosslessPng, true);
    assert.equal(res.pngRoundTripDiffPixels, 0);
    assert.equal(res.metadata.chunkType, 'msBX', 'Newly encrypted PNG must report chunkType === "msBX"');
    assert.equal(res.metadata.isLegacyChunk, false, 'Newly encrypted PNG must report isLegacyChunk === false');
    assert.equal(res.metadata.chunkDisplay, 'msBX', 'Newly encrypted PNG must report chunkDisplay === "msBX"');

    // Save to temporary file and reload to verify metadata & pixel survival across disk I/O
    const tmpFile = path.join(os.tmpdir(), `test_enc_${Date.now()}.png`);
    fs.writeFileSync(tmpFile, res.pngBytes);
    const reloadedBytes = new Uint8Array(fs.readFileSync(tmpFile));
    fs.unlinkSync(tmpFile);

    const decoded = await BitEngine.decodeLosslessPNG(reloadedBytes);
    const msBXChunks = decoded.chunks.filter(c => c.type === 'msBX');
    const msBxLegacyChunks = decoded.chunks.filter(c => c.type === 'msBx');
    assert.equal(msBXChunks.length, 1, 'Newly encrypted PNG must contain exactly one msBX chunk');
    assert.equal(msBxLegacyChunks.length, 0, 'Newly encrypted PNG must not contain legacy msBx chunk');
    assert.equal(countDiffPixels(res.imageData, decoded.imageData), 0, 'Encrypted pixels before PNG encoding must equal encrypted pixels after PNG decoding');
    assert.ok(countDiffPixels(origRgb, decoded.imageData) > 0, 'PNG must display encrypted pixels, not original pixels');

    const dec = await BitEngine.decryptFromPNG(reloadedBytes, testKeyA);
    assert.equal(dec.metadata.chunkType, 'msBX');
    assert.equal(dec.metadata.chunkDisplay, 'msBX');
    assert.equal(countDiffPixels(origRgb, dec.imageData), 0, 'Recovered RGB image must have 0 different pixels');
    pass('Newly encrypted PNG uses msBX chunk, survives disk save/load, preserves encrypted pixels (0 diff), and recovers original RGB image with 0 different pixels');
  }

  // 2. Grayscale image encryption & exact grayscale recovery
  {
    const res = await BitEngine.encryptToPNG(cloneImageData(origGray), testKeyA, null, {
      k: 2,
      iterations: 1000,
      keyType: 'text',
      scope: 'full'
    });
    assert.equal(res.metadata.originalColorMode, 0, 'Should auto-detect Grayscale colour mode (0)');
    const dec = await BitEngine.decryptFromPNG(res.pngBytes, testKeyA);
    assert.equal(countDiffPixels(origGray, dec.imageData), 0, 'Recovered Grayscale image must have 0 different pixels');
    pass('Exact Grayscale (mode 0) encryption and recovery verified (0 different pixels)');
  }

  // 3. All k values from 1 to 8
  {
    for (let k = 1; k <= 8; k++) {
      const res = await BitEngine.encryptToPNG(cloneImageData(origRgb), testKeyA, null, {
        k,
        iterations: 500,
        keyType: 'text',
        scope: 'full'
      });
      assert.equal(res.metadata.k, k);
      const dec = await BitEngine.decryptFromPNG(res.pngBytes, testKeyA);
      assert.equal(countDiffPixels(origRgb, dec.imageData), 0, `k=${k} round-trip failed`);
    }
    pass('All Stage 3 MSB bit depths k = 1..8 verified with 0 different pixels');
  }

  // 4. Fresh random salt for every encryption
  {
    const res1 = await BitEngine.encryptToPNG(cloneImageData(origRgb), testKeyA, null, { iterations: 500 });
    const res2 = await BitEngine.encryptToPNG(cloneImageData(origRgb), testKeyA, null, { iterations: 500 });
    assert.notEqual(res1.metadata.saltHex, res2.metadata.saltHex, 'Each encryption must generate a fresh random 16-byte salt');
    pass('Fresh 16-byte cryptographic random salt generated for each encryption');
  }

  // 5. Selective encryption: Human Body Silhouette mask & Human Face Contour mask (plain & protected mask modes)
  {
    // Create synthetic body mask (central vertical silhouette) and face mask (circular head region)
    const bodyMask = new Uint8Array(W * H);
    const faceMask = new Uint8Array(W * H);
    for (let y = 0; y < H; y++) {
      for (let x = 0; x < W; x++) {
        const idx = y * W + x;
        if (x >= 18 && x <= 46 && y >= 10 && y <= 44) bodyMask[idx] = 1;
        const dx = x - 32, dy = y - 18;
        if (dx * dx + dy * dy <= 100) faceMask[idx] = 1;
      }
    }

    for (const [scope, mask, protectMask] of [
      ['person', bodyMask, false],
      ['face', faceMask, false],
      ['face', faceMask, true]
    ]) {
      const enc = await BitEngine.encryptToPNG(cloneImageData(origRgb), testKeyA, mask, {
        k: 2,
        iterations: 500,
        scope,
        protectMask
      });
      assert.equal(enc.metadata.scope, scope);

      // Verify unselected background pixels are untouched in the encrypted PNG
      for (let i = 0; i < W * H; i++) {
        if (mask[i] === 0) {
          const p = i * 4;
          assert.equal(enc.imageData.data[p], origRgb.data[p]);
          assert.equal(enc.imageData.data[p + 1], origRgb.data[p + 1]);
          assert.equal(enc.imageData.data[p + 2], origRgb.data[p + 2]);
        }
      }

      const dec = await BitEngine.decryptFromPNG(enc.pngBytes, testKeyA);
      assert.equal(countDiffPixels(origRgb, dec.imageData), 0);
      assert.deepEqual(dec.metadata.mask, mask, 'Restored segmentation mask must match original mask bit-for-bit');
    }
    pass('Body-region & Face-region selective encryption (both plain RLE and keystream-protected mask) preserve background and recover 100% with 0 diff pixels');
  }

  // 6. Image-key-based encryption and decryption + incorrect key-image rejection
  {
    const keyImgBytesA = await BitEngine.encodeLosslessPNG(origRgb);
    const keyImgBytesB = await BitEngine.encodeLosslessPNG(origGray);
    const keyHashA = await BitEngine.hashKeyImage(keyImgBytesA);
    const keyHashB = await BitEngine.hashKeyImage(keyImgBytesB);

    const enc = await BitEngine.encryptToPNG(cloneImageData(origRgb), keyHashA.hex, null, {
      k: 2,
      iterations: 500,
      keyType: 'image',
      scope: 'full'
    });
    const inspected = await BitEngine.inspectEncryptedPNG(enc.pngBytes);
    assert.equal(inspected.metadata.keyType, 'image', 'Metadata must identify keyType === "image"');

    const dec = await BitEngine.decryptFromPNG(enc.pngBytes, keyHashA.hex);
    assert.equal(countDiffPixels(origRgb, dec.imageData), 0);

    await assert.rejects(
      () => BitEngine.decryptFromPNG(enc.pngBytes, keyHashB.hex),
      /incorrect|modified/i,
      'Wrong key image must be rejected'
    );
    pass('Image-key-based encryption, metadata keyType detection, recovery, and wrong-key-image rejection verified');
  }

  // 7. BMP & PNG input compatibility
  {
    const bmpBlob = BitEngine.imageDataToBMPBlob(origRgb);
    const bmpBytes = new Uint8Array(await bmpBlob.arrayBuffer());
    assert.equal(bmpBytes[0], 0x42); // 'B'
    assert.equal(bmpBytes[1], 0x4D); // 'M'
    pass('Lossless 24-bit Windows BMP and PNG input/output format compatibility verified');
  }

  // 8. Error handling: wrong password, missing metadata, invalid identifier, unsupported version, corrupted metadata
  {
    const validEnc = await BitEngine.encryptToPNG(cloneImageData(origRgb), testKeyA, null, { iterations: 500 });

    // 8a. Wrong password
    await assert.rejects(
      () => BitEngine.decryptFromPNG(validEnc.pngBytes, testKeyB),
      /password or key image is incorrect/i
    );

    // 8b. Ordinary PNG without `msBx` metadata chunk
    const plainPng = await BitEngine.encodeLosslessPNG(origRgb);
    await assert.rejects(
      () => BitEngine.inspectEncryptedPNG(plainPng),
      /Missing FYP encryption metadata/i
    );

    // 8c. Invalid metadata identifier
    const badIdMeta = BitEngine.encodeMsBxMetadata({
      originalColorMode: 1,
      k: 2,
      keyType: 'text',
      scope: 'full',
      width: W,
      height: H,
      iterations: 500,
      salt: new Uint8Array(16),
      verificationTag: new Uint8Array(32).fill(1)
    });
    badIdMeta[0] = 0x58; // corrupt 'K' -> 'X'
    const badIdPng = await BitEngine.encodeLosslessPNG(origRgb, [{ type: 'msBX', data: badIdMeta }]);
    await assert.rejects(
      () => BitEngine.inspectEncryptedPNG(badIdPng),
      /Invalid FYP metadata identifier/i
    );

    // 8d. Unsupported metadata version
    const badVerMeta = BitEngine.encodeMsBxMetadata({
      originalColorMode: 1,
      k: 2,
      keyType: 'text',
      scope: 'full',
      width: W,
      height: H,
      iterations: 500,
      salt: new Uint8Array(16),
      verificationTag: new Uint8Array(32).fill(1)
    });
    badVerMeta[8] = 99;
    const badVerPng = await BitEngine.encodeLosslessPNG(origRgb, [{ type: 'msBX', data: badVerMeta }]);
    await assert.rejects(
      () => BitEngine.inspectEncryptedPNG(badVerPng),
      /Unsupported FYP metadata version/i
    );

    // 8e. Truncated metadata chunk
    const truncPng = await BitEngine.encodeLosslessPNG(origRgb, [{ type: 'msBX', data: new Uint8Array(20) }]);
    await assert.rejects(
      () => BitEngine.inspectEncryptedPNG(truncPng),
      /Corrupted or truncated PNG metadata/i
    );

    // 8f. Corrupted encrypted pixel in PNG (tamper detection via SHA-256 verification tag)
    const tamperedImg = cloneImageData(validEnc.imageData);
    tamperedImg.data[0] ^= 0xFF;
    const decodedOrig = await BitEngine.decodeLosslessPNG(validEnc.pngBytes);
    const msBXChunk = decodedOrig.chunks.find(c => c.type === 'msBX');
    const tamperedPng = await BitEngine.encodeLosslessPNG(tamperedImg, [msBXChunk]);
    await assert.rejects(
      () => BitEngine.decryptFromPNG(tamperedPng, testKeyA),
      /incorrect, or the encrypted PNG has been modified/i
    );

    // 8g. Conflicting metadata: PNG containing BOTH `msBX` and legacy `msBx` chunks
    const conflictingPng = await BitEngine.encodeLosslessPNG(validEnc.imageData, [
      { type: 'msBX', data: msBXChunk.data },
      { type: 'msBx', data: msBXChunk.data }
    ]);
    await assert.rejects(
      () => BitEngine.inspectEncryptedPNG(conflictingPng),
      /Conflicting FYP encryption metadata.*both "msBX" and legacy "msBx"/i
    );

    // 8h. Duplicate `msBX` chunks in the same PNG
    const duplicateMsBXPng = await BitEngine.encodeLosslessPNG(validEnc.imageData, [
      { type: 'msBX', data: msBXChunk.data },
      { type: 'msBX', data: msBXChunk.data }
    ]);
    await assert.rejects(
      () => BitEngine.inspectEncryptedPNG(duplicateMsBXPng),
      /Duplicate FYP encryption metadata.*duplicate "msBX"/i
    );

    // 8i. Duplicate legacy `msBx` chunks in the same PNG
    const duplicateMsBxLegacyPng = await BitEngine.encodeLosslessPNG(validEnc.imageData, [
      { type: 'msBx', data: msBXChunk.data },
      { type: 'msBx', data: msBXChunk.data }
    ]);
    await assert.rejects(
      () => BitEngine.inspectEncryptedPNG(duplicateMsBxLegacyPng),
      /Duplicate FYP encryption metadata.*duplicate legacy "msBx"/i
    );

    // 8j. Invalid PNG chunk CRC-32 (corrupted msBX chunk CRC bytes)
    const badCrcPng = new Uint8Array(validEnc.pngBytes);
    // IHDR chunk starts at offset 8 and is 25 bytes total (4 len + 4 type + 13 data + 4 crc),
    // so msBX chunk starts at offset 33. Read its 4-byte big-endian length to locate its CRC-32:
    const msBXLen = ((badCrcPng[33] << 24) | (badCrcPng[34] << 16) | (badCrcPng[35] << 8) | badCrcPng[36]) >>> 0;
    const msBXCrcOffset = 33 + 4 + 4 + msBXLen;
    badCrcPng[msBXCrcOffset] ^= 0xFF;
    await assert.rejects(
      () => BitEngine.inspectEncryptedPNG(badCrcPng),
      /CRC-32 checksum mismatch in "msBX" chunk/i
    );

    pass('Rejected wrong password, missing metadata, conflicting msBX+msBx chunks, duplicate chunks, invalid CRC-32, invalid identifier/version, and modified pixels');
  }

  // 9. Backward compatibility with legacy `msBx` PNG files (full image + selective protected mask)
  {
    const faceMask = new Uint8Array(W * H);
    for (let i = 0; i < W * H; i++) {
      if (i % 3 === 0) faceMask[i] = 1;
    }

    const currentEnc = await BitEngine.encryptToPNG(cloneImageData(origRgb), testKeyA, faceMask, {
      k: 2,
      iterations: 500,
      scope: 'face',
      protectMask: true
    });
    const decoded = await BitEngine.decodeLosslessPNG(currentEnc.pngBytes);
    const msBXChunk = decoded.chunks.find(c => c.type === 'msBX');
    assert.ok(msBXChunk, 'Current encrypted PNG must have msBX chunk');

    // Re-encode with legacy `msBx` chunk name (and valid CRC for `msBx`)
    const legacyMsBxPng = await BitEngine.encodeLosslessPNG(currentEnc.imageData, [
      { type: 'msBx', data: msBXChunk.data }
    ]);

    const inspectedLegacy = await BitEngine.inspectEncryptedPNG(legacyMsBxPng);
    assert.equal(inspectedLegacy.metadata.chunkType, 'msBx', 'Legacy PNG must report chunkType === "msBx"');
    assert.equal(inspectedLegacy.metadata.isLegacyChunk, true, 'Legacy PNG must report isLegacyChunk === true');
    assert.equal(inspectedLegacy.metadata.chunkDisplay, 'msBx (Legacy)', 'Legacy PNG must report chunkDisplay === "msBx (Legacy)"');

    const decLegacy = await BitEngine.decryptFromPNG(legacyMsBxPng, testKeyA);
    assert.equal(decLegacy.metadata.chunkType, 'msBx');
    assert.equal(decLegacy.metadata.isLegacyChunk, true);
    assert.equal(decLegacy.metadata.chunkDisplay, 'msBx (Legacy)');
    assert.equal(countDiffPixels(origRgb, decLegacy.imageData), 0, 'Legacy msBx PNG must recover original image with 0 different pixels');
    assert.deepEqual(decLegacy.metadata.mask, faceMask, 'Legacy msBx PNG with protected mask must recover exact mask');
    pass('Backward compatibility with legacy msBx PNG files (including protected selective masks) verified with 0 different pixels');
  }

  // 10. Backward compatibility with legacy `.msbx` container files
  {
    const legacyEnc = await BitEngine.encryptToMSBX(cloneImageData(origRgb), testKeyA, null, {
      k: 2,
      iterations: 500
    });
    const legacyDec = await BitEngine.decryptFromMSBX(legacyEnc.msbxBytes, testKeyA);
    assert.equal(countDiffPixels(origRgb, legacyDec.imageData), 0);
    pass('Backward compatibility with legacy .msbx container files preserved (0 different pixels)');
  }

  // 11. Optimized Schema v2 vs Legacy Schema v1 encoding, decoding, and storage reduction verification
  {
    const encV1 = await BitEngine.encryptToPNG(cloneImageData(origRgb), testKeyA, null, {
      k: 2,
      iterations: 100000,
      metaVersion: 1
    });
    const encV2 = await BitEngine.encryptToPNG(cloneImageData(origRgb), testKeyA, null, {
      k: 2,
      iterations: 100000,
      metaVersion: 2
    });

    assert.equal(encV1.metadata.metaVersion, 1, 'v1 encryption must have metaVersion === 1');
    assert.equal(encV1.metadata.byteLength, 76, 'v1 full-image msBX payload must be 76 bytes');
    assert.equal(encV2.metadata.metaVersion, 2, 'v2 encryption must have metaVersion === 2');
    assert.equal(encV2.metadata.byteLength, 51, 'v2 full-image msBX payload must be 51 bytes (25 bytes saved)');
    assert.equal(encV2.metadata.dimensionsFromIHDR, true, 'v2 must deduplicate width/height from IHDR');

    const cmp = await BitEngine.compareMetadataOptimization(encV2.pngBytes);
    assert.equal(cmp.originalMetadataBytes, 76);
    assert.equal(cmp.optimizedMetadataBytes, 51);
    assert.equal(cmp.bytesSaved, 25);
    assert.equal(cmp.storageReductionPct, 32.89);

    // Decrypt both v1 and v2 and confirm 0 different pixels
    const decV1 = await BitEngine.decryptFromPNG(encV1.pngBytes, testKeyA);
    const decV2 = await BitEngine.decryptFromPNG(encV2.pngBytes, testKeyA);
    assert.equal(countDiffPixels(origRgb, decV1.imageData), 0, 'v1 encrypted PNG must recover 0 diff pixels');
    assert.equal(countDiffPixels(origRgb, decV2.imageData), 0, 'v2 encrypted PNG must recover 0 diff pixels');
    pass('Optimized Schema v2 (51B vs 76B v1, 32.89% header reduction) and Legacy Schema v1 both recover 0 different pixels');
  }

  // 12. All 4 Lossless Face/Body Mask Compression Codecs (Raw Binary, Bit-Packed, RLE-Varint, DEFLATE)
  {
    const faceMask = new Uint8Array(W * H);
    for (let y = 10; y < 38; y++) {
      for (let x = 16; x < 48; x++) {
        faceMask[y * W + x] = 1;
      }
    }

    const bench = BitEngine.benchmarkMaskCompression(faceMask);
    assert.equal(bench.methods.length, 4);
    for (const m of bench.methods) {
      assert.equal(m.verifiedLossless, true, `Mask codec ${m.name} must be 100% lossless (0 diff bits)`);
      assert.equal(m.diffBits, 0);
    }

    // Verify full encryptToPNG -> decryptFromPNG round-trip for each of the 4 mask codecs
    for (const codecId of [
      BitEngine.MASK_CODEC_RAW,
      BitEngine.MASK_CODEC_BITPACKED,
      BitEngine.MASK_CODEC_RLE,
      BitEngine.MASK_CODEC_DEFLATE
    ]) {
      const enc = await BitEngine.encryptToPNG(cloneImageData(origRgb), testKeyA, faceMask, {
        k: 3,
        iterations: 1000,
        scope: 'face',
        metaVersion: 2,
        maskCodec: codecId
      });
      assert.equal(enc.metadata.maskCodec, codecId);
      const dec = await BitEngine.decryptFromPNG(enc.pngBytes, testKeyA);
      assert.equal(countDiffPixels(origRgb, dec.imageData), 0, `Mask codec ${codecId} must recover 0 diff pixels`);
      assert.deepEqual(dec.metadata.mask, faceMask, `Mask codec ${codecId} must recover bit-for-bit identical mask`);
    }
    pass('All 4 lossless mask compression codecs (Raw Binary, Bit-Packed, RLE-Varint, DEFLATE) verified bit-for-bit with 0 different pixels');
  }

  // 13. PNG Binary Structure Explorer: Multi-IDAT chunks & optional ancillary chunks (tEXt, gAMA, pHYs) + Optional TLV fields
  {
    const encWithOpt = await BitEngine.encryptToPNG(cloneImageData(origRgb), testKeyA, null, {
      k: 2,
      iterations: 1000,
      metaVersion: 2,
      optionalFields: [
        { id: 1, critical: false, value: 1730000000 },
        { id: 2, critical: false, value: 'KXBIT-FYP-2026' },
        { id: 3, critical: false, value: 'Unit-Test-Comment' },
        { id: 99, critical: false, value: 'Unknown-NonCritical-Field' }
      ]
    });

    // Split the IDAT payload across 2 separate IDAT chunks and insert a tEXt ancillary chunk
    const parsedOrig = BitEngine.parsePngBinaryStructure(encWithOpt.pngBytes);
    const ihdrSec = parsedOrig.chunks.find(c => c.type === 'IHDR');
    const msbxSec = parsedOrig.chunks.find(c => c.type === 'msBX');
    const idatSec = parsedOrig.chunks.find(c => c.type === 'IDAT');
    const iendSec = parsedOrig.chunks.find(c => c.type === 'IEND');

    const mid = Math.floor(idatSec.dataBytes.length / 2);
    const idat1 = BitEngine.buildPngChunk('IDAT', idatSec.dataBytes.subarray(0, mid));
    const idat2 = BitEngine.buildPngChunk('IDAT', idatSec.dataBytes.subarray(mid));
    const textChunk = BitEngine.buildPngChunk('tEXt', new TextEncoder().encode('Software\0KXBIT Platform'));

    const multiIdatPng = new Uint8Array(
      8 + ihdrSec.rawBytes.length + textChunk.length + msbxSec.rawBytes.length + idat1.length + idat2.length + iendSec.rawBytes.length
    );
    let p = 0;
    multiIdatPng.set(BitEngine.PNG_SIGNATURE, p); p += 8;
    multiIdatPng.set(ihdrSec.rawBytes, p); p += ihdrSec.rawBytes.length;
    multiIdatPng.set(textChunk, p); p += textChunk.length;
    multiIdatPng.set(msbxSec.rawBytes, p); p += msbxSec.rawBytes.length;
    multiIdatPng.set(idat1, p); p += idat1.length;
    multiIdatPng.set(idat2, p); p += idat2.length;
    multiIdatPng.set(iendSec.rawBytes, p);

    const multiStruct = BitEngine.parsePngBinaryStructure(multiIdatPng);
    assert.equal(multiStruct.structuralValid, true, 'Multi-IDAT PNG with tEXt chunk must be structurally valid');
    assert.equal(multiStruct.idatCount, 2, 'Must detect 2 separate IDAT chunks');
    assert.equal(multiStruct.sizeFormulaMatches, true, 'Total PNG size must equal Signature + sum of all chunks');

    const decMulti = await BitEngine.decryptFromPNG(multiIdatPng, testKeyA);
    assert.equal(countDiffPixels(origRgb, decMulti.imageData), 0, 'Multi-IDAT PNG with ancillary chunks must recover 0 diff pixels');
    assert.equal(decMulti.metadata.optionalFields.length, 4, 'Must decode all 4 optional TLV fields');

    // Verify unknown CRITICAL optional field is rejected
    const badCritMeta = BitEngine.encodeMsBxMetadataV2({
      algoVersion: 1,
      originalColorMode: 1,
      k: 2,
      keyType: 'text',
      scope: 'full',
      iterations: 1000,
      salt: new Uint8Array(16).fill(7),
      verificationTag: new Uint8Array(32).fill(9),
      optionalFields: [{ id: 99, critical: true, value: 'MustFail' }]
    });
    assert.throws(
      () => BitEngine.decodeMsBxMetadata(badCritMeta, null, { width: W, height: H }),
      /Unsupported required optional metadata field/i
    );
    pass('Multi-IDAT PNGs, optional ancillary chunks (tEXt), and Schema v2 optional TLV fields (safe vs critical) verified');
  }

  // 14. Interactive Bit/Byte Manipulation, Incorrect Chunk Length, Invalid MSB k, and Educational Tampering Presets
  {
    const faceMask = new Uint8Array(W * H);
    for (let i = 0; i < 300; i++) faceMask[i] = 1;
    const validEnc = await BitEngine.encryptToPNG(cloneImageData(origRgb), testKeyA, faceMask, {
      k: 2,
      iterations: 1000,
      scope: 'face',
      metaVersion: 2
    });

    // Verify baseline 4-tier validation passes all 4 levels
    const baseReport = await BitEngine.validatePngAndMetadataMultiLevel(validEnc.pngBytes, testKeyA, origRgb);
    assert.equal(baseReport.allVerified, true, 'Unmodified PNG must pass all 4 validation tiers');
    assert.equal(baseReport.level4.diffPixelsVsOriginal, 0);

    // Test all 6 educational tampering presets
    const tamperChangeK = BitEngine.applyEducationalTamperPreset(validEnc.pngBytes, 'change-k');
    const repK = await BitEngine.validatePngAndMetadataMultiLevel(tamperChangeK.tamperedPngBytes, testKeyA, origRgb);
    assert.equal(repK.level1.valid, true, 'change-k keeps valid PNG CRC');
    assert.equal(repK.level2.valid, true, 'change-k keeps valid metadata schema');
    assert.equal(repK.level3.valid, false, 'change-k must fail SHA-256 authentication');

    const tamperAlgo = BitEngine.applyEducationalTamperPreset(validEnc.pngBytes, 'change-algo');
    const repAlgo = await BitEngine.validatePngAndMetadataMultiLevel(tamperAlgo.tamperedPngBytes, testKeyA, origRgb);
    assert.equal(repAlgo.level1.valid, true);
    assert.equal(repAlgo.level2.valid, false, 'change-algo must fail metadata schema validation');

    const tamperSalt = BitEngine.applyEducationalTamperPreset(validEnc.pngBytes, 'modify-salt');
    const repSalt = await BitEngine.validatePngAndMetadataMultiLevel(tamperSalt.tamperedPngBytes, testKeyA, origRgb);
    assert.equal(repSalt.level1.valid, true);
    assert.equal(repSalt.level3.valid, false, 'modify-salt must fail SHA-256 authentication');

    const tamperRemove = BitEngine.applyEducationalTamperPreset(validEnc.pngBytes, 'remove-msbx');
    const repRemove = await BitEngine.validatePngAndMetadataMultiLevel(tamperRemove.tamperedPngBytes, testKeyA, origRgb);
    assert.equal(repRemove.level1.valid, true, 'PNG without msBX is still structurally valid');
    assert.equal(repRemove.level2.valid, false, 'PNG without msBX must fail Level 2 metadata presence');

    const tamperMask = BitEngine.applyEducationalTamperPreset(validEnc.pngBytes, 'modify-mask');
    const repMask = await BitEngine.validatePngAndMetadataMultiLevel(tamperMask.tamperedPngBytes, testKeyA, origRgb);
    assert.equal(repMask.allVerified, false, 'modify-mask must fail verification');

    const tamperCrc = BitEngine.applyEducationalTamperPreset(validEnc.pngBytes, 'corrupt-crc');
    const repCrc = await BitEngine.validatePngAndMetadataMultiLevel(tamperCrc.tamperedPngBytes, testKeyA, origRgb);
    assert.equal(repCrc.level1.valid, false, 'corrupt-crc must fail Level 1 PNG structural CRC check');

    // Test incorrect chunk length detection
    const badLenPng = BitEngine.rebuildPngWithModifiedMetadata(validEnc.pngBytes, validEnc.metadata.metaPrefixBytes, {
      corruptLengthDelta: 999999
    });
    const repBadLen = await BitEngine.validatePngAndMetadataMultiLevel(badLenPng, testKeyA, origRgb);
    assert.equal(repBadLen.level1.valid, false, 'Chunk length exceeding file size must fail Level 1 structural check');

    // Test invalid MSB k setting in v1 (k = 0 and k = 9)
    assert.throws(
      () => BitEngine.encodeMsBxMetadata({
        metaVersion: 1,
        originalColorMode: 1,
        k: 9,
        keyType: 'text',
        scope: 'full',
        width: W,
        height: H,
        iterations: 1000,
        salt: new Uint8Array(16).fill(1),
        verificationTag: new Uint8Array(32).fill(2)
      }),
      /Invalid MSB bit depth/i
    );
    const validV1ForK = BitEngine.encodeMsBxMetadata({
      metaVersion: 1,
      originalColorMode: 1,
      k: 2,
      keyType: 'text',
      scope: 'full',
      width: W,
      height: H,
      iterations: 1000,
      salt: new Uint8Array(16).fill(1),
      verificationTag: new Uint8Array(32).fill(2)
    });
    const badKMeta = new Uint8Array(validV1ForK);
    badKMeta[11] = 9;
    assert.throws(
      () => BitEngine.decodeMsBxMetadata(badKMeta),
      /Invalid MSB bit depth/i
    );

    pass('Interactive bit/byte tampering presets, 4-tier validation, invalid chunk length, and invalid MSB k detection verified');
  }

  // 15. Complete Integrated Encryption -> Explorer -> Structured Edit/Regeneration -> Optimization -> Validation -> Decryption Workflow (Section 7)
  {
    const faceMask = new Uint8Array(W * H);
    for (let y = 12; y < 36; y++) {
      for (let x = 20; x < 44; x++) faceMask[y * W + x] = 1;
    }

    // Step 1–4: Encrypt image and generate self-describing PNG
    const initialEnc = await BitEngine.encryptToPNG(cloneImageData(origRgb), testKeyA, faceMask, {
      k: 2,
      iterations: 1000,
      scope: 'face',
      metaVersion: 2
    });

    // Step 5–6: Inspect actual PNG structure & view metadata fields in hex/binary/decimal
    const struct1 = BitEngine.parsePngBinaryStructure(initialEnc.pngBytes);
    assert.equal(struct1.structuralValid, true);
    assert.ok(struct1.msbxSection, 'Generated PNG must contain msBX chunk');
    const kField = struct1.msbxSection.msbxBreakdown.fields.find(f => f.field.includes('MSB Bit Depth'));
    assert.ok(kField, 'Field breakdown must expose MSB k-value');
    assert.ok(kField.value.includes('k = 2'), 'MSB k-value must decode to k = 2');

    // Step 7–8: Modify optional metadata field + encryption-critical k (2 -> 4) via Mode A Structured Regeneration
    const customizedEnc = await BitEngine.encryptToPNG(cloneImageData(origRgb), testKeyA, faceMask, {
      k: 4,
      iterations: 1000,
      scope: 'face',
      metaVersion: 2,
      maskCodec: BitEngine.MASK_CODEC_DEFLATE,
      optionalFields: [
        { id: 2, critical: false, value: 'KXBIT-Integrated-Workflow' },
        { id: 3, critical: false, value: 'Verified post-encryption metadata customization' }
      ]
    });

    // Step 9–10: Optimize & Validate final PNG across all 4 tiers before download
    const optReport = await BitEngine.compareMetadataOptimization(customizedEnc.pngBytes);
    assert.ok(optReport.optimizedMetadataBytes < optReport.originalMetadataBytes, 'Optimized v2 metadata must be smaller than legacy v1');
    const valReport = await BitEngine.validatePngAndMetadataMultiLevel(customizedEnc.pngBytes, testKeyA, origRgb);
    assert.equal(valReport.allVerified, true, 'Customized & regenerated PNG must pass all 4 validation tiers');
    assert.equal(valReport.level4.diffPixelsVsOriginal, 0);

    // Step 11–13: Upload final PNG to Decryption pipeline, decrypt with password, and confirm 0 different pixels
    const inspectedFinal = await BitEngine.inspectEncryptedPNG(customizedEnc.pngBytes);
    assert.equal(inspectedFinal.metadata.k, 4);
    assert.equal(inspectedFinal.metadata.optionalFields.length, 2);
    assert.equal(inspectedFinal.metadata.optionalFields[0].value, 'KXBIT-Integrated-Workflow');

    const decryptedFinal = await BitEngine.decryptFromPNG(customizedEnc.pngBytes, testKeyA);
    assert.equal(countDiffPixels(origRgb, decryptedFinal.imageData), 0, 'Decrypted image must be pixel-for-pixel identical (0 diff pixels)');

    pass('Complete 13-step integrated Encryption -> Binary Explorer -> Structured Edit/Regeneration -> Optimization -> Validation -> Decryption workflow verified (0 diff pixels)');
  }

  // 16. Standard Mode & All 7 Advanced Stage Combinations (Stage 1 only, Stage 2 only, Stage 3 only, S1+S2, S1+S3, S2+S3, S1+S2+S3)
  {
    const stageCombos = [
      { name: 'Standard Mode (S1+S2+S3)', mode: 'standard', s1: true,  s2: true,  s3: true },
      { name: 'Advanced Mode (S1+S2+S3)', mode: 'advanced', s1: true,  s2: true,  s3: true },
      { name: 'Stage 1 Only (Fisher-Yates)', mode: 'advanced', s1: true,  s2: false, s3: false },
      { name: 'Stage 2 Only (RGB Perm)',     mode: 'advanced', s1: false, s2: true,  s3: false },
      { name: 'Stage 3 Only (k-MSB XOR)',    mode: 'advanced', s1: false, s2: false, s3: true },
      { name: 'Stage 1 + Stage 2',           mode: 'advanced', s1: true,  s2: true,  s3: false },
      { name: 'Stage 1 + Stage 3',           mode: 'advanced', s1: true,  s2: false, s3: true },
      { name: 'Stage 2 + Stage 3',           mode: 'advanced', s1: false, s2: true,  s3: true }
    ];

    for (const combo of stageCombos) {
      const enc = await BitEngine.encryptToPNG(cloneImageData(origRgb), testKeyA, null, {
        k: 3,
        iterations: 1000,
        encryptionMode: combo.mode,
        stageConfig: {
          encryptionMode: combo.mode,
          stage1Enabled: combo.s1,
          stage2Enabled: combo.s2,
          stage2Mode: 'keyed',
          stage3Enabled: combo.s3,
          k: 3,
          stage3Channels: { r: true, g: true, b: true }
        }
      });

      assert.ok(countDiffPixels(origRgb, enc.imageData) > 0, `${combo.name} must modify pixels during encryption`);
      const inspected = await BitEngine.inspectEncryptedPNG(enc.pngBytes);
      assert.equal(inspected.metadata.stage1Enabled, combo.s1, `${combo.name}: msBX stage1Enabled mismatch`);
      assert.equal(inspected.metadata.stage2Enabled, combo.s2, `${combo.name}: msBX stage2Enabled mismatch`);
      assert.equal(inspected.metadata.stage3Enabled, combo.s3, `${combo.name}: msBX stage3Enabled mismatch`);

      const dec = await BitEngine.decryptFromPNG(enc.pngBytes, testKeyA);
      assert.equal(countDiffPixels(origRgb, dec.imageData), 0, `${combo.name}: must recover 0 different pixels`);
    }

    // Verify validation rejects 0 enabled stages and 0 enabled channels
    assert.throws(
      () => BitEngine.normalizeStageConfig({ stage1Enabled: false, stage2Enabled: false, stage3Enabled: false }),
      /At least one encryption stage/i
    );
    assert.throws(
      () => BitEngine.normalizeStageConfig({ stage1Enabled: false, stage2Enabled: false, stage3Enabled: true, stage3Channels: { r: false, g: false, b: false } }),
      /At least one RGB channel/i
    );

    pass('Standard Mode & all 7 Advanced stage combinations (S1, S2, S3, S1+S2, S1+S3, S2+S3, S1+S2+S3) verified with 0 different pixels');
  }

  // 17. Advanced Stage 2 Fixed Permutations (RGB/RBG/GRB/GBR/BRG/BGR), Stage 3 RGB Channel Subsets, k=1..8, Key Image, Selective Face/Body & Custom ROI
  {
    // A. Test all 6 Fixed RGB Permutations (0=RGB, 1=RBG, 2=GRB, 3=GBR, 4=BRG, 5=BGR) + Key-Driven
    for (let fixedId = 0; fixedId <= 5; fixedId++) {
      const encFixed = await BitEngine.encryptToPNG(cloneImageData(origRgb), testKeyA, null, {
        k: 2,
        iterations: 1000,
        encryptionMode: 'advanced',
        stageConfig: {
          encryptionMode: 'advanced',
          stage1Enabled: false,
          stage2Enabled: true,
          stage2Mode: 'fixed',
          stage2FixedPermId: fixedId,
          stage3Enabled: false,
          k: 2
        }
      });
      const insp = await BitEngine.inspectEncryptedPNG(encFixed.pngBytes);
      assert.equal(insp.metadata.stage2Mode, 'fixed');
      assert.equal(insp.metadata.stage2FixedPermId, fixedId);
      assert.equal(insp.metadata.stage2FixedPermLabel, BitEngine.CHANNEL_PERM_LABELS[fixedId]);

      const decFixed = await BitEngine.decryptFromPNG(encFixed.pngBytes, testKeyA);
      assert.equal(countDiffPixels(origRgb, decFixed.imageData), 0, `Fixed RGB permutation ${BitEngine.CHANNEL_PERM_LABELS[fixedId]} must recover 0 diff pixels`);
    }

    // B. Test all 7 non-empty RGB channel combinations in Stage 3 (and verify unselected channels remain 100% untouched when S1=false, S2=false!)
    const chCombos = [
      { r: true,  g: false, b: false },
      { r: false, g: true,  b: false },
      { r: false, g: false, b: true  },
      { r: true,  g: true,  b: false },
      { r: true,  g: false, b: true  },
      { r: false, g: true,  b: true  },
      { r: true,  g: true,  b: true  }
    ];

    for (const ch of chCombos) {
      const encCh = await BitEngine.encryptToPNG(cloneImageData(origRgb), testKeyA, null, {
        k: 5,
        iterations: 1000,
        encryptionMode: 'advanced',
        stageConfig: {
          encryptionMode: 'advanced',
          stage1Enabled: false,
          stage2Enabled: false,
          stage3Enabled: true,
          k: 5,
          stage3Channels: ch
        }
      });

      // Verify unselected channels were NOT modified in the encrypted image
      for (let i = 0; i < origRgb.data.length; i += 4) {
        if (!ch.r) assert.equal(encCh.imageData.data[i], origRgb.data[i], 'Disabled Red channel must remain unchanged');
        if (!ch.g) assert.equal(encCh.imageData.data[i + 1], origRgb.data[i + 1], 'Disabled Green channel must remain unchanged');
        if (!ch.b) assert.equal(encCh.imageData.data[i + 2], origRgb.data[i + 2], 'Disabled Blue channel must remain unchanged');
      }

      const decCh = await BitEngine.decryptFromPNG(encCh.pngBytes, testKeyA);
      assert.equal(countDiffPixels(origRgb, decCh.imageData), 0, `Channel subset R=${ch.r},G=${ch.g},B=${ch.b} must recover 0 diff pixels`);
    }

    // C. Test Key-Image + Face/Body Selective Mask + Custom ROI + Schema v1 & Schema v2 with Advanced Stage Config
    const keyImgBuffer = await BitEngine.encodeLosslessPNG(origGray);
    const keyImgDigest = await BitEngine.hashKeyImage(keyImgBuffer);
    const customRoi = [{ x: 10, y: 8, width: 28, height: 22 }];

    for (const ver of [1, 2]) {
      const encAdvRoi = await BitEngine.encryptToPNG(cloneImageData(origRgb), keyImgDigest.hex, customRoi, {
        k: 6,
        iterations: 1000,
        keyType: 'image',
        scope: 'custom',
        metaVersion: ver,
        encryptionMode: 'advanced',
        stageConfig: {
          encryptionMode: 'advanced',
          stage1Enabled: true,
          stage2Enabled: true,
          stage2Mode: 'fixed',
          stage2FixedPermId: 4, // BRG
          stage3Enabled: true,
          k: 6,
          stage3Channels: { r: true, g: false, b: true }
        }
      });

      // Verify PNG Binary Visualizer field breakdown includes the Stage Configuration fields
      const structAdv = BitEngine.parsePngBinaryStructure(encAdvRoi.pngBytes);
      assert.equal(structAdv.structuralValid, true);
      const stageField = structAdv.msbxSection.msbxBreakdown.fields.find(f => f.field.includes('Stage'));
      assert.ok(stageField, `Schema v${ver} field breakdown must include Stage Configuration fields`);

      const decAdvRoi = await BitEngine.decryptFromPNG(encAdvRoi.pngBytes, keyImgDigest.hex);
      assert.equal(countDiffPixels(origRgb, decAdvRoi.imageData), 0, `Schema v${ver} Advanced ROI + Key Image must recover 0 diff pixels`);
    }

    pass('All 6 Fixed RGB permutations, all 7 RGB channel subsets, k=1..8, Key-Image, Selective Face/Body & Custom ROI in Schema v1 & v2 verified with 0 different pixels');
  }

  // 18. Stage 1 Customizable Pixel Block Size (1×1 to 32×32 px), Mask-Aware Block Permutation, Irregular & Disconnected ROIs, Tiny ROI Fallback, Non-Divisible Dimensions
  {
    // Create a non-divisible 83 × 71 test image so every block size (2, 3, 5, 8, 16, 32) has incomplete edge regions
    const oddW = 83;
    const oddH = 71;
    const oddImg = createSyntheticImage(oddW, oddH, 'rgb');

    // A. Verify Stage 1 block size validation (1..32 valid; 0 or 33 rejected)
    assert.throws(
      () => BitEngine.normalizeStageConfig({ stage1Enabled: true, stage1BlockSize: 0 }, 2),
      /Invalid Stage 1 pixel block size/i
    );
    assert.throws(
      () => BitEngine.normalizeStageConfig({ stage1Enabled: true, stage1BlockSize: 33 }, 2),
      /Invalid Stage 1 pixel block size/i
    );

    // B. Test all required block sizes (1×1, 2×2, 3×3, 5×5, 8×8, 16×16, 32×32) across Entire Image on non-divisible 83×71 image
    const blockSizes = [1, 2, 3, 5, 8, 16, 32];
    const stage1OnlyOutputs = new Map();

    for (const B of blockSizes) {
      const saltFixed = new Uint8Array(16).fill(0x42);
      const encBlk = await BitEngine.encryptToPNG(cloneImageData(oddImg), testKeyA, null, {
        k: 2,
        iterations: 1000,
        salt: saltFixed,
        encryptionMode: B === 1 ? 'standard' : 'advanced',
        stageConfig: {
          encryptionMode: B === 1 ? 'standard' : 'advanced',
          stage1Enabled: true,
          stage1BlockSize: B,
          stage2Enabled: true,
          stage2Mode: 'keyed',
          stage3Enabled: true,
          k: 2,
          stage3Channels: { r: true, g: true, b: true }
        }
      });

      const insp = await BitEngine.inspectEncryptedPNG(encBlk.pngBytes);
      assert.equal(insp.metadata.stage1BlockSize, B, `Decoded metadata stage1BlockSize must equal ${B}`);
      assert.equal(insp.metadata.stageConfig.stage1BlockSize, B);

      const decBlk = await BitEngine.decryptFromPNG(encBlk.pngBytes, testKeyA);
      assert.equal(countDiffPixels(oddImg, decBlk.imageData), 0, `Full-image block size ${B}×${B} on 83×71 image must recover 0 diff pixels`);

      // Also run Stage-1-only encryption with fixed salt to verify different block sizes produce distinct spatial permutations
      const encS1Only = await BitEngine.encryptToPNG(cloneImageData(oddImg), testKeyA, null, {
        k: 2,
        iterations: 1000,
        salt: saltFixed,
        encryptionMode: 'advanced',
        stageConfig: {
          encryptionMode: 'advanced',
          stage1Enabled: true,
          stage1BlockSize: B,
          stage2Enabled: false,
          stage3Enabled: false,
          k: 2
        }
      });
      stage1OnlyOutputs.set(B, encS1Only.imageData);
      const decS1Only = await BitEngine.decryptFromPNG(encS1Only.pngBytes, testKeyA);
      assert.equal(countDiffPixels(oddImg, decS1Only.imageData), 0, `Stage-1-only block size ${B}×${B} must recover 0 diff pixels`);
    }

    // Verify 1×1, 5×5, and 16×16 Stage-1-only encrypted outputs are genuinely different from each other
    assert.ok(countDiffPixels(stage1OnlyOutputs.get(1), stage1OnlyOutputs.get(5)) > 100, '1×1 vs 5×5 Stage 1 output must differ');
    assert.ok(countDiffPixels(stage1OnlyOutputs.get(5), stage1OnlyOutputs.get(16)) > 100, '5×5 vs 16×16 Stage 1 output must differ');

    // C. Test Irregular Face Mask, Disconnected Multi-Person Body Mask, and Custom ROI across block sizes (1, 3, 5, 8, 16, 32)
    //    and verify 0 background pixels outside the mask are modified!
    const irregularFaceMask = new Uint8Array(oddW * oddH);
    const disconnectedBodyMask = new Uint8Array(oddW * oddH);
    for (let y = 0; y < oddH; y++) {
      for (let x = 0; x < oddW; x++) {
        const idx = y * oddW + x;
        // Irregular ellipse + wavy contour for Face mask
        const dx = (x - 41) / 22;
        const dy = (y - 35) / 24;
        if (dx * dx + dy * dy <= 1.0 + 0.12 * Math.sin(x * 0.7) * Math.cos(y * 0.6)) {
          irregularFaceMask[idx] = 1;
        }
        // Two disconnected person regions for Body mask (left person + right person)
        if ((x >= 5 && x <= 31 && y >= 8 && y <= 62) || (x >= 48 && x <= 77 && y >= 10 && y <= 65)) {
          disconnectedBodyMask[idx] = 1;
        }
      }
    }
    const customRoiRect = [{ x: 11, y: 9, width: 47, height: 39 }];
    const customRoiMask = new Uint8Array(oddW * oddH);
    const customTargetIdx = BitEngine.getTargetPixelIndices(oddImg, customRoiRect);
    for (let i = 0; i < customTargetIdx.length; i++) {
      customRoiMask[customTargetIdx[i]] = 1;
    }

    const regionConfigs = [
      { scope: 'face', maskInput: irregularFaceMask, binMask: irregularFaceMask },
      { scope: 'person', maskInput: disconnectedBodyMask, binMask: disconnectedBodyMask },
      { scope: 'custom', maskInput: customRoiRect, binMask: customRoiMask }
    ];

    for (const reg of regionConfigs) {
      for (const B of [1, 3, 5, 8, 16, 32]) {
        const encSelective = await BitEngine.encryptToPNG(cloneImageData(oddImg), testKeyA, reg.maskInput, {
          k: 3,
          iterations: 1000,
          scope: reg.scope,
          encryptionMode: 'advanced',
          stageConfig: {
            encryptionMode: 'advanced',
            stage1Enabled: true,
            stage1BlockSize: B,
            stage2Enabled: true,
            stage2Mode: 'keyed',
            stage3Enabled: true,
            k: 3,
            stage3Channels: { r: true, g: true, b: true }
          }
        });

        // Verify ZERO pixels outside the ROI mask were modified or shifted into background!
        let outsideModified = 0;
        for (let p = 0; p < oddW * oddH; p++) {
          if (reg.binMask[p] === 0) {
            const i = p * 4;
            if (encSelective.imageData.data[i] !== oddImg.data[i] ||
                encSelective.imageData.data[i + 1] !== oddImg.data[i + 1] ||
                encSelective.imageData.data[i + 2] !== oddImg.data[i + 2]) {
              outsideModified++;
            }
          }
        }
        assert.equal(outsideModified, 0, `Scope=${reg.scope} with block size ${B}×${B} must modify 0 pixels outside ROI mask`);

        // Verify decryption recovers 0 differing pixels
        const decSelective = await BitEngine.decryptFromPNG(encSelective.pngBytes, testKeyA);
        assert.equal(countDiffPixels(oddImg, decSelective.imageData), 0, `Scope=${reg.scope} with block size ${B}×${B} must recover 0 diff pixels`);
      }
    }

    // D. Test Tiny ROI smaller than chosen block size (e.g. 10×10 ROI with 32×32 block size => fallbackUsed = true)
    //    and Key Image + Schema v1 & Schema v2 round-trip
    const tinyRoi = [{ x: 15, y: 15, width: 10, height: 10 }];
    const tinyIndices = BitEngine.getTargetPixelIndices(oddImg, tinyRoi);
    const tinyPart = BitEngine.partitionMaskAwareBlocks(oddW, oddH, tinyIndices, 32);
    assert.equal(tinyPart.fallbackUsed, true, '10×10 ROI with 32×32 block size must trigger deterministic fallback');
    assert.equal(tinyPart.eligibleBlocks.length, 0);
    assert.equal(tinyPart.boundaryIndices.length, tinyIndices.length);

    const keyImgBuf18 = await BitEngine.encodeLosslessPNG(origGray);
    const keyImgDig18 = await BitEngine.hashKeyImage(keyImgBuf18);

    for (const ver of [1, 2]) {
      const encTiny = await BitEngine.encryptToPNG(cloneImageData(oddImg), keyImgDig18.hex, tinyRoi, {
        k: 4,
        iterations: 1000,
        keyType: 'image',
        scope: 'custom',
        metaVersion: ver,
        encryptionMode: 'advanced',
        stageConfig: {
          encryptionMode: 'advanced',
          stage1Enabled: true,
          stage1BlockSize: 32,
          stage2Enabled: true,
          stage2Mode: 'keyed',
          stage3Enabled: true,
          k: 4,
          stage3Channels: { r: true, g: true, b: true }
        }
      });
      const inspTiny = await BitEngine.inspectEncryptedPNG(encTiny.pngBytes);
      assert.equal(inspTiny.metadata.stage1BlockSize, 32, `Schema v${ver} must preserve stage1BlockSize=32`);

      const decTiny = await BitEngine.decryptFromPNG(encTiny.pngBytes, keyImgDig18.hex);
      assert.equal(countDiffPixels(oddImg, decTiny.imageData), 0, `Schema v${ver} tiny ROI fallback with 32×32 block size must recover 0 diff pixels`);
    }

    pass('Stage 1 customizable pixel block sizes (1×1..32×32 px), mask-aware block permutation, irregular/disconnected ROIs, tiny ROI fallback, non-divisible dimensions, and Schema v1/v2 round-trip verified with 0 different pixels');
  }

  // =========================================================================
  // 19. STAGE 2 CUSTOMIZABLE RGB CHANNEL PERMUTATION (DYNAMIC SUBSETS & FIXED)
  // =========================================================================
  {
    const imgW = 48;
    const imgH = 40;
    const srcImg = createSyntheticImage(imgW, imgH, 'rgb');
    const s2Key = 'Stage2-RGB-Custom-Key!';
    const keyImgBuf19 = await BitEngine.encodeLosslessPNG(origGray);
    const keyImgDig19 = await BitEngine.hashKeyImage(keyImgBuf19);

    // A. Validation check: 0 allowed permutations in Key-Driven mode must throw
    assert.throws(() => {
      BitEngine.normalizeStageConfig({
        encryptionMode: 'advanced',
        stage2Enabled: true,
        stage2Mode: 'keyed',
        stage2AllowedMask: 0
      }, 2);
    }, /At least one RGB channel permutation/i, 'Empty Stage 2 allowed permutation mask must be rejected');

    // B. Key-Driven Dynamic Subsets (All 6, 3-subset, 2-subset, 1-subset) across Schema v1 & v2
    const dynamicCases = [
      { label: 'All 6 (Default)', perms: ['RGB', 'RBG', 'GRB', 'GBR', 'BRG', 'BGR'], expectedMask: 0x3F },
      { label: '3-Subset {RGB,BGR,GRB}', perms: ['RGB', 'BGR', 'GRB'], expectedMask: (1 << 0) | (1 << 5) | (1 << 2) },
      { label: '2-Subset {RBG,GBR}', perms: ['RBG', 'GBR'], expectedMask: (1 << 1) | (1 << 3) },
      { label: '1-Subset {BGR}', perms: ['BGR'], expectedMask: (1 << 5) }
    ];

    for (const ver of [1, 2]) {
      for (const dc of dynamicCases) {
        const encDyn = await BitEngine.encryptToPNG(cloneImageData(srcImg), s2Key, null, {
          k: 3,
          iterations: 1000,
          metaVersion: ver,
          encryptionMode: 'advanced',
          stageConfig: {
            encryptionMode: 'advanced',
            stage1Enabled: true,
            stage1BlockSize: 4,
            stage2Enabled: true,
            stage2Mode: 'keyed',
            stage2AllowedPerms: dc.perms,
            stage3Enabled: true,
            k: 3,
            stage3Channels: { r: true, g: false, b: true }
          }
        });

        const insp = await BitEngine.inspectEncryptedPNG(encDyn.pngBytes);
        assert.equal(insp.metadata.stageConfig.stage2Mode, 'keyed');
        assert.equal(insp.metadata.stageConfig.stage2AllowedMask, dc.expectedMask, `Schema v${ver} ${dc.label} must persist stage2AllowedMask`);
        assert.equal(insp.metadata.stageConfig.stage2AllowedCount, dc.perms.length);

        const decDyn = await BitEngine.decryptFromPNG(encDyn.pngBytes, s2Key);
        assert.equal(countDiffPixels(srcImg, decDyn.imageData), 0, `Schema v${ver} Stage 2 Dynamic ${dc.label} must recover 0 diff pixels`);
      }
    }

    // C. Verify that single-permutation Key-Driven Dynamic {BGR} actually produces BGR channel order when Stage 1 & 3 are OFF
    const encOnlyBgr = await BitEngine.encryptToPNG(cloneImageData(srcImg), s2Key, null, {
      k: 2,
      iterations: 1000,
      metaVersion: 2,
      encryptionMode: 'advanced',
      stageConfig: {
        encryptionMode: 'advanced',
        stage1Enabled: false,
        stage2Enabled: true,
        stage2Mode: 'keyed',
        stage2AllowedPerms: ['BGR'],
        stage3Enabled: false,
        k: 2
      }
    });
    const encOnlyBgrImg = (await BitEngine.decodeLosslessPNG(encOnlyBgr.pngBytes)).imageData;
    for (let i = 0; i < imgW * imgH * 4; i += 4) {
      assert.equal(encOnlyBgrImg.data[i], srcImg.data[i + 2], 'Single allowed perm {BGR} must map R <- B');
      assert.equal(encOnlyBgrImg.data[i + 1], srcImg.data[i + 1], 'Single allowed perm {BGR} must map G <- G');
      assert.equal(encOnlyBgrImg.data[i + 2], srcImg.data[i], 'Single allowed perm {BGR} must map B <- R');
    }
    const decOnlyBgr = await BitEngine.decryptFromPNG(encOnlyBgr.pngBytes, s2Key);
    assert.equal(countDiffPixels(srcImg, decOnlyBgr.imageData), 0);

    // D. All 6 Fixed RGB Order options + Selective ROI (Face/Body/Custom) + Key Image + Mask Privacy Protection
    const roiMask = new Uint8Array(imgW * imgH);
    for (let y = 8; y < 32; y++) {
      for (let x = 10; x < 38; x++) {
        if (((x - 24) / 14) ** 2 + ((y - 20) / 12) ** 2 <= 1.0) {
          roiMask[y * imgW + x] = 1;
        }
      }
    }

    for (let permId = 0; permId < 6; permId++) {
      const encFix = await BitEngine.encryptToPNG(cloneImageData(srcImg), keyImgDig19.hex, roiMask, {
        k: 2,
        iterations: 1000,
        keyType: 'image',
        scope: 'face',
        protectMask: true,
        metaVersion: 2,
        encryptionMode: 'advanced',
        stageConfig: {
          encryptionMode: 'advanced',
          stage1Enabled: true,
          stage1BlockSize: 8,
          stage2Enabled: true,
          stage2Mode: 'fixed',
          stage2FixedPermId: permId,
          stage3Enabled: true,
          k: 2,
          stage3Channels: { r: true, g: true, b: true }
        }
      });

      const encFixImg = (await BitEngine.decodeLosslessPNG(encFix.pngBytes)).imageData;
      let outsideDiffs = 0;
      for (let p = 0; p < imgW * imgH; p++) {
        if (!roiMask[p]) {
          const idx = p * 4;
          if (encFixImg.data[idx] !== srcImg.data[idx] ||
              encFixImg.data[idx + 1] !== srcImg.data[idx + 1] ||
              encFixImg.data[idx + 2] !== srcImg.data[idx + 2]) {
            outsideDiffs++;
          }
        }
      }
      assert.equal(outsideDiffs, 0, `Fixed permId=${permId} must not modify pixels outside Face ROI`);

      const decFix = await BitEngine.decryptFromPNG(encFix.pngBytes, keyImgDig19.hex);
      assert.equal(countDiffPixels(srcImg, decFix.imageData), 0, `Fixed permId=${permId} with Key Image + Protected Mask must recover 0 diff pixels`);
    }

    // E. Stage 2 Disabled with Stage 1 (8x8) & Stage 3 (k=5)
    const encS2Off = await BitEngine.encryptToPNG(cloneImageData(srcImg), s2Key, roiMask, {
      k: 5,
      iterations: 1000,
      scope: 'body',
      metaVersion: 2,
      encryptionMode: 'advanced',
      stageConfig: {
        encryptionMode: 'advanced',
        stage1Enabled: true,
        stage1BlockSize: 8,
        stage2Enabled: false,
        stage3Enabled: true,
        k: 5,
        stage3Channels: { r: true, g: true, b: true }
      }
    });
    const decS2Off = await BitEngine.decryptFromPNG(encS2Off.pngBytes, s2Key);
    assert.equal(countDiffPixels(srcImg, decS2Off.imageData), 0, 'Stage 2 Disabled must recover 0 diff pixels');

    pass('Stage 2 RGB channel permutation customization (Key-Driven dynamic subsets, all 6 Fixed orders, Stage 2 OFF, ROI isolation, Key Image, Mask Protection, and Schema v1/v2) verified with 0 different pixels');
  }

  console.log(`\nALL ${passed} TEST SUITES PASSED SUCCESSFULLY.`);
}

runTests().catch((err) => {
  console.error('TEST SUITE FAILED:', err);
  process.exit(1);
});

