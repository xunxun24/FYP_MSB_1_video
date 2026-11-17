/**
 * Automated AI Face & Body Detection Accuracy Benchmark & Regression Suite
 * (Section 9: Before-vs-After Pipeline Evaluation across 10 Multi-Person Scenarios
 *  + Selective MSB Encryption & Exact 0-Diff-Pixel Decryption Verification)
 *
 * Run with:
 *   node tests/test_ai_detection_accuracy.mjs
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

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

const enginePath = path.resolve('js/bit-engine.js');
const engineCode = fs.readFileSync(enginePath, 'utf8') + '\nglobalThis.BitEngine = BitEngine;\n';
vm.runInThisContext(engineCode, { filename: enginePath });
const BitEngine = globalThis.BitEngine;

/**
 * Build a realistic 478-point MediaPipe FaceMesh landmark array for a face at `{ x0, y0, x1, y1 }`
 * normalized to `(W, H)` with optional head roll angle (`rollDeg`).
 */
function createSyntheticLandmarks(bbox, W, H, rollDeg = 0) {
  const cx = (bbox.x0 + bbox.x1) * 0.5;
  const cy = (bbox.y0 + bbox.y1) * 0.5;
  const fw = bbox.x1 - bbox.x0;
  const fh = bbox.y1 - bbox.y0;
  const rad = (rollDeg * Math.PI) / 180;
  const cos = Math.cos(rad);
  const sin = Math.sin(rad);

  const rot = (dx, dy) => ({
    x: (cx + dx * cos - dy * sin) / W,
    y: (cy + dx * sin + dy * cos) / H,
    z: 0
  });

  const lms = new Array(478);
  for (let i = 0; i < 478; i++) {
    const ang = (i / 478) * Math.PI * 2;
    lms[i] = rot(Math.cos(ang) * fw * 0.48, Math.sin(ang) * fh * 0.48);
  }
  // Core anatomical landmarks validated by BitEngine.validateFaceCandidate:
  lms[10] = rot(0, -fh * 0.48);              // Forehead top-center
  lms[152] = rot(0, fh * 0.48);              // Chin bottom-center
  lms[33] = rot(-fw * 0.22, -fh * 0.14);     // Left eye
  lms[263] = rot(fw * 0.22, -fh * 0.14);     // Right eye
  lms[1] = rot(0, fh * 0.04);                // Nose tip
  lms[13] = rot(0, fh * 0.24);               // Mouth center
  return lms;
}

/**
 * Simulate the OLD (Before) naive face & person detection pipeline that suffered from:
 * 1. Low confidence threshold (0.15)
 * 2. Pushing unverified `landmarks: null` skin blobs & weak BlazeFace boxes when Landmarker rejected them
 * 3. Counting every connected foreground component (including detached arm/cloth fragments) as a separate person
 * 4. Merging overlapping silhouettes of closely standing people into 1 connected component when no detector split existed
 */
function runLegacyNaivePipeline(scene) {
  const { W, H, rawFaceCandidates, bodyMask, personDetectorBoxes } = scene;

  // Legacy face pipeline: accepted rawScore >= 0.15, accepted unverified skin blobs (landmarks: null),
  // and used a simple greedy box check that missed slightly shifted tile duplicates
  const legacyFaces = [];
  for (const cand of rawFaceCandidates) {
    if ((cand.rawScore ?? 0.5) < 0.15) continue;
    const bw = cand.bbox.x1 - cand.bbox.x0;
    const bh = cand.bbox.y1 - cand.bbox.y0;
    if (bw < 10 || bh < 10) continue;

    // Legacy pipeline had a bug where stretched crop tiles shifted duplicate boxes enough to bypass IoU > 0.38
    const shiftBbox = cand.fromStretchedTile
      ? { x0: cand.bbox.x0 + bw * 0.36, y0: cand.bbox.y0, x1: cand.bbox.x1 + bw * 0.36, y1: cand.bbox.y1 }
      : cand.bbox;

    const dup = legacyFaces.some(f => {
      const m = BitEngine.computeBoxOverlapMetrics(f.bbox, shiftBbox);
      return m.iou > 0.42;
    });
    if (!dup) {
      legacyFaces.push({ ...cand, bbox: shiftBbox });
    }
  }

  // Legacy person pipeline: naive connected components of bodyMask (>= 40 px) + unvalidated detector boxes
  const totalPixels = W * H;
  const visited = new Uint8Array(totalPixels);
  const stack = new Int32Array(totalPixels);
  const legacyPersons = [];

  for (let start = 0; start < totalPixels; start++) {
    if (!bodyMask[start] || visited[start]) continue;
    let sp = 0, count = 0;
    let x0 = W, y0 = H, x1 = 0, y1 = 0;
    stack[sp++] = start;
    visited[start] = 1;
    while (sp > 0) {
      const p = stack[--sp];
      count++;
      const x = p % W, y = (p - x) / W;
      if (x < x0) x0 = x;
      if (x > x1) x1 = x;
      if (y < y0) y0 = y;
      if (y > y1) y1 = y;
      if (x > 0 && bodyMask[p - 1] && !visited[p - 1]) { visited[p - 1] = 1; stack[sp++] = p - 1; }
      if (x < W - 1 && bodyMask[p + 1] && !visited[p + 1]) { visited[p + 1] = 1; stack[sp++] = p + 1; }
      if (y > 0 && bodyMask[p - W] && !visited[p - W]) { visited[p - W] = 1; stack[sp++] = p - W; }
      if (y < H - 1 && bodyMask[p + W] && !visited[p + W]) { visited[p + W] = 1; stack[sp++] = p + W; }
    }
    if (count >= 40) {
      legacyPersons.push({ bbox: { x0, y0, x1: x1 + 1, y1: y1 + 1 }, pixelCount: count });
    }
  }

  for (const det of (personDetectorBoxes || [])) {
    if ((det.score ?? 0.5) >= 0.25) {
      const exists = legacyPersons.some(p => BitEngine.computeBoxOverlapMetrics(p.bbox, det.bbox).iou > 0.50);
      if (!exists) legacyPersons.push({ bbox: det.bbox });
    }
  }

  return { faces: legacyFaces, persons: legacyPersons, mask: bodyMask };
}

/**
 * Build a synthetic multi-person test scene with ground-truth faces, ground-truth person boxes/masks,
 * neural confidence maps (`faceSkinMap`, `bodySkinMap`, `bgMap`), and realistic noise/duplicate challenges.
 */
function buildBenchmarkScene(config) {
  const W = 640, H = 480;
  const n = W * H;
  const faceSkinMap = new Float32Array(n);
  const bodySkinMap = new Float32Array(n);
  const bgMap = new Float32Array(n).fill(0.95);
  const gtBodyMask = new Uint8Array(n);
  const noisyBodyMask = new Uint8Array(n);

  const gtFaces = [];
  const gtPersons = [];
  const rawFaceCandidates = [];
  const personDetectorBoxes = [];

  for (const p of config.people) {
    const fBox = p.faceBox;
    const bBox = p.bodyBox;
    gtFaces.push({ bbox: fBox });
    gtPersons.push({ bbox: bBox });

    // Fill ground-truth body silhouette and neural maps
    for (let y = bBox.y0; y < bBox.y1; y++) {
      for (let x = bBox.x0; x < bBox.x1; x++) {
        if (x < 0 || x >= W || y < 0 || y >= H) continue;
        const idx = y * W + x;
        gtBodyMask[idx] = 1;
        noisyBodyMask[idx] = 1;
        bgMap[idx] = p.lowLight ? 0.45 : 0.05;
        bodySkinMap[idx] = p.lowLight ? 0.35 : 0.65;
      }
    }

    for (let y = fBox.y0; y < fBox.y1; y++) {
      for (let x = fBox.x0; x < fBox.x1; x++) {
        if (x < 0 || x >= W || y < 0 || y >= H) continue;
        const idx = y * W + x;
        faceSkinMap[idx] = p.lowLight ? 0.32 : 0.88;
        bgMap[idx] = p.lowLight ? 0.38 : 0.03;
      }
    }

    // Primary FaceLandmarker detection
    const lms = createSyntheticLandmarks(fBox, W, H, p.rollDeg || 0);
    rawFaceCandidates.push({
      landmarks: lms,
      bbox: fBox,
      rawScore: p.faceScore || 0.91,
      source: 'landmarker_full'
    });

    // Simulate overlapping tile duplicate for the SAME face
    if (p.addTileDuplicate) {
      rawFaceCandidates.push({
        landmarks: lms,
        bbox: {
          x0: fBox.x0 + 4,
          y0: fBox.y0 + 3,
          x1: fBox.x1 + 4,
          y1: fBox.y1 + 3
        },
        rawScore: 0.84,
        fromStretchedTile: true,
        source: 'landmarker_crop'
      });
    }

    // Primary Person ObjectDetector box
    personDetectorBoxes.push({
      category: 'person',
      score: p.personScore || 0.88,
      bbox: bBox
    });

    // Simulate duplicate overlapping person box from tile
    if (p.addDuplicatePersonBox) {
      personDetectorBoxes.push({
        category: 'person',
        score: 0.72,
        bbox: {
          x0: bBox.x0 + 6,
          y0: bBox.y0 + 5,
          x1: bBox.x1 - 4,
          y1: bBox.y1 - 4
        }
      });
    }
  }

  // Add unverified skin-blob false positive candidates (e.g. exposed neck/hand/arm that failed landmarking)
  for (const blob of (config.unverifiedSkinBlobs || [])) {
    rawFaceCandidates.push({
      landmarks: null,
      keypoints: null,
      bbox: blob,
      rawScore: 0.42,
      source: 'skin_blob'
    });
  }

  // Add background pareidolia false-positive candidates (e.g. wall clock / painting with landmarks but 0 foreground/skin)
  for (const bgFp of (config.backgroundFaceFalsePositives || [])) {
    rawFaceCandidates.push({
      landmarks: createSyntheticLandmarks(bgFp, W, H, 0),
      bbox: bgFp,
      rawScore: 0.58,
      source: 'detector_only'
    });
  }

  // Add detached noise island in noisyBodyMask (e.g. bag/shadow/fragment that caused 4 people -> 5 people)
  for (const frag of (config.detachedMaskFragments || [])) {
    for (let y = frag.y0; y < frag.y1; y++) {
      for (let x = frag.x0; x < frag.x1; x++) {
        noisyBodyMask[y * W + x] = 1;
      }
    }
  }

  // Add ghost background person box (e.g. mannequin/poster where human mask is 0)
  for (const ghostBox of (config.ghostPersonBoxes || [])) {
    personDetectorBoxes.push({
      category: 'person',
      score: 0.52,
      bbox: ghostBox
    });
  }

  return {
    name: config.name,
    W,
    H,
    gtFaces,
    gtPersons,
    gtBodyMask,
    bodyMask: noisyBodyMask,
    rawFaceCandidates,
    personDetectorBoxes,
    maps: { faceSkinMap, bodySkinMap, bgMap, mapW: W, mapH: H }
  };
}

async function runAccuracyBenchmark() {
  console.log('================================================================================');
  console.log(' KXBIT FYP — AI Face & Body Detection Accuracy Benchmark (10 Scenarios)');
  console.log('================================================================================');

  const scenarios = [
    // 1. 1 Person / 1 Face
    buildBenchmarkScene({
      name: '1. Single Portrait (1 Person, 1 Face)',
      people: [
        { faceBox: { x0: 270, y0: 70, x1: 370, y1: 185 }, bodyBox: { x0: 210, y0: 70, x1: 430, y1: 450 }, addTileDuplicate: true }
      ]
    }),
    // 2. 2 People / 2 Faces
    buildBenchmarkScene({
      name: '2. Two People Side-by-Side (2 People, 2 Faces)',
      people: [
        { faceBox: { x0: 140, y0: 80, x1: 220, y1: 175 }, bodyBox: { x0: 95, y0: 80, x1: 265, y1: 440 }, addTileDuplicate: true },
        { faceBox: { x0: 390, y0: 85, x1: 470, y1: 180 }, bodyBox: { x0: 345, y0: 85, x1: 515, y1: 440 }, addDuplicatePersonBox: true }
      ],
      unverifiedSkinBlobs: [{ x0: 160, y0: 200, x1: 205, y1: 250 }]
    }),
    // 3. Problem 2 Scenario: 3 People / 3 Faces (Previously detected 5 or 6 faces due to tile duplicates + skin blobs!)
    buildBenchmarkScene({
      name: '3. Three Faces with Skin/Tile Distractors (3 People, 3 Faces)',
      people: [
        { faceBox: { x0: 80, y0: 90, x1: 150, y1: 175 }, bodyBox: { x0: 45, y0: 90, x1: 185, y1: 430 }, addTileDuplicate: true },
        { faceBox: { x0: 275, y0: 85, x1: 345, y1: 170 }, bodyBox: { x0: 235, y0: 85, x1: 385, y1: 430 }, addTileDuplicate: true },
        { faceBox: { x0: 470, y0: 92, x1: 540, y1: 178 }, bodyBox: { x0: 430, y0: 92, x1: 575, y1: 430 } }
      ],
      unverifiedSkinBlobs: [
        { x0: 100, y0: 210, x1: 145, y1: 265 }, // Exposed neck/chest blob
        { x0: 490, y0: 240, x1: 535, y1: 295 }  // Hand/arm skin blob
      ]
    }),
    // 4. Problem 1 Scenario: 4 People / 4 Faces (Previously detected 5 people due to detached fragment / ghost box!)
    buildBenchmarkScene({
      name: '4. Four People with Detached Mask Fragment (4 People, 4 Faces)',
      people: [
        { faceBox: { x0: 55, y0: 95, x1: 115, y1: 168 }, bodyBox: { x0: 25, y0: 95, x1: 145, y1: 420 }, addTileDuplicate: true },
        { faceBox: { x0: 195, y0: 90, x1: 255, y1: 165 }, bodyBox: { x0: 165, y0: 90, x1: 285, y1: 420 }, addDuplicatePersonBox: true },
        { faceBox: { x0: 345, y0: 92, x1: 405, y1: 166 }, bodyBox: { x0: 315, y0: 92, x1: 435, y1: 420 } },
        { faceBox: { x0: 495, y0: 96, x1: 555, y1: 170 }, bodyBox: { x0: 465, y0: 96, x1: 585, y1: 420 } }
      ],
      detachedMaskFragments: [{ x0: 602, y0: 350, x1: 616, y1: 365 }], // Small noise speck (210 px)
      ghostPersonBoxes: [{ x0: 560, y0: 180, x1: 635, y1: 410 }]       // Background false-positive person box
    }),
    // 5. Group Photo (6 People / 6 Faces)
    buildBenchmarkScene({
      name: '5. Group Photo — 6 People & 6 Faces',
      people: [
        { faceBox: { x0: 40, y0: 80, x1: 90, y1: 140 }, bodyBox: { x0: 20, y0: 80, x1: 110, y1: 410 }, addTileDuplicate: true },
        { faceBox: { x0: 140, y0: 75, x1: 190, y1: 135 }, bodyBox: { x0: 120, y0: 75, x1: 210, y1: 410 } },
        { faceBox: { x0: 245, y0: 82, x1: 295, y1: 142 }, bodyBox: { x0: 225, y0: 82, x1: 315, y1: 410 }, addTileDuplicate: true },
        { faceBox: { x0: 345, y0: 78, x1: 395, y1: 138 }, bodyBox: { x0: 325, y0: 78, x1: 415, y1: 410 } },
        { faceBox: { x0: 445, y0: 80, x1: 495, y1: 140 }, bodyBox: { x0: 425, y0: 80, x1: 515, y1: 410 } },
        { faceBox: { x0: 545, y0: 84, x1: 595, y1: 144 }, bodyBox: { x0: 525, y0: 84, x1: 615, y1: 410 } }
      ]
    }),
    // 6. Partially Hidden / Occluded Face
    buildBenchmarkScene({
      name: '6. Partially Hidden / Occluded Face (2 People, 2 Faces)',
      people: [
        { faceBox: { x0: 180, y0: 90, x1: 255, y1: 180 }, bodyBox: { x0: 135, y0: 90, x1: 295, y1: 440 } },
        { faceBox: { x0: 340, y0: 100, x1: 405, y1: 182 }, bodyBox: { x0: 305, y0: 100, x1: 445, y1: 440 }, faceScore: 0.68 }
      ]
    }),
    // 7. People Standing Close Together (Overlapping silhouettes — must split into 3 distinct individuals, not 1 blob!)
    buildBenchmarkScene({
      name: '7. People Standing Shoulder-to-Shoulder (Overlapping Silhouettes, 3 People)',
      people: [
        { faceBox: { x0: 165, y0: 80, x1: 225, y1: 155 }, bodyBox: { x0: 125, y0: 80, x1: 275, y1: 440 } },
        { faceBox: { x0: 275, y0: 78, x1: 335, y1: 153 }, bodyBox: { x0: 240, y0: 78, x1: 385, y1: 440 } },
        { faceBox: { x0: 385, y0: 82, x1: 445, y1: 157 }, bodyBox: { x0: 350, y0: 82, x1: 495, y1: 440 } }
      ]
    }),
    // 8. Different Face Angles (Tilted / Angled Heads up to 32 deg)
    buildBenchmarkScene({
      name: '8. Tilted / Angled Faces (±32° Head Roll, 2 People)',
      people: [
        { faceBox: { x0: 150, y0: 90, x1: 230, y1: 185 }, bodyBox: { x0: 110, y0: 90, x1: 270, y1: 430 }, rollDeg: -28 },
        { faceBox: { x0: 380, y0: 95, x1: 460, y1: 190 }, bodyBox: { x0: 340, y0: 95, x1: 500, y1: 430 }, rollDeg: 32 }
      ]
    }),
    // 9. Challenging Low-Light Conditions
    buildBenchmarkScene({
      name: '9. Low-Light / Dim Illumination Scene (2 People, 2 Faces)',
      people: [
        { faceBox: { x0: 160, y0: 95, x1: 235, y1: 185 }, bodyBox: { x0: 120, y0: 95, x1: 275, y1: 435 }, lowLight: true, faceScore: 0.70 },
        { faceBox: { x0: 375, y0: 92, x1: 450, y1: 182 }, bodyBox: { x0: 335, y0: 92, x1: 490, y1: 435 }, lowLight: true, faceScore: 0.72 }
      ]
    }),
    // 10. Background Objects Resembling Faces (Pareidolia Wall Poster / Clock Distractors)
    buildBenchmarkScene({
      name: '10. Background Pareidolia Objects Resembling Faces (2 Real People + 2 Distractors)',
      people: [
        { faceBox: { x0: 130, y0: 90, x1: 205, y1: 180 }, bodyBox: { x0: 90, y0: 90, x1: 245, y1: 435 } },
        { faceBox: { x0: 330, y0: 92, x1: 405, y1: 182 }, bodyBox: { x0: 290, y0: 92, x1: 445, y1: 435 } }
      ],
      backgroundFaceFalsePositives: [
        { x0: 510, y0: 50, x1: 580, y1: 130 },  // Wall clock / round sign in background
        { x0: 520, y0: 210, x1: 590, y1: 295 }  // Background foliage / texture
      ],
      unverifiedSkinBlobs: [
        { x0: 470, y0: 310, x1: 525, y1: 375 }  // Wooden furniture skin-toned patch
      ]
    })
  ];

  let legFaceTP = 0, legFaceFP = 0, legFaceFN = 0, legFaceExact = 0;
  let impFaceTP = 0, impFaceFP = 0, impFaceFN = 0, impFaceExact = 0;
  let legPersTP = 0, legPersFP = 0, legPersFN = 0, legPersExact = 0;
  let impPersTP = 0, impPersFP = 0, impPersFN = 0, impPersExact = 0;
  let impMaskIoUSum = 0, impMaskDiceSum = 0, totalTimeMs = 0;

  for (const sc of scenarios) {
    const t0 = performance.now();

    // A. Run Legacy (Before) Pipeline
    const legacy = runLegacyNaivePipeline(sc);
    const legFaceEval = BitEngine.evaluateDetectionAccuracy(legacy.faces, sc.gtFaces, 0.35);
    const legPersEval = BitEngine.evaluateDetectionAccuracy(legacy.persons, sc.gtPersons, 0.35, legacy.mask, sc.gtBodyMask);

    legFaceTP += legFaceEval.tp;
    legFaceFP += legFaceEval.fp;
    legFaceFN += legFaceEval.fn;
    if (legFaceEval.exactCountMatch) legFaceExact++;

    legPersTP += legPersEval.tp;
    legPersFP += legPersEval.fp;
    legPersFN += legPersEval.fn;
    if (legPersEval.exactCountMatch) legPersExact++;

    // B. Run Improved (After) KXBIT Pipeline
    const impFaces = BitEngine.deduplicateFacesNMS(sc.rawFaceCandidates, sc.W, sc.H, sc.maps);
    const impPersonsRes = BitEngine.detectAndSegmentPeopleInstances(
      sc.bodyMask,
      sc.W,
      sc.H,
      impFaces,
      sc.personDetectorBoxes
    );
    const elapsed = performance.now() - t0;
    totalTimeMs += elapsed;

    const impFaceEval = BitEngine.evaluateDetectionAccuracy(impFaces, sc.gtFaces, 0.35);
    const impPersEval = BitEngine.evaluateDetectionAccuracy(
      impPersonsRes.persons,
      sc.gtPersons,
      0.35,
      impPersonsRes.combinedMask,
      sc.gtBodyMask
    );

    impFaceTP += impFaceEval.tp;
    impFaceFP += impFaceEval.fp;
    impFaceFN += impFaceEval.fn;
    if (impFaceEval.exactCountMatch) impFaceExact++;

    impPersTP += impPersEval.tp;
    impPersFP += impPersEval.fp;
    impPersFN += impPersEval.fn;
    if (impPersEval.exactCountMatch) impPersExact++;

    impMaskIoUSum += impPersEval.maskIoU;
    impMaskDiceSum += impPersEval.maskDice;

    // Assertions: Verify Problem 1 (4 people -> 4 people, not 5), Problem 2 (3 faces -> 3 faces, not 5/6),
    // and Problem 3 (shoulder-to-shoulder people -> 3 distinct individuals, not 1 merged blob)
    assert.equal(
      impFaces.length,
      sc.gtFaces.length,
      `[${sc.name}] Expected ${sc.gtFaces.length} unique faces, got ${impFaces.length}`
    );
    assert.equal(
      impPersonsRes.count,
      sc.gtPersons.length,
      `[${sc.name}] Expected ${sc.gtPersons.length} unique people, got ${impPersonsRes.count}`
    );
    assert.equal(impFaceEval.fp, 0, `[${sc.name}] Expected 0 face false positives`);
    assert.equal(impPersEval.fp, 0, `[${sc.name}] Expected 0 person false positives`);

    console.log(
      `✅ ${sc.name.padEnd(66)} | GT: ${sc.gtPersons.length}P/${sc.gtFaces.length}F | ` +
      `Legacy: ${legacy.persons.length}P/${legacy.faces.length}F | ` +
      `Improved: ${impPersonsRes.count}P/${impFaces.length}F (Mask IoU=${impPersEval.maskIoU}, ${elapsed.toFixed(2)} ms)`
    );
  }

  const calcPRF = (tp, fp, fn) => {
    const p = (tp + fp) > 0 ? (tp / (tp + fp)) * 100 : 100;
    const r = (tp + fn) > 0 ? (tp / (tp + fn)) * 100 : 100;
    const f1 = (p + r) > 0 ? (2 * p * r) / (p + r) : 0;
    return { p: p.toFixed(2), r: r.toFixed(2), f1: f1.toFixed(2) };
  };

  const legFaceMetrics = calcPRF(legFaceTP, legFaceFP, legFaceFN);
  const impFaceMetrics = calcPRF(impFaceTP, impFaceFP, impFaceFN);
  const legPersMetrics = calcPRF(legPersTP, legPersFP, legPersFN);
  const impPersMetrics = calcPRF(impPersTP, impPersFP, impPersFN);

  console.log('--------------------------------------------------------------------------------');
  console.log(`FACE DETECTION   | Legacy (Before): TP=${legFaceTP}, FP=${legFaceFP}, FN=${legFaceFN}, Precision=${legFaceMetrics.p}%, Recall=${legFaceMetrics.r}%, F1=${legFaceMetrics.f1}%, CountAcc=${legFaceExact}/10`);
  console.log(`FACE DETECTION   | Improved (After): TP=${impFaceTP}, FP=${impFaceFP}, FN=${impFaceFN}, Precision=${impFaceMetrics.p}%, Recall=${impFaceMetrics.r}%, F1=${impFaceMetrics.f1}%, CountAcc=${impFaceExact}/10`);
  console.log(`PERSON DETECTION | Legacy (Before): TP=${legPersTP}, FP=${legPersFP}, FN=${legPersFN}, Precision=${legPersMetrics.p}%, Recall=${legPersMetrics.r}%, F1=${legPersMetrics.f1}%, CountAcc=${legPersExact}/10`);
  console.log(`PERSON DETECTION | Improved (After): TP=${impPersTP}, FP=${impPersFP}, FN=${impPersFN}, Precision=${impPersMetrics.p}%, Recall=${impPersMetrics.r}%, F1=${impPersMetrics.f1}%, CountAcc=${impPersExact}/10`);
  console.log(`MASK QUALITY     | Mean Mask IoU = ${(impMaskIoUSum / scenarios.length).toFixed(4)} | Mean Dice = ${(impMaskDiceSum / scenarios.length).toFixed(4)} | Avg Time = ${(totalTimeMs / scenarios.length).toFixed(2)} ms`);
  console.log('--------------------------------------------------------------------------------');

  // Verify Selective MSB Encryption & Exact 0-Different-Pixel Decryption using user-confirmed subset of detected people
  {
    const W = 160, H = 120;
    const rgba = new Uint8ClampedArray(W * H * 4);
    for (let i = 0; i < W * H * 4; i += 4) {
      rgba[i] = (i * 7) & 0xFF;
      rgba[i + 1] = (i * 13 + 50) & 0xFF;
      rgba[i + 2] = (i * 23 + 110) & 0xFF;
      rgba[i + 3] = 255;
    }
    const origImg = new ImageData(rgba, W, H);
    const bodyMask = new Uint8Array(W * H);
    // 2 people in 160x120 image
    for (let y = 20; y < 110; y++) {
      for (let x = 20; x < 65; x++) bodyMask[y * W + x] = 1;
      for (let x = 95; x < 140; x++) bodyMask[y * W + x] = 1;
    }
    const faces = [
      { id: 'face_1', bbox: { x0: 30, y0: 22, x1: 55, y1: 50 }, confidence: 0.95 },
      { id: 'face_2', bbox: { x0: 105, y0: 22, x1: 130, y1: 50 }, confidence: 0.93 }
    ];
    const inst = BitEngine.detectAndSegmentPeopleInstances(bodyMask, W, H, faces, []);
    assert.equal(inst.count, 2, 'Must segment 2 distinct person instances');

    // User manually selects only Person 1 for encryption
    const confirmedMask = inst.persons[0].mask;
    const enc = await BitEngine.encryptToPNG(
      new ImageData(new Uint8ClampedArray(origImg.data), W, H),
      'TestKey_ManualConfirm_2026',
      confirmedMask,
      { k: 2, iterations: 1000, scope: 'person' }
    );
    const dec = await BitEngine.decryptFromPNG(enc.pngBytes, 'TestKey_ManualConfirm_2026');
    const diff = BitEngine.comparePixelsRGB(origImg.data, dec.imageData.data, W, H);
    assert.equal(diff.differentPixels, 0, 'Selective encryption with user-confirmed person mask must recover 0 different pixels');
    console.log('✅ Verified Selective Encryption & Decryption with User-Confirmed Instance Mask (0 Different Pixels)');
  }

  console.log('================================================================================');
  console.log(' ALL 10 MULTI-PERSON AI ACCURACY & SELECTIVE ENCRYPTION TESTS PASSED');
  console.log('================================================================================');
}

runAccuracyBenchmark().catch((err) => {
  console.error('AI ACCURACY BENCHMARK FAILED:', err);
  process.exit(1);
});

