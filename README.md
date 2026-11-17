# BitShield FYP — MSB-Based Image Encryption Using Pixel Permutation, RGB Channel Permutation and 2-MSB XOR Encryption

A client-side web-based reversible image encryption, AI-assisted selective region encryption, and steganography suite built with HTML5, CSS3, and Vanilla JavaScript, deployed on **Cloudflare Pages**.

---

## 1. Self-Describing Encrypted PNG Architecture (`encrypted_photo.png`)

Instead of relying solely on a custom binary container, the primary output of encryption is a **Self-Describing Encrypted PNG** (`encrypted_photo.png`) that:
1. **Remains a 100% valid ISO/IEC 15948 (RFC 2083) PNG image** readable by any standard image viewer (Windows Photos, macOS Preview, desktop/mobile browsers).
2. **Displays the encrypted ciphertext pixels** in `IDAT` rather than the original unencrypted image.
3. **Embeds all required non-secret decryption metadata** inside a private ancillary PNG chunk named **`msBx`** (`0x6D, 0x73, 0x42, 0x78`).
4. **Verifies lossless pixel encoding automatically** on every encryption by decoding the generated PNG and confirming:
   $$\text{Encrypted pixels before PNG encoding} = \text{Encrypted pixels after PNG decoding} \quad (\text{Different pixels} = 0)$$
5. **Preserves legacy `.msbx` decryption support** on the Decrypt page for backward compatibility.

---

## 2. PNG Metadata Format (`msBx` Private Ancillary Chunk)

Per ISO/IEC 15948 PNG chunk naming conventions:
- **`m`** (lowercase, bit 5 = 1): **Ancillary** — standard PNG viewers safely ignore this chunk when displaying the image.
- **`s`** (lowercase, bit 5 = 1): **Private** — application-specific FYP metadata.
- **`B`** (uppercase, bit 5 = 0): **Reserved bit = 0** (required by PNG specification).
- **`x`** (lowercase, bit 5 = 1): **Safe-to-copy**.

### Binary Layout of the `msBx` Chunk Payload (Big-Endian)

| Byte Offset | Size | Type | Field | Description |
| :--- | :--- | :--- | :--- | :--- |
| `0..7` | 8 B | ASCII | `identifier` | Fixed FYP identifier `"KENX-ENC"` |
| `8` | 1 B | `uint8` | `meta_version` | Metadata format version (`1`) |
| `9` | 1 B | `uint8` | `algo_version` | 3-Stage Encryption Algorithm version (`1`) |
| `10` | 1 B | `uint8` | `color_mode` | Original colour mode: `0` = Grayscale (8-bit), `1` = RGB (24-bit), `2` = RGBA (32-bit) |
| `11` | 1 B | `uint8` | `k` | Number of encrypted MSB bits ($1 \le k \le 8$, default $k = 2$) |
| `12` | 1 B | `uint8` | `key_type` | Key source required: `0` = Password, `1` = Key Image |
| `13` | 1 B | `uint8` | `scope` | Encryption scope: `0` = Full Image, `1` = Human Body, `2` = Human Face, `3` = Custom ROI |
| `14` | 1 B | `uint8` | `mask_encoding` | `0` = None (Full Image), `1` = Plain RLE-Varint mask, `2` = Keystream-Protected RLE-Varint mask |
| `15` | 1 B | `uint8` | `reserved` | Reserved flags (`0`) |
| `16..19` | 4 B | `uint32` BE | `width` | Original image width in pixels |
| `20..23` | 4 B | `uint32` BE | `height` | Original image height in pixels |
| `24..27` | 4 B | `uint32` BE | `iterations` | Iterated SHA-256 KDF count (default `100,000`) |
| `28..43` | 16 B | `uint8[16]` | `salt` | Fresh CSPRNG random salt per encryption |
| `44..75` | 32 B | `uint8[32]` | `verification_tag` | SHA-256 authentication tag over master key + header prefix + original plaintext pixels + mask |
| `76..79` | 4 B | `uint32` BE | `mask_length` | *(Present only when `scope != 0`)* Byte length $M$ of the encoded segmentation mask |
| `80..80+M-1` | $M$ B | `uint8[M]` | `mask_payload` | *(Present only when `scope != 0`)* Lossless LEB128 RLE-encoded binary mask ($W \times H$ pixels) |

**What is NEVER stored in `msBx`:** Plaintext passwords, raw secret keys, key images, or the original unencrypted image.

---

## 3. Three-Stage Reversible Encryption & Decryption Workflows

### Key Derivation (`BitEngine.deriveMasterKeyIterated`)
1. Generate a fresh 16-byte cryptographic random salt $S$ (`crypto.getRandomValues`).
2. Compute initial digest $D_0 = \text{SHA-256}(\text{secret} \parallel S)$, followed by $N - 1$ rounds of $D_i = \text{SHA-256}(D_{i-1} \parallel S)$ (default $N = 100{,}000$ iterations).
3. For image-key mode (`key_type = 1`), the exact binary bytes of the key image are hashed with SHA-256 (`BitEngine.hashKeyImage`) to form the deterministic secret input.
4. Derive independent domain-separated Xoshiro128** keystreams via $\text{SHA-256}(K_{\text{master}} \parallel S \parallel \text{domainTag})$:
   - `"STAGE1_PIXEL_PERM"`
   - `"STAGE2_CHANNEL_PERM"`
   - `"STAGE3_MSB_XOR"`
   - `"KENX_PNG_VERIFY_TAG"`
   - `"MASK_PROTECT_STREAM"` (when optional mask privacy protection is enabled)

### Encryption Order (`BitEngine.encryptToPNG`)
$$\text{Original Pixels} \longrightarrow \text{Stage 1: Fisher–Yates Pixel Permutation} \longrightarrow \text{Stage 2: 6-State RGB Channel Permutation} \longrightarrow \text{Stage 3: } k\text{-MSB XOR} \longrightarrow \text{Lossless PNG + } \texttt{msBx}$$

### Decryption & Verification Order (`BitEngine.decryptFromPNG`)
$$\text{Encrypted PNG} \longrightarrow \text{Read } \texttt{msBx} \text{ Metadata} \longrightarrow \text{Reverse Stage 3 (MSB XOR)} \longrightarrow \text{Reverse Stage 2 (Inverse RGB Perm)} \longrightarrow \text{Reverse Stage 1 (Inverse Pixel Perm)} \longrightarrow \text{Verify SHA-256 Tag}$$
- If the SHA-256 verification tag over the recovered pixels does not match byte-for-byte, decryption aborts immediately, clears the output canvas, and displays:
  > *"The password or key image is incorrect, or the encrypted PNG has been modified. No recovered image was saved."*

---

## 4. AI Region Mask Storage & Security Consideration

- **AI Segmentation**: Uses MediaPipe Tasks Vision (`ImageSegmenter` `selfie_multiclass_256x256` + multi-scale `FaceLandmarker` / `FaceDetector` + Sobel edge-guided filter) to trace human body silhouettes and multi-person face contours.
- **Lossless Mask Serialization**: The binary pixel mask ($\{0, 1\}^{W \times H}$) is compressed losslessly using alternating run-length encoding (LEB128 varints) and stored inside the `msBx` chunk so decryption restores the exact mask without re-running AI detection.
- **Security Consideration**:
  - Storing an unencrypted mask (`mask_encoding = 1`) allows the Decrypt page to preview the region metadata before the key is entered, and the unencrypted background pixels in selective encryption naturally reveal the outline of the encrypted region.
  - Enabling **Optional Mask Privacy Protection (`mask_encoding = 2`)** XOR-encrypts the RLE mask bytes inside `msBx` using the `"MASK_PROTECT_STREAM"` keystream so metadata inspection alone cannot extract the mask without the correct key.

---

## 5. Current Limitations

- **Lossy Re-compression by Third-Party Messaging Apps**: If a user sends `encrypted_photo.png` through a messaging app in "standard photo mode" (which converts PNG to lossy JPEG and strips ancillary PNG chunks), both the encrypted pixel values and the `msBx` chunk will be destroyed. When transferring across devices via messaging apps, always send as an **uncompressed Document / File** or transfer via AirDrop, email attachment, cloud drive, or USB.
- **Browser Canvas Memory Ceiling**: Images up to **4K UHD ($3840 \times 2160$, ~8.3 MP)** process comfortably on desktop and mobile browsers. Extremely large images (> 24 MP) may hit Mobile Safari's per-canvas memory limit.

---

## 6. Local Development & Automated Testing

### Run Locally
```powershell
python -m http.server 3000
```
Then open `http://localhost:3000` in Chrome, Edge, Firefox, or Safari.

### Run Automated Test Suite
```powershell
node tests/test_encrypted_png.mjs
```
This executes 9 end-to-end test suites verifying PNG signature & chunk validity, lossless pixel round-trips (`0` different pixels), RGB & Grayscale recovery, $k \in \{1..8\}$, fresh random salts, AI body/face mask serialization (plain & protected), image-key mode, tamper/wrong-key rejection, and legacy `.msbx` compatibility.

---

## 7. Cloudflare Pages Deployment Instructions

1. Push the repository to GitHub (`https://github.com/xunxun24/FYP_MSB_1_video.git`):
   ```powershell
   git add index.html style.css js/bit-engine.js js/app.js _headers tests/test_encrypted_png.mjs README.md
   git commit -m "Implement Self-Describing Encrypted PNG with embedded msBx metadata"
   git push origin main
   ```
2. In the **Cloudflare Dashboard** -> **Workers & Pages** -> **Pages** -> **Connect to Git**:
   - **Repository**: `xunxun24/FYP_MSB_1_video`
   - **Framework preset**: `None`
   - **Build command**: *(leave empty)*
   - **Build output directory**: `/`
3. Or deploy directly from the terminal using Wrangler:
   ```powershell
   npx wrangler pages deploy . --project-name bitshield-fyp
   ```
4. `_headers` is included in the repository root to set `X-Content-Type-Options: nosniff` and proper content headers on Cloudflare Pages.

