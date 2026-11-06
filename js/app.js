/**
 * FYP Application Controller - UI Events, Neural Body & Face Contour Segmentation,
 * Canvas Overlay Visualization, Exact Shape MSB Encryption, & 8-Bit Inspector
 */

document.addEventListener('DOMContentLoaded', () => {

  // State Management
  const state = {
    encImage: null,
    encMode: 'msb',
    encScope: 'full', // 'full' | 'person' | 'face' | 'custom'
    decMeta: null,    // Auto-detected encryption metadata for the image loaded in the Decrypt tab
    lastEncryptedMeta: null, // Metadata (scope, exact mask/ROI, key type) of the last encryption
    segToken: 0,      // Guards against overlapping AI segmentation runs
    bodyMask: null,   // Uint8Array(width * height)
    faceMask: null,   // Uint8Array(width * height)
    allMask: null,    // Uint8Array(width * height)
    customRoi: { x: 0, y: 0, width: 0, height: 0, active: false },
    isDraggingRoi: false,
    dragStart: { x: 0, y: 0 },
    detectedBodyStats: { pixelCount: 0, coveragePct: 0, topX: 0, topY: 0 },
    detectedFaceStats: { pixelCount: 0, coveragePct: 0, topX: 0, topY: 0 },
    isAiDetecting: false,
    aiModelsLoaded: false,
    encFileName: 'image',
    decFileName: 'restored_photo',
    decImage: null,
    decMsbxBytes: null,
    decMsbxHeader: null,
    decMode: 'msb',
    lastOriginalImageData: null,
    lastEncryptedImageData: null,
    lastEncryptedMSBX: null,
    lastEncryptedHeader: null,
    lastDecryptedImageData: null,
    lastEncryptedScope: 'full',
    lastEncryptedPassword: '',
    lastEncryptedKeyType: 'text',
    lastEncryptedKeyImage: null,
    lastEncryptedRoi: null,
    encKeyType: 'text',
    encKeyImage: null,
    decKeyType: 'text',
    decKeyImage: null,
    stegoCover: null,
    stegoStego: null
  };

  // Cache DOM Elements
  const DOM = {
    tabs: document.querySelectorAll('.nav-tab'),
    tabPanes: document.querySelectorAll('.tab-pane'),
    
    // Encrypt Tab
    encDropZone: document.getElementById('enc-drop-zone'),
    encFileInput: document.getElementById('enc-file-input'),
    aiStatusBadge: document.getElementById('ai-status-badge'),
    btnScopeFull: document.getElementById('btn-scope-full'),
    btnScopePerson: document.getElementById('btn-scope-person'),
    btnScopeFace: document.getElementById('btn-scope-face'),
    btnScopeCustom: document.getElementById('btn-scope-custom'),
    subPersonCount: document.getElementById('sub-person-count'),
    subFaceCount: document.getElementById('sub-face-count'),
    subCustomCount: document.getElementById('sub-custom-count'),
    encRoiHelper: document.getElementById('enc-roi-helper'),
    roiStatusText: document.getElementById('roi-status-text'),
    btnClearRoi: document.getElementById('btn-clear-roi'),
    aiDetectionBanner: document.getElementById('ai-detection-banner'),
    aiDetectionText: document.getElementById('ai-detection-text'),
    btnEncKeyTypeText: document.getElementById('btn-enc-keytype-text'),
    btnEncKeyTypeImage: document.getElementById('btn-enc-keytype-image'),
    encTextKeyBox: document.getElementById('enc-text-key-box'),
    encImgKeyBox: document.getElementById('enc-img-key-box'),
    encKeyImageDropzone: document.getElementById('enc-key-image-dropzone'),
    encKeyImageInput: document.getElementById('enc-key-image-input'),
    encKeyImgPrompt: document.getElementById('enc-key-img-prompt'),
    encKeyImgCard: document.getElementById('enc-key-img-card'),
    encKeyImgThumb: document.getElementById('enc-key-img-thumb'),
    encKeyImgName: document.getElementById('enc-key-img-name'),
    encKeyImgMeta: document.getElementById('enc-key-img-meta'),
    encKeyImgHash: document.getElementById('enc-key-img-hash'),
    btnEncChangeKeyImg: document.getElementById('btn-enc-change-key-img'),
    btnEncRemoveKeyImg: document.getElementById('btn-enc-remove-key-img'),
    encPwdBadge: document.getElementById('enc-pwd-badge'),
    encImgBadge: document.getElementById('enc-img-badge'),
    encPassword: document.getElementById('enc-password'),
    toggleEncPwd: document.getElementById('toggle-enc-pwd'),
    btnProcessEncrypt: document.getElementById('btn-process-encrypt'),
    canvasEncOrig: document.getElementById('canvas-enc-orig'),
    canvasEncResult: document.getElementById('canvas-enc-result'),
    phEncOrig: document.getElementById('ph-enc-orig'),
    phEncResult: document.getElementById('ph-enc-result'),
    encMetrics: document.getElementById('enc-metrics'),
    valEncMse: document.getElementById('val-enc-mse'),
    valEncPsnr: document.getElementById('val-enc-psnr'),
    valEncSwapped: document.getElementById('val-enc-swapped'),
    encKSelect: document.getElementById('enc-k-select'),
    btnDownloadMsbx: document.getElementById('btn-download-msbx'),
    encMsbxInfo: document.getElementById('enc-msbx-info'),
    encExportFormat: document.getElementById('enc-export-format'),
    encQuality: document.getElementById('enc-quality'),
    jpegQualityGroup: document.getElementById('jpeg-quality-group'),
    qualityVal: document.getElementById('quality-val'),
    btnDownloadEncrypted: document.getElementById('btn-download-encrypted'),

    // Decrypt Tab
    decDropZone: document.getElementById('dec-drop-zone'),
    decFileInput: document.getElementById('dec-file-input'),
    btnUseEncryptedFromEnc: document.getElementById('btn-use-encrypted-from-enc'),
    decErrorBanner: document.getElementById('dec-error-banner'),
    decErrorTitle: document.getElementById('dec-error-title'),
    decErrorText: document.getElementById('dec-error-text'),
    decMsbxMeta: document.getElementById('dec-msbx-meta'),
    decScopeInfo: document.getElementById('dec-scope-info'),
    decScopeInfoText: document.getElementById('dec-scope-info-text'),
    decTextKeyBox: document.getElementById('dec-text-key-box'),
    decImgKeyBox: document.getElementById('dec-img-key-box'),
    decKeyImageDropzone: document.getElementById('dec-key-image-dropzone'),
    decKeyImageInput: document.getElementById('dec-key-image-input'),
    decKeyImgPrompt: document.getElementById('dec-key-img-prompt'),
    decKeyImgCard: document.getElementById('dec-key-img-card'),
    decKeyImgThumb: document.getElementById('dec-key-img-thumb'),
    decKeyImgName: document.getElementById('dec-key-img-name'),
    decKeyImgMeta: document.getElementById('dec-key-img-meta'),
    decKeyImgHash: document.getElementById('dec-key-img-hash'),
    btnDecChangeKeyImg: document.getElementById('btn-dec-change-key-img'),
    btnDecRemoveKeyImg: document.getElementById('btn-dec-remove-key-img'),
    decPwdBadge: document.getElementById('dec-pwd-badge'),
    decImgBadge: document.getElementById('dec-img-badge'),
    decPassword: document.getElementById('dec-password'),
    toggleDecPwd: document.getElementById('toggle-dec-pwd'),
    btnProcessDecrypt: document.getElementById('btn-process-decrypt'),
    canvasDecOrig: document.getElementById('canvas-dec-orig'),
    phDecOrig: document.getElementById('ph-dec-orig'),
    canvasDecResult: document.getElementById('canvas-dec-result'),
    phDecResult: document.getElementById('ph-dec-result'),
    decMetrics: document.getElementById('dec-metrics'),
    valDecMse: document.getElementById('val-dec-mse'),
    valDecPsnr: document.getElementById('val-dec-psnr'),
    valDecSwapped: document.getElementById('val-dec-swapped'),
    decFidelityCard: document.getElementById('dec-fidelity-card'),
    btnDownloadRestored: document.getElementById('btn-download-restored'),
    decExportFormat: document.getElementById('dec-export-format'),

    // Stego Tab
    stegoTypeBtns: document.querySelectorAll('.stego-type-btn'),
    stegoEmbedSub: document.getElementById('stego-embed-sub'),
    stegoExtractSub: document.getElementById('stego-extract-sub'),
    stegoCoverZone: document.getElementById('stego-cover-zone'),
    stegoCoverInput: document.getElementById('stego-cover-input'),
    stegoSecretText: document.getElementById('stego-secret-text'),
    stegoPwd: document.getElementById('stego-pwd'),
    btnStegoEmbed: document.getElementById('btn-stego-embed'),
    stegoStegoZone: document.getElementById('stego-stego-zone'),
    stegoStegoInput: document.getElementById('stego-stego-input'),
    stegoExtPwd: document.getElementById('stego-ext-pwd'),
    btnStegoExtract: document.getElementById('btn-stego-extract'),
    canvasStegoResult: document.getElementById('canvas-stego-result'),
    phStegoResult: document.getElementById('ph-stego-result'),
    extractedPayloadDisplay: document.getElementById('extracted-payload-display'),
    btnDownloadStego: document.getElementById('btn-download-stego')
  };

  /* ==========================================================================
     Tab Navigation Setup
     ========================================================================== */
  DOM.tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      DOM.tabs.forEach(t => t.classList.remove('active'));
      DOM.tabPanes.forEach(p => p.classList.remove('active'));
      
      tab.classList.add('active');
      const targetPane = document.getElementById(tab.getAttribute('data-tab'));
      if (targetPane) targetPane.classList.add('active');

      if (tab.getAttribute('data-tab') === 'decrypt-tab') {
        updateDecButtonState();
      }
    });
  });

  // Password Visibility Toggles
  function setupPwdToggle(btn, input) {
    if (!btn || !input) return;
    btn.addEventListener('click', () => {
      const isPwd = input.type === 'password';
      input.type = isPwd ? 'text' : 'password';
      btn.innerHTML = isPwd ? '<i class="fa-solid fa-eye-slash"></i>' : '<i class="fa-solid fa-eye"></i>';
    });
  }
  setupPwdToggle(DOM.toggleEncPwd, DOM.encPassword);
  setupPwdToggle(DOM.toggleDecPwd, DOM.decPassword);

  /* ==========================================================================
     Key Image / Visual Cryptography Key Management
     ========================================================================== */
  /* ==========================================================================
     Key Image / Visual Cryptography Key Management & Validation
     ========================================================================== */
  function updateEncButtonState() {
    if (!DOM.btnProcessEncrypt) return;
    if (!state.encImage) {
      DOM.btnProcessEncrypt.disabled = true;
      DOM.btnProcessEncrypt.classList.remove('btn-key-needed');
      DOM.btnProcessEncrypt.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles"></i> Execute 3-Stage Encryption';
      return;
    }

    if (state.encKeyType === 'image' && !state.encKeyImage) {
      DOM.btnProcessEncrypt.disabled = false;
      DOM.btnProcessEncrypt.classList.add('btn-key-needed');
      DOM.btnProcessEncrypt.innerHTML = '<i class="fa-solid fa-image"></i> Please Upload Key Image First';
      return;
    }

    // Update password badge dynamically
    if (state.encKeyType === 'text' && DOM.encPwdBadge) {
      const hasPwd = DOM.encPassword && DOM.encPassword.value.trim().length > 0;
      if (hasPwd) {
        DOM.encPwdBadge.className = 'key-req-badge ready';
        DOM.encPwdBadge.innerHTML = '<i class="fa-solid fa-circle-check"></i> Password Set';
      } else {
        DOM.encPwdBadge.className = 'key-req-badge';
        DOM.encPwdBadge.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> Password Required';
      }
    }

    DOM.btnProcessEncrypt.disabled = false;
    DOM.btnProcessEncrypt.classList.remove('btn-key-needed');
    DOM.btnProcessEncrypt.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles"></i> Execute 3-Stage Encryption';
  }

  function updateDecButtonState() {
    if (!DOM.btnProcessDecrypt) return;

    const hasPwd = !!(DOM.decPassword && DOM.decPassword.value.trim().length > 0);
    const hasImgKey = !!state.decKeyImage;

    // Password badge: either option satisfies the key requirement
    if (DOM.decPwdBadge) {
      if (hasPwd) {
        DOM.decPwdBadge.className = 'key-req-badge ready';
        DOM.decPwdBadge.innerHTML = '<i class="fa-solid fa-circle-check"></i> Password Set';
      } else if (hasImgKey) {
        DOM.decPwdBadge.className = 'key-req-badge optional';
        DOM.decPwdBadge.innerHTML = '<i class="fa-solid fa-minus"></i> Not needed (key image loaded)';
      } else {
        DOM.decPwdBadge.className = 'key-req-badge';
        DOM.decPwdBadge.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> Password or Key Image Required';
      }
    }
    if (DOM.decImgBadge) {
      if (hasImgKey) {
        DOM.decImgBadge.className = 'key-req-badge ready';
        DOM.decImgBadge.innerHTML = '<i class="fa-solid fa-circle-check"></i> Key Image Loaded';
      } else {
        DOM.decImgBadge.className = 'key-req-badge optional';
        DOM.decImgBadge.innerHTML = '<i class="fa-solid fa-circle-info"></i> Only if encrypted with an image key';
      }
    }

    if (!state.decImage && !state.decMsbxBytes) {
      DOM.btnProcessDecrypt.disabled = true;
      DOM.btnProcessDecrypt.classList.remove('btn-key-needed');
      DOM.btnProcessDecrypt.innerHTML = '<i class="fa-solid fa-rotate-left"></i> Restore Original Image';
      return;
    }

    if (!hasPwd && !hasImgKey) {
      DOM.btnProcessDecrypt.disabled = false;
      DOM.btnProcessDecrypt.classList.add('btn-key-needed');
      DOM.btnProcessDecrypt.innerHTML = '<i class="fa-solid fa-key"></i> Enter Password or Upload Key Image';
      return;
    }

    DOM.btnProcessDecrypt.disabled = false;
    DOM.btnProcessDecrypt.classList.remove('btn-key-needed');
    DOM.btnProcessDecrypt.innerHTML = '<i class="fa-solid fa-rotate-left"></i> Restore Original Image';
  }

  function initKeyImageSystem() {
    // Encrypt Tab Key Type Toggle (Text Password vs Image as Key)
    if (DOM.btnEncKeyTypeText && DOM.btnEncKeyTypeImage) {
      DOM.btnEncKeyTypeText.addEventListener('click', () => {
        state.encKeyType = 'text';
        DOM.btnEncKeyTypeText.classList.add('active');
        DOM.btnEncKeyTypeImage.classList.remove('active');
        const rText = DOM.btnEncKeyTypeText.querySelector('.key-card-radio');
        const rImg = DOM.btnEncKeyTypeImage.querySelector('.key-card-radio');
        if (rText) rText.innerHTML = '<i class="fa-solid fa-circle-dot"></i>';
        if (rImg) rImg.innerHTML = '<i class="fa-regular fa-circle"></i>';
        if (DOM.encTextKeyBox) DOM.encTextKeyBox.style.display = 'block';
        if (DOM.encImgKeyBox) DOM.encImgKeyBox.style.display = 'none';
        if (DOM.encPassword) DOM.encPassword.focus();
        updateEncButtonState();
      });

      DOM.btnEncKeyTypeImage.addEventListener('click', () => {
        const wasAlreadyImage = (state.encKeyType === 'image');
        state.encKeyType = 'image';
        DOM.btnEncKeyTypeImage.classList.add('active');
        DOM.btnEncKeyTypeText.classList.remove('active');
        const rText = DOM.btnEncKeyTypeText.querySelector('.key-card-radio');
        const rImg = DOM.btnEncKeyTypeImage.querySelector('.key-card-radio');
        if (rImg) rImg.innerHTML = '<i class="fa-solid fa-circle-dot"></i>';
        if (rText) rText.innerHTML = '<i class="fa-regular fa-circle"></i>';
        if (DOM.encTextKeyBox) DOM.encTextKeyBox.style.display = 'none';
        if (DOM.encImgKeyBox) DOM.encImgKeyBox.style.display = 'block';
        updateEncButtonState();

        // Immediately prompt user to choose an image file
        if (!state.encKeyImage || wasAlreadyImage) {
          if (DOM.encKeyImageInput) DOM.encKeyImageInput.click();
        }
      });
    }

    // Decrypt Tab: no key-source toggle. The password field and key-image upload are both
    // shown, and the key type is inferred from whichever one the user provides.

    // Password input listeners for dynamic badge feedback
    if (DOM.encPassword) {
      DOM.encPassword.addEventListener('input', () => updateEncButtonState());
    }
    if (DOM.decPassword) {
      DOM.decPassword.addEventListener('input', () => updateDecButtonState());
    }

    // Helper: Process Key Image File
    async function handleKeyImageFile(file, isEncrypt) {
      if (!file) return;
      const isImg = (file.type && file.type.startsWith('image/')) ||
        /\.(png|jpe?g|webp|bmp|gif|tiff?|svg)$/i.test(file.name);
      if (!isImg) {
        alert(`"${file.name}" is not a recognized image file. Please upload an image (PNG, JPG, BMP, WEBP).`);
        return;
      }

      try {
        const keyData = await BitEngine.hashKeyImage(file);
        const url = URL.createObjectURL(file);
        const img = new Image();
        img.onload = () => {
          const info = {
            file,
            url,
            hex: keyData.hex,
            displayHash: keyData.displayHash,
            fullHash: keyData.fullHash,
            name: file.name,
            sizeKb: (file.size / 1024).toFixed(1),
            width: img.width,
            height: img.height
          };

          if (isEncrypt) {
            state.encKeyImage = info;
            if (DOM.encKeyImgThumb) DOM.encKeyImgThumb.src = url;
            if (DOM.encKeyImgName) DOM.encKeyImgName.textContent = info.name;
            if (DOM.encKeyImgMeta) DOM.encKeyImgMeta.textContent = `${info.width} × ${info.height} px • ${info.sizeKb} KB`;
            if (DOM.encKeyImgHash) DOM.encKeyImgHash.innerHTML = `<i class="fa-solid fa-fingerprint"></i> SHA-256: <span>${info.displayHash}</span>`;
            if (DOM.encKeyImgPrompt) DOM.encKeyImgPrompt.style.display = 'none';
            if (DOM.encKeyImgCard) DOM.encKeyImgCard.style.display = 'flex';
            if (DOM.encImgBadge) {
              DOM.encImgBadge.className = 'key-req-badge ready';
              DOM.encImgBadge.innerHTML = '<i class="fa-solid fa-circle-check"></i> Key Image Loaded';
            }
            updateEncButtonState();
          } else {
            state.decKeyImage = info;
            if (DOM.decKeyImgThumb) DOM.decKeyImgThumb.src = url;
            if (DOM.decKeyImgName) DOM.decKeyImgName.textContent = info.name;
            if (DOM.decKeyImgMeta) DOM.decKeyImgMeta.textContent = `${info.width} × ${info.height} px • ${info.sizeKb} KB`;
            if (DOM.decKeyImgHash) DOM.decKeyImgHash.innerHTML = `<i class="fa-solid fa-fingerprint"></i> SHA-256: <span>${info.displayHash}</span>`;
            if (DOM.decKeyImgPrompt) DOM.decKeyImgPrompt.style.display = 'none';
            if (DOM.decKeyImgCard) DOM.decKeyImgCard.style.display = 'flex';
            updateDecButtonState();
          }
        };
        img.src = url;
      } catch (err) {
        alert("Failed to compute key image digest: " + err.message);
      }
    }

    // Encrypt Key Image File Input & Drag/Drop
    if (DOM.encKeyImageInput) {
      DOM.encKeyImageInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files[0]) {
          handleKeyImageFile(e.target.files[0], true);
        }
        e.target.value = ''; // Always clear so choosing the same file re-triggers change
      });
    }

    if (DOM.encKeyImageDropzone) {
      DOM.encKeyImageDropzone.addEventListener('click', (e) => {
        // Do not trigger file input if user clicked Change or Remove buttons inside card
        if (e.target.closest('#btn-enc-remove-key-img') || e.target.closest('#btn-enc-change-key-img')) {
          return;
        }
        if (DOM.encKeyImageInput) DOM.encKeyImageInput.click();
      });
      DOM.encKeyImageDropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        DOM.encKeyImageDropzone.classList.add('dragover');
      });
      DOM.encKeyImageDropzone.addEventListener('dragleave', () => {
        DOM.encKeyImageDropzone.classList.remove('dragover');
      });
      DOM.encKeyImageDropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        DOM.encKeyImageDropzone.classList.remove('dragover');
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
          handleKeyImageFile(e.dataTransfer.files[0], true);
        }
      });
    }

    if (DOM.btnEncChangeKeyImg) {
      DOM.btnEncChangeKeyImg.addEventListener('click', (e) => {
        e.stopPropagation();
        if (DOM.encKeyImageInput) DOM.encKeyImageInput.click();
      });
    }

    if (DOM.btnEncRemoveKeyImg) {
      DOM.btnEncRemoveKeyImg.addEventListener('click', (e) => {
        e.stopPropagation();
        state.encKeyImage = null;
        if (DOM.encKeyImageInput) DOM.encKeyImageInput.value = '';
        if (DOM.encKeyImgPrompt) DOM.encKeyImgPrompt.style.display = 'block';
        if (DOM.encKeyImgCard) DOM.encKeyImgCard.style.display = 'none';
        if (DOM.encImgBadge) {
          DOM.encImgBadge.className = 'key-req-badge';
          DOM.encImgBadge.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> Key Image Required';
        }
        updateEncButtonState();
      });
    }

    // Decrypt Key Image File Input & Drag/Drop
    if (DOM.decKeyImageInput) {
      DOM.decKeyImageInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files[0]) {
          handleKeyImageFile(e.target.files[0], false);
        }
        e.target.value = ''; // Always clear so choosing the same file re-triggers change
      });
    }

    if (DOM.decKeyImageDropzone) {
      DOM.decKeyImageDropzone.addEventListener('click', (e) => {
        // Do not trigger file input if user clicked Change or Remove buttons inside card
        if (e.target.closest('#btn-dec-remove-key-img') || e.target.closest('#btn-dec-change-key-img')) {
          return;
        }
        if (DOM.decKeyImageInput) DOM.decKeyImageInput.click();
      });
      DOM.decKeyImageDropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        DOM.decKeyImageDropzone.classList.add('dragover');
      });
      DOM.decKeyImageDropzone.addEventListener('dragleave', () => {
        DOM.decKeyImageDropzone.classList.remove('dragover');
      });
      DOM.decKeyImageDropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        DOM.decKeyImageDropzone.classList.remove('dragover');
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
          handleKeyImageFile(e.dataTransfer.files[0], false);
        }
      });
    }

    if (DOM.btnDecChangeKeyImg) {
      DOM.btnDecChangeKeyImg.addEventListener('click', (e) => {
        e.stopPropagation();
        if (DOM.decKeyImageInput) DOM.decKeyImageInput.click();
      });
    }

    if (DOM.btnDecRemoveKeyImg) {
      DOM.btnDecRemoveKeyImg.addEventListener('click', (e) => {
        e.stopPropagation();
        state.decKeyImage = null;
        if (DOM.decKeyImageInput) DOM.decKeyImageInput.value = '';
        if (DOM.decKeyImgPrompt) DOM.decKeyImgPrompt.style.display = 'block';
        if (DOM.decKeyImgCard) DOM.decKeyImgCard.style.display = 'none';
        updateDecButtonState();
      });
    }
  }

  initKeyImageSystem();
  updateEncButtonState();
  updateDecButtonState();

  /* ==========================================================================
     Helper Utilities
     ========================================================================== */
  function loadImage(file, callback) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new Image();
      img.onload = () => callback(img);
      img.src = e.target.result;
    };
    reader.readAsDataURL(file);
  }

  function renderToCanvas(img, canvas, placeholder) {
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    canvas.style.display = 'block';
    canvas.width = img.width;
    canvas.height = img.height;
    ctx.drawImage(img, 0, 0);
    if (placeholder) placeholder.style.display = 'none';
  }

  function clearCanvasAndShowPlaceholder(canvas, placeholder) {
    if (canvas) {
      const ctx = canvas.getContext('2d');
      if (ctx) ctx.clearRect(0, 0, canvas.width, canvas.height);
      canvas.width = 0;
      canvas.height = 0;
      canvas.style.display = 'none';
    }
    if (placeholder) {
      placeholder.style.display = 'flex';
    }
  }

  function clearEncryptedResultView() {
    state.lastEncryptedImageData = null;
    state.lastEncryptedMSBX = null;
    state.lastEncryptedHeader = null;
    clearCanvasAndShowPlaceholder(DOM.canvasEncResult, DOM.phEncResult);
    if (DOM.encMetrics) DOM.encMetrics.style.display = 'none';
    if (DOM.valEncMse) DOM.valEncMse.textContent = '0.00';
    if (DOM.valEncPsnr) DOM.valEncPsnr.textContent = '∞ dB';
    if (DOM.valEncSwapped) DOM.valEncSwapped.textContent = '0';
    if (DOM.btnDownloadMsbx) DOM.btnDownloadMsbx.disabled = true;
    if (DOM.encMsbxInfo) {
      DOM.encMsbxInfo.style.display = 'none';
      DOM.encMsbxInfo.innerHTML = '';
    }
    if (DOM.btnDownloadEncrypted) DOM.btnDownloadEncrypted.disabled = true;

    // Reset preview tabs to Side-by-Side if currently toggled to Result Only
    const prevTabs = document.querySelectorAll('.prev-tab');
    if (prevTabs.length > 0) {
      prevTabs.forEach(b => {
        if (b.getAttribute('data-view') === 'split') b.classList.add('active');
        else b.classList.remove('active');
      });
      const comp = document.getElementById('enc-comparison');
      if (comp) {
        const origBox = comp.querySelector('.comp-box:first-child');
        const resBox = comp.querySelector('.comp-box:last-child');
        if (origBox) origBox.style.display = 'flex';
        if (resBox) resBox.classList.remove('full-width');
      }
    }
  }

  function clearDecryptedResultView() {
    state.lastDecryptedImageData = null;
    clearCanvasAndShowPlaceholder(DOM.canvasDecResult, DOM.phDecResult);
    if (DOM.decMetrics) DOM.decMetrics.style.display = 'none';
    if (DOM.decFidelityCard) DOM.decFidelityCard.style.display = 'none';
    if (DOM.valDecMse) DOM.valDecMse.textContent = '0.00';
    if (DOM.valDecPsnr) DOM.valDecPsnr.textContent = '∞ dB';
    if (DOM.valDecSwapped) DOM.valDecSwapped.textContent = '0';
    if (DOM.btnDownloadRestored) DOM.btnDownloadRestored.disabled = true;
  }

  function showDecError(title, message) {
    if (!DOM.decErrorBanner) return;
    if (DOM.decErrorTitle) DOM.decErrorTitle.textContent = title || 'Decryption / Verification Error';
    if (DOM.decErrorText) DOM.decErrorText.textContent = message || 'Failed to verify or decrypt the container.';
    DOM.decErrorBanner.style.display = 'flex';
  }

  function hideDecError() {
    if (!DOM.decErrorBanner) return;
    DOM.decErrorBanner.style.display = 'none';
    if (DOM.decErrorText) DOM.decErrorText.textContent = '';
  }

  function renderMsbxHeaderCard(el, header, byteLength, titleLabel) {
    if (!el || !header) return;
    const kb = (byteLength / 1024).toFixed(1);
    const scopeName = SCOPE_LABELS[header.scope] || 'Entire Image';
    el.innerHTML = `
      <div class="msbx-meta-header">
        <span><i class="fa-solid fa-file-shield"></i> ${titleLabel || 'Portable .msbx Container (68-Byte Fixed Header)'}</span>
        <span>${kb} KB</span>
      </div>
      <div class="msbx-meta-grid">
        <div class="msbx-meta-item">
          <span class="msbx-meta-label">Magic / Version</span>
          <span class="msbx-meta-val">${header.magic} • v${header.version}</span>
        </div>
        <div class="msbx-meta-item">
          <span class="msbx-meta-label">Mode / Channels</span>
          <span class="msbx-meta-val">${header.modeLabel} (mode=${header.imageMode})</span>
        </div>
        <div class="msbx-meta-item">
          <span class="msbx-meta-label">Stage 3 k-MSB</span>
          <span class="msbx-meta-val">k = ${header.k} bit${header.k > 1 ? 's' : ''}</span>
        </div>
        <div class="msbx-meta-item">
          <span class="msbx-meta-label">Dimensions</span>
          <span class="msbx-meta-val">${header.width} × ${header.height} px</span>
        </div>
        <div class="msbx-meta-item">
          <span class="msbx-meta-label">KDF Iterations</span>
          <span class="msbx-meta-val">${header.iterations.toLocaleString()} SHA-256</span>
        </div>
        <div class="msbx-meta-item">
          <span class="msbx-meta-label">Encrypted Scope</span>
          <span class="msbx-meta-val">${scopeName}</span>
        </div>
        <div class="msbx-meta-item full">
          <span class="msbx-meta-label">16-Byte Random Salt (Hex)</span>
          <span class="msbx-meta-val">${header.saltHex}</span>
        </div>
        <div class="msbx-meta-item full">
          <span class="msbx-meta-label">32-Byte SHA-256 Verification Tag (Hex)</span>
          <span class="msbx-meta-val">${header.tagHex}</span>
        </div>
      </div>
    `;
    el.style.display = 'block';
  }

  // Refresh & Reset Encryption Key Source Selection & Inputs
  function refreshEncKeySourceUI() {
    state.encKeyType = 'text';
    state.encKeyImage = null;

    // Clear password input & reset status badge
    if (DOM.encPassword) {
      DOM.encPassword.value = '';
      DOM.encPassword.type = 'password';
    }
    if (DOM.toggleEncPwd) {
      DOM.toggleEncPwd.innerHTML = '<i class="fa-solid fa-eye"></i>';
    }
    if (DOM.encPwdBadge) {
      DOM.encPwdBadge.className = 'key-req-badge';
      DOM.encPwdBadge.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> Password Required';
    }

    // Reset image key upload input, prompt & card
    if (DOM.encKeyImageInput) DOM.encKeyImageInput.value = '';
    if (DOM.encKeyImgPrompt) DOM.encKeyImgPrompt.style.display = 'block';
    if (DOM.encKeyImgCard) DOM.encKeyImgCard.style.display = 'none';
    if (DOM.encKeyImgThumb) DOM.encKeyImgThumb.src = '';
    if (DOM.encKeyImgName) DOM.encKeyImgName.textContent = '';
    if (DOM.encKeyImgMeta) DOM.encKeyImgMeta.textContent = '';
    if (DOM.encKeyImgHash) DOM.encKeyImgHash.innerHTML = '<i class="fa-solid fa-fingerprint"></i> SHA-256: <span>Calculating...</span>';
    if (DOM.encImgBadge) {
      DOM.encImgBadge.className = 'key-req-badge';
      DOM.encImgBadge.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> Key Image Required';
    }

    // Reset selector buttons to Text Password active
    if (DOM.btnEncKeyTypeText) {
      DOM.btnEncKeyTypeText.classList.add('active');
      const rText = DOM.btnEncKeyTypeText.querySelector('.key-card-radio');
      if (rText) rText.innerHTML = '<i class="fa-solid fa-circle-dot"></i>';
    }
    if (DOM.btnEncKeyTypeImage) {
      DOM.btnEncKeyTypeImage.classList.remove('active');
      const rImg = DOM.btnEncKeyTypeImage.querySelector('.key-card-radio');
      if (rImg) rImg.innerHTML = '<i class="fa-regular fa-circle"></i>';
    }

    // Show Text Password box, hide Image Key box
    if (DOM.encTextKeyBox) DOM.encTextKeyBox.style.display = 'block';
    if (DOM.encImgKeyBox) DOM.encImgKeyBox.style.display = 'none';

    updateEncButtonState();
  }

  // Refresh & Reset Decryption Key Inputs (password field + key image upload)
  function refreshDecKeySourceUI() {
    state.decKeyImage = null;

    // Clear password input
    if (DOM.decPassword) {
      DOM.decPassword.value = '';
      DOM.decPassword.type = 'password';
    }
    if (DOM.toggleDecPwd) {
      DOM.toggleDecPwd.innerHTML = '<i class="fa-solid fa-eye"></i>';
    }

    // Reset image key upload input, prompt & card
    if (DOM.decKeyImageInput) DOM.decKeyImageInput.value = '';
    if (DOM.decKeyImgPrompt) DOM.decKeyImgPrompt.style.display = 'block';
    if (DOM.decKeyImgCard) DOM.decKeyImgCard.style.display = 'none';
    if (DOM.decKeyImgThumb) DOM.decKeyImgThumb.src = '';
    if (DOM.decKeyImgName) DOM.decKeyImgName.textContent = '';
    if (DOM.decKeyImgMeta) DOM.decKeyImgMeta.textContent = '';
    if (DOM.decKeyImgHash) DOM.decKeyImgHash.innerHTML = '<i class="fa-solid fa-fingerprint"></i> SHA-256: <span>Calculating...</span>';

    // Badges are recomputed from the current inputs
    updateDecButtonState();
  }

  /* ==========================================================================
     AI Human Segmentation with Multi-Face Detection & Edge-Detection Refinement
     --------------------------------------------------------------------------
     1. MediaPipe Selfie Multiclass Segmenter (full frame + high-res tiles &
        per-face crops) -> per-pixel confidence for background (0), hair (1),
        body-skin (2), face-skin (3), clothes (4), and accessories (5).
     2. Multi-Scale Face Detection (MediaPipe FaceLandmarker 478-point mesh +
        BlazeFace detector + tiled zoom passes + face-skin cluster proposals)
        -> reliably detects all faces in group photos (4, 6, 10+ faces).
     3. True Edge-Detection Boundary Refinement:
        - Multi-channel Sobel colour gradient detector
        - Local Foreground / Background RGB colour affinity in a boundary trimap
        - Edge-preserving Colour Guided Filter (He et al., 2013) that snaps the
          contour directly onto the photo's real colour edges (hairline, jawline,
          cheeks, shoulders, arms, clothing).
     ========================================================================== */
  const MP_VERSION = '0.10.14';
  const MP_BUNDLE_URL = `https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@${MP_VERSION}/vision_bundle.mjs`;
  const MP_WASM_URL = `https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@${MP_VERSION}/wasm`;
  const MP_SEGMENTER_MODEL = 'https://storage.googleapis.com/mediapipe-models/image_segmenter/selfie_multiclass_256x256/float32/latest/selfie_multiclass_256x256.tflite';
  const MP_FACE_MODEL = 'https://storage.googleapis.com/mediapipe-models/face_landmarker/face_landmarker/float16/1/face_landmarker.task';
  const MP_FACE_DETECTOR_MODEL = 'https://storage.googleapis.com/mediapipe-models/face_detector/blaze_face_short_range/float16/1/blaze_face_short_range.tflite';

  // Working resolution long side (px) for AI + edge detection.
  const SEG_WORK_MAX = 1280;

  // Ordered MediaPipe FaceMesh silhouette (face-oval) landmark indices (clockwise from top-center 10).
  const FACE_OVAL_IDX = [
    10, 338, 297, 332, 284, 251, 389, 356, 454, 323, 361, 288, 397, 365, 379, 378,
    400, 377, 152, 148, 176, 149, 150, 136, 172, 58, 132, 93, 234, 127, 162, 21,
    54, 103, 67, 109
  ];

  // Forehead / upper-temple indices in FACE_OVAL_IDX (expanded slightly upward so hairlines can be edge-traced).
  const FOREHEAD_SET = new Set([10, 338, 297, 332, 284, 251, 389, 109, 67, 103, 54, 21, 162]);

  let imageSegmenter = null;
  let faceLandmarker = null;
  let faceDetector = null;

  function setAiBadge(cls, html) {
    if (!DOM.aiStatusBadge) return;
    DOM.aiStatusBadge.className = 'ai-status-badge' + (cls ? ' ' + cls : '');
    DOM.aiStatusBadge.innerHTML = html;
  }

  async function initAIModels() {
    try {
      const vision = await import(MP_BUNDLE_URL);
      const fileset = await vision.FilesetResolver.forVisionTasks(MP_WASM_URL);

      imageSegmenter = await vision.ImageSegmenter.createFromOptions(fileset, {
        baseOptions: { modelAssetPath: MP_SEGMENTER_MODEL, delegate: 'CPU' },
        runningMode: 'IMAGE',
        outputCategoryMask: false,
        outputConfidenceMasks: true
      });

      try {
        faceLandmarker = await vision.FaceLandmarker.createFromOptions(fileset, {
          baseOptions: { modelAssetPath: MP_FACE_MODEL, delegate: 'CPU' },
          runningMode: 'IMAGE',
          numFaces: 12,
          minFaceDetectionConfidence: 0.20,
          minFacePresenceConfidence: 0.20
        });
      } catch (faceErr) {
        console.warn('Face Landmarker unavailable:', faceErr);
      }

      try {
        faceDetector = await vision.FaceDetector.createFromOptions(fileset, {
          baseOptions: { modelAssetPath: MP_FACE_DETECTOR_MODEL, delegate: 'CPU' },
          runningMode: 'IMAGE',
          minDetectionConfidence: 0.20
        });
      } catch (detErr) {
        console.warn('Face Detector unavailable:', detErr);
      }

      state.aiModelsLoaded = true;
      setAiBadge('ready', '<i class="fa-solid fa-check-circle"></i> Neural Edge Vision Ready');
    } catch (err) {
      console.error('MediaPipe vision models failed to load:', err);
      state.aiModelsLoaded = false;
      setAiBadge('error', '<i class="fa-solid fa-triangle-exclamation"></i> AI Offline – use Drag & Select ROI');
    }
  }

  // Load models in background; segmentation awaits this promise.
  const aiReadyPromise = initAIModels();

  /* ---------- Low-level image-processing & edge-detection helpers ---------- */

  function resampleBilinear(src, sw, sh, dw, dh) {
    if (sw === dw && sh === dh) return src;
    const out = new Float32Array(dw * dh);
    const sx = sw / dw;
    const sy = sh / dh;
    for (let y = 0; y < dh; y++) {
      const fy = Math.max(0, Math.min(sh - 1, (y + 0.5) * sy - 0.5));
      const y0 = Math.floor(fy);
      const y1 = Math.min(sh - 1, y0 + 1);
      const wy = fy - y0;
      for (let x = 0; x < dw; x++) {
        const fx = Math.max(0, Math.min(sw - 1, (x + 0.5) * sx - 0.5));
        const x0 = Math.floor(fx);
        const x1 = Math.min(sw - 1, x0 + 1);
        const wx = fx - x0;
        const top = src[y0 * sw + x0] * (1 - wx) + src[y0 * sw + x1] * wx;
        const bot = src[y1 * sw + x0] * (1 - wx) + src[y1 * sw + x1] * wx;
        out[y * dw + x] = top * (1 - wy) + bot * wy;
      }
    }
    return out;
  }

  function boxMean(src, w, h, r) {
    if (r <= 0) return new Float32Array(src);
    const tmp = new Float32Array(w * h);
    const out = new Float32Array(w * h);
    for (let y = 0; y < h; y++) {
      const row = y * w;
      let sum = 0;
      for (let x = 0; x <= Math.min(r, w - 1); x++) sum += src[row + x];
      for (let x = 0; x < w; x++) {
        const lo = Math.max(0, x - r);
        const hi = Math.min(w - 1, x + r);
        tmp[row + x] = sum / (hi - lo + 1);
        if (x + r + 1 < w) sum += src[row + x + r + 1];
        if (x - r >= 0) sum -= src[row + x - r];
      }
    }
    for (let x = 0; x < w; x++) {
      let sum = 0;
      for (let y = 0; y <= Math.min(r, h - 1); y++) sum += tmp[y * w + x];
      for (let y = 0; y < h; y++) {
        const lo = Math.max(0, y - r);
        const hi = Math.min(h - 1, y + r);
        out[y * w + x] = sum / (hi - lo + 1);
        if (y + r + 1 < h) sum += tmp[(y + r + 1) * w + x];
        if (y - r >= 0) sum -= tmp[(y - r) * w + x];
      }
    }
    return out;
  }

  /**
   * Multi-channel 3x3 Sobel Colour Edge Detector.
   * Returns per-pixel gradient magnitude in [0, 1] across RGB channels.
   */
  function computeSobelEdges(rgb, w, h) {
    const mag = new Float32Array(w * h);
    let maxG = 1e-5;
    for (let y = 1; y < h - 1; y++) {
      for (let x = 1; x < w - 1; x++) {
        const i00 = ((y - 1) * w + (x - 1)) * 3;
        const i01 = ((y - 1) * w + x) * 3;
        const i02 = ((y - 1) * w + (x + 1)) * 3;
        const i10 = (y * w + (x - 1)) * 3;
        const i12 = (y * w + (x + 1)) * 3;
        const i20 = ((y + 1) * w + (x - 1)) * 3;
        const i21 = ((y + 1) * w + x) * 3;
        const i22 = ((y + 1) * w + (x + 1)) * 3;

        let g2 = 0;
        for (let c = 0; c < 3; c++) {
          const gx = -rgb[i00 + c] + rgb[i02 + c]
                   - 2 * rgb[i10 + c] + 2 * rgb[i12 + c]
                   - rgb[i20 + c] + rgb[i22 + c];
          const gy = -rgb[i00 + c] - 2 * rgb[i01 + c] - rgb[i02 + c]
                   + rgb[i20 + c] + 2 * rgb[i21 + c] + rgb[i22 + c];
          g2 += gx * gx + gy * gy;
        }
        const g = Math.sqrt(g2);
        mag[y * w + x] = g;
        if (g > maxG) maxG = g;
      }
    }
    const inv = 1 / maxG;
    for (let i = 0; i < mag.length; i++) mag[i] = Math.min(1, mag[i] * inv);
    return mag;
  }

  /**
   * Colour Guided Filter (He, Sun & Tang, 2013).
   */
  function guidedFilterColor(I, w, h, p, r, eps) {
    const n = w * h;
    const Ir = new Float32Array(n);
    const Ig = new Float32Array(n);
    const Ib = new Float32Array(n);
    for (let i = 0; i < n; i++) {
      Ir[i] = I[i * 3];
      Ig[i] = I[i * 3 + 1];
      Ib[i] = I[i * 3 + 2];
    }

    const prod = new Float32Array(n);
    const meanOfProduct = (a, b) => {
      for (let i = 0; i < n; i++) prod[i] = a[i] * b[i];
      return boxMean(prod, w, h, r);
    };

    const mR = boxMean(Ir, w, h, r);
    const mG = boxMean(Ig, w, h, r);
    const mB = boxMean(Ib, w, h, r);
    const mP = boxMean(p, w, h, r);
    const mRP = meanOfProduct(Ir, p);
    const mGP = meanOfProduct(Ig, p);
    const mBP = meanOfProduct(Ib, p);
    const vRR = meanOfProduct(Ir, Ir);
    const vRG = meanOfProduct(Ir, Ig);
    const vRB = meanOfProduct(Ir, Ib);
    const vGG = meanOfProduct(Ig, Ig);
    const vGB = meanOfProduct(Ig, Ib);
    const vBB = meanOfProduct(Ib, Ib);

    const aR = new Float32Array(n);
    const aG = new Float32Array(n);
    const aB = new Float32Array(n);
    const bb = new Float32Array(n);

    for (let i = 0; i < n; i++) {
      const mr = mR[i], mg = mG[i], mb = mB[i], mp = mP[i];
      const cR = mRP[i] - mr * mp;
      const cG = mGP[i] - mg * mp;
      const cB = mBP[i] - mb * mp;

      const rr = vRR[i] - mr * mr + eps;
      const rg = vRG[i] - mr * mg;
      const rb = vRB[i] - mr * mb;
      const gg = vGG[i] - mg * mg + eps;
      const gb = vGB[i] - mg * mb;
      const bl = vBB[i] - mb * mb + eps;

      const i00 = gg * bl - gb * gb;
      const i01 = gb * rb - rg * bl;
      const i02 = rg * gb - gg * rb;
      const i11 = rr * bl - rb * rb;
      const i12 = rb * rg - rr * gb;
      const i22 = rr * gg - rg * rg;
      const det = rr * i00 + rg * i01 + rb * i02;
      const invDet = det !== 0 ? 1 / det : 0;

      const a0 = (cR * i00 + cG * i01 + cB * i02) * invDet;
      const a1 = (cR * i01 + cG * i11 + cB * i12) * invDet;
      const a2 = (cR * i02 + cG * i12 + cB * i22) * invDet;
      aR[i] = a0;
      aG[i] = a1;
      aB[i] = a2;
      bb[i] = mp - a0 * mr - a1 * mg - a2 * mb;
    }

    const maR = boxMean(aR, w, h, r);
    const maG = boxMean(aG, w, h, r);
    const maB = boxMean(aB, w, h, r);
    const mbb = boxMean(bb, w, h, r);

    const q = new Float32Array(n);
    for (let i = 0; i < n; i++) {
      q[i] = maR[i] * Ir[i] + maG[i] * Ig[i] + maB[i] * Ib[i] + mbb[i];
    }
    return q;
  }

  /**
   * True Edge-Detection Boundary Snapping:
   * 1. Builds a boundary trimap band of radius `bandRadius` around the contour.
   * 2. Estimates local Definite Foreground & Definite Background RGB colours
   *    on either side of the contour and computes per-pixel RGB colour affinity.
   * 3. Uses Sobel edge magnitude + Guided Filter (`eps = 2e-4`) so the 0.5
   *    iso-contour snaps tightly onto the photo's real colour & gradient edges.
   */
  function refineAlphaWithEdges(rgb, sobel, w, h, coarse, opts = {}) {
    const out = new Float32Array(w * h);
    const baseR = opts.radius || Math.max(3, Math.min(10, Math.round(Math.max(w, h) / 160)));
    const eps = opts.eps || 2e-4;

    let minX = w, minY = h, maxX = -1, maxY = -1;
    for (let y = 0; y < h; y++) {
      for (let x = 0; x < w; x++) {
        if (coarse[y * w + x] > 0.02) {
          if (x < minX) minX = x;
          if (x > maxX) maxX = x;
          if (y < minY) minY = y;
          if (y > maxY) maxY = y;
        }
      }
    }
    if (maxX < 0) return out;

    const pad = baseR * 4;
    minX = Math.max(0, minX - pad);
    minY = Math.max(0, minY - pad);
    maxX = Math.min(w - 1, maxX + pad);
    maxY = Math.min(h - 1, maxY + pad);
    const cw = maxX - minX + 1;
    const ch = maxY - minY + 1;
    const cn = cw * ch;

    const cRGB = new Float32Array(cn * 3);
    const cP = new Float32Array(cn);
    const cSobel = new Float32Array(cn);
    for (let y = 0; y < ch; y++) {
      for (let x = 0; x < cw; x++) {
        const gi = (y + minY) * w + (x + minX);
        const ci = y * cw + x;
        cP[ci] = coarse[gi];
        cSobel[ci] = sobel[gi];
        cRGB[ci * 3] = rgb[gi * 3];
        cRGB[ci * 3 + 1] = rgb[gi * 3 + 1];
        cRGB[ci * 3 + 2] = rgb[gi * 3 + 2];
      }
    }

    // Smooth the prior slightly so hard polygon/mask borders have a genuine transition band
    const smoothP = boxMean(cP, cw, ch, Math.max(2, Math.round(baseR * 0.6)));

    // Estimate local foreground & background RGB colours in a neighbourhood of radius 2*baseR
    const statR = baseR * 2;
    const wFg = new Float32Array(cn);
    const wBg = new Float32Array(cn);
    const fgR = new Float32Array(cn), fgG = new Float32Array(cn), fgB = new Float32Array(cn);
    const bgR = new Float32Array(cn), bgG = new Float32Array(cn), bgB = new Float32Array(cn);

    for (let i = 0; i < cn; i++) {
      const p = smoothP[i];
      // Definite-ish foreground vs background weights
      const wf = p > 0.55 ? (p - 0.55) / 0.45 : 0;
      const wb = p < 0.45 ? (0.45 - p) / 0.45 : 0;
      wFg[i] = wf;
      wBg[i] = wb;
      fgR[i] = wf * cRGB[i * 3];
      fgG[i] = wf * cRGB[i * 3 + 1];
      fgB[i] = wf * cRGB[i * 3 + 2];
      bgR[i] = wb * cRGB[i * 3];
      bgG[i] = wb * cRGB[i * 3 + 1];
      bgB[i] = wb * cRGB[i * 3 + 2];
    }

    const mWf = boxMean(wFg, cw, ch, statR);
    const mWb = boxMean(wBg, cw, ch, statR);
    const mFgR = boxMean(fgR, cw, ch, statR);
    const mFgG = boxMean(fgG, cw, ch, statR);
    const mFgB = boxMean(fgB, cw, ch, statR);
    const mBgR = boxMean(bgR, cw, ch, statR);
    const mBgG = boxMean(bgG, cw, ch, statR);
    const mBgB = boxMean(bgB, cw, ch, statR);

    // Build edge-snapped prior inside the boundary band
    const prior = new Float32Array(cn);
    const band = new Uint8Array(cn);
    for (let i = 0; i < cn; i++) {
      const sp = smoothP[i];
      if (sp > 0.03 && sp < 0.97 && mWf[i] > 1e-3 && mWb[i] > 1e-3) {
        band[i] = 1;
        const fr = mFgR[i] / mWf[i], fg = mFgG[i] / mWf[i], fb = mFgB[i] / mWf[i];
        const br = mBgR[i] / mWb[i], bg = mBgG[i] / mWb[i], bb = mBgB[i] / mWb[i];
        const r = cRGB[i * 3], g = cRGB[i * 3 + 1], b = cRGB[i * 3 + 2];

        const dFg = (r - fr) * (r - fr) + (g - fg) * (g - fg) + (b - fb) * (b - fb);
        const dBg = (r - br) * (r - br) + (g - bg) * (g - bg) + (b - bb) * (b - bb);
        const sep = (fr - br) * (fr - br) + (fg - bg) * (fg - bg) + (fb - bb) * (fb - bb);

        const colorAff = dBg / (dFg + dBg + 1e-4);
        // Stronger local FG/BG contrast + Sobel gradient -> stronger snapping to colour edge
        const edgeWeight = Math.min(0.82, Math.sqrt(sep) * 2.2 + cSobel[i] * 0.35);
        prior[i] = (1 - edgeWeight) * sp + edgeWeight * colorAff;
      } else {
        prior[i] = cP[i];
      }
    }

    // Two-stage guided filter (coarse radius then fine radius for crisp 1px edge locking)
    const qCoarse = guidedFilterColor(cRGB, cw, ch, prior, baseR, eps);
    const fineR = Math.max(2, Math.round(baseR * 0.45));
    const qFine = guidedFilterColor(cRGB, cw, ch, qCoarse, fineR, eps * 0.5);

    for (let y = 0; y < ch; y++) {
      for (let x = 0; x < cw; x++) {
        const ci = y * cw + x;
        const gi = (y + minY) * w + (x + minX);
        if (band[ci]) {
          let v = Math.min(1, Math.max(0, qFine[ci]));
          // Sharpen right across strong Sobel gradient peaks
          if (cSobel[ci] > 0.12) {
            v = 0.5 + (v - 0.5) * (1 + cSobel[ci] * 1.5);
            v = Math.min(1, Math.max(0, v));
          }
          out[gi] = v;
        } else {
          out[gi] = cP[ci];
        }
      }
    }
    return out;
  }

  /**
   * Remove small foreground specks and fill small enclosed holes (4-connectivity).
   */
  function cleanupAlpha(alpha, w, h, minIslandPixels, maxHolePixels) {
    const n = w * h;
    const bin = new Uint8Array(n);
    let fgCount = 0;
    for (let i = 0; i < n; i++) {
      if (alpha[i] >= 0.5) { bin[i] = 1; fgCount++; }
    }
    if (fgCount === 0) return;

    const visited = new Uint8Array(n);
    const stack = new Int32Array(n);
    const comp = new Int32Array(n);

    for (let start = 0; start < n; start++) {
      if (visited[start]) continue;
      const val = bin[start];
      let sp = 0, cs = 0, touchesBorder = false;
      stack[sp++] = start;
      visited[start] = 1;

      while (sp > 0) {
        const p = stack[--sp];
        comp[cs++] = p;
        const x = p % w;
        const y = (p - x) / w;
        if (x === 0 || y === 0 || x === w - 1 || y === h - 1) touchesBorder = true;
        if (x > 0 && !visited[p - 1] && bin[p - 1] === val) { visited[p - 1] = 1; stack[sp++] = p - 1; }
        if (x < w - 1 && !visited[p + 1] && bin[p + 1] === val) { visited[p + 1] = 1; stack[sp++] = p + 1; }
        if (y > 0 && !visited[p - w] && bin[p - w] === val) { visited[p - w] = 1; stack[sp++] = p - w; }
        if (y < h - 1 && !visited[p + w] && bin[p + w] === val) { visited[p + w] = 1; stack[sp++] = p + w; }
      }

      if (val === 1 && cs < minIslandPixels) {
        for (let k = 0; k < cs; k++) alpha[comp[k]] = 0;
      } else if (val === 0 && !touchesBorder && cs < maxHolePixels) {
        for (let k = 0; k < cs; k++) alpha[comp[k]] = 1;
      }
    }
  }

  function alphaToFullResMask(alpha, w, h, W, H) {
    const mask = new Uint8Array(W * H);
    const full = resampleBilinear(alpha, w, h, W, H);
    let count = 0, topX = Math.floor(W / 2), topY = -1;
    for (let i = 0; i < W * H; i++) {
      if (full[i] >= 0.5) {
        mask[i] = 1;
        count++;
        if (topY < 0) { topY = Math.floor(i / W); topX = i % W; }
      }
    }
    return { mask, count, topX, topY: Math.max(0, topY) };
  }

  function runSegmenter(source) {
    return new Promise((resolve, reject) => {
      try {
        imageSegmenter.segment(source, (result) => {
          try {
            const masks = (result.confidenceMasks || []).map(m => ({
              w: m.width,
              h: m.height,
              data: new Float32Array(m.getAsFloat32Array())
            }));
            resolve(masks);
          } catch (e) {
            reject(e);
          }
        });
      } catch (e) {
        reject(e);
      }
    });
  }

  /**
   * Run multiclass segmenter on a sub-crop of `sourceCanvas` and return
   * resampled class maps for that crop rectangle.
   */
  async function segmentSubRect(sourceCanvas, rx, ry, rw, rh) {
    const c = document.createElement('canvas');
    c.width = 256;
    c.height = 256;
    const ctx = c.getContext('2d');
    ctx.drawImage(sourceCanvas, rx, ry, rw, rh, 0, 0, 256, 256);
    const masks = await runSegmenter(c);
    return masks.map(m => resampleBilinear(m.data, m.w, m.h, rw, rh));
  }

  /**
   * Multi-Scale + Tiled + Proposal Face Detection.
   * Guarantees that all faces in group photos (e.g. 4+ people) are found,
   * even when individual faces are small or off-centre.
   */
  function detectAllFacesMultiScale(workCanvas, w, h, faceSkinMap) {
    const foundFaces = []; // each item: { landmarks: Array<{x,y,z}> | null, bbox: {x0,y0,x1,y1} }

    function bboxFromLandmarks(lm) {
      let x0 = 1, y0 = 1, x1 = 0, y1 = 0;
      for (let i = 0; i < FACE_OVAL_IDX.length; i++) {
        const pt = lm[FACE_OVAL_IDX[i]];
        if (pt.x < x0) x0 = pt.x;
        if (pt.x > x1) x1 = pt.x;
        if (pt.y < y0) y0 = pt.y;
        if (pt.y > y1) y1 = pt.y;
      }
      return { x0: x0 * w, y0: y0 * h, x1: x1 * w, y1: y1 * h };
    }

    function iouOrOverlap(a, b) {
      const ix0 = Math.max(a.x0, b.x0), iy0 = Math.max(a.y0, b.y0);
      const ix1 = Math.min(a.x1, b.x1), iy1 = Math.min(a.y1, b.y1);
      const iw = Math.max(0, ix1 - ix0), ih = Math.max(0, iy1 - iy0);
      const inter = iw * ih;
      const areaA = Math.max(1, (a.x1 - a.x0) * (a.y1 - a.y0));
      const areaB = Math.max(1, (b.x1 - b.x0) * (b.y1 - b.y0));
      const union = areaA + areaB - inter;
      const minArea = Math.min(areaA, areaB);
      const acx = (a.x0 + a.x1) * 0.5, acy = (a.y0 + a.y1) * 0.5;
      const bcx = (b.x0 + b.x1) * 0.5, bcy = (b.y0 + b.y1) * 0.5;
      const dist = Math.hypot(acx - bcx, acy - bcy);
      const avgSize = 0.5 * (Math.hypot(a.x1 - a.x0, a.y1 - a.y0) + Math.hypot(b.x1 - b.x0, b.y1 - b.y0));
      return (inter / union > 0.30) || (inter / minArea > 0.55) || (dist < avgSize * 0.35);
    }

    function addLandmarkFace(lm) {
      const bbox = bboxFromLandmarks(lm);
      const bw = bbox.x1 - bbox.x0, bh = bbox.y1 - bbox.y0;
      if (bw < 12 || bh < 12) return;
      for (let i = 0; i < foundFaces.length; i++) {
        if (iouOrOverlap(foundFaces[i].bbox, bbox)) {
          // Prefer a face with landmarks over a bbox-only detection
          if (!foundFaces[i].landmarks && lm) {
            foundFaces[i] = { landmarks: lm, bbox };
          }
          return;
        }
      }
      foundFaces.push({ landmarks: lm, bbox });
    }

    function runLandmarkerOnCrop(rx, ry, rw, rh, targetSize = 512) {
      if (!faceLandmarker || rw < 16 || rh < 16) return;
      const c = document.createElement('canvas');
      c.width = targetSize;
      c.height = targetSize;
      const ctx = c.getContext('2d');
      ctx.drawImage(workCanvas, rx, ry, rw, rh, 0, 0, targetSize, targetSize);
      try {
        const res = faceLandmarker.detect(c);
        const lms = (res && res.faceLandmarks) ? res.faceLandmarks : [];
        lms.forEach(lm => {
          // Ignore detections clipped right against the artificial crop border
          let minX = 1, maxX = 0, minY = 1, maxY = 0;
          FACE_OVAL_IDX.forEach(idx => {
            const p = lm[idx];
            if (p.x < minX) minX = p.x;
            if (p.x > maxX) maxX = p.x;
            if (p.y < minY) minY = p.y;
            if (p.y > maxY) maxY = p.y;
          });
          const touchesLeft = rx > 2 && minX < 0.015;
          const touchesRight = (rx + rw < w - 2) && maxX > 0.985;
          const touchesTop = ry > 2 && minY < 0.015;
          const touchesBot = (ry + rh < h - 2) && maxY > 0.985;
          if (touchesLeft || touchesRight || touchesTop || touchesBot) return;

          const mapped = lm.map(pt => ({
            x: (rx + pt.x * rw) / w,
            y: (ry + pt.y * rh) / h,
            z: pt.z
          }));
          addLandmarkFace(mapped);
        });
      } catch (e) {
        // ignore single-crop error
      }
    }

    // 1. Full-frame FaceLandmarker pass
    if (faceLandmarker) {
      try {
        const res = faceLandmarker.detect(workCanvas);
        ((res && res.faceLandmarks) || []).forEach(lm => addLandmarkFace(lm));
      } catch (e) {
        console.warn('Full-frame FaceLandmarker failed:', e);
      }
    }

    // 2. Overlapping tiled passes (magnifies smaller/group-photo faces by ~2x)
    const tiles = [
      [0, 0, w * 0.62, h * 0.75],
      [w * 0.19, 0, w * 0.62, h * 0.75],
      [w * 0.38, 0, w * 0.62, h * 0.75],
      [0, h * 0.15, w * 0.58, h * 0.85],
      [w * 0.42, h * 0.15, w * 0.58, h * 0.85]
    ];
    tiles.forEach(([tx, ty, tw, th]) => {
      runLandmarkerOnCrop(Math.round(tx), Math.round(ty), Math.round(tw), Math.round(th), 512);
    });

    // 3. BlazeFace detector pass (full + left/right halves) -> refine each box with FaceLandmarker crop
    if (faceDetector) {
      const detCrops = [
        [0, 0, w, h],
        [0, 0, Math.round(w * 0.6), h],
        [Math.round(w * 0.4), 0, Math.round(w * 0.6), h]
      ];
      detCrops.forEach(([dx, dy, dw, dh]) => {
        try {
          const c = document.createElement('canvas');
          c.width = dw;
          c.height = dh;
          c.getContext('2d').drawImage(workCanvas, dx, dy, dw, dh, 0, 0, dw, dh);
          const detRes = faceDetector.detect(c);
          ((detRes && detRes.detections) || []).forEach(det => {
            const bb = det.boundingBox;
            if (!bb) return;
            const bx0 = dx + bb.originX;
            const by0 = dy + bb.originY;
            const bw = bb.width;
            const bh = bb.height;
            const candBox = { x0: bx0, y0: by0, x1: bx0 + bw, y1: by0 + bh };
            const already = foundFaces.some(f => iouOrOverlap(f.bbox, candBox));
            if (!already) {
              const pad = Math.max(bw, bh) * 0.85;
              const cx0 = Math.max(0, Math.floor(bx0 - pad));
              const cy0 = Math.max(0, Math.floor(by0 - pad));
              const cx1 = Math.min(w, Math.ceil(bx0 + bw + pad));
              const cy1 = Math.min(h, Math.ceil(by0 + bh + pad));
              const beforeCount = foundFaces.length;
              runLandmarkerOnCrop(cx0, cy0, cx1 - cx0, cy1 - cy0, 384);
              if (foundFaces.length === beforeCount) {
                foundFaces.push({ landmarks: null, bbox: candBox });
              }
            }
          });
        } catch (e) {
          // ignore
        }
      });
    }

    // 4. Connected-component proposals from neural `faceSkinMap` (class 3)
    // Catches any remaining face that neural segmentation saw as face-skin!
    if (faceSkinMap) {
      const n = w * h;
      const visited = new Uint8Array(n);
      const stack = new Int32Array(n);
      const minCluster = Math.max(35, Math.round(n * 0.00035));

      for (let start = 0; start < n; start++) {
        if (visited[start] || faceSkinMap[start] < 0.25) continue;
        let sp = 0, count = 0;
        let x0 = w, y0 = h, x1 = 0, y1 = 0;
        stack[sp++] = start;
        visited[start] = 1;

        while (sp > 0) {
          const p = stack[--sp];
          count++;
          const x = p % w;
          const y = (p - x) / w;
          if (x < x0) x0 = x;
          if (x > x1) x1 = x;
          if (y < y0) y0 = y;
          if (y > y1) y1 = y;

          if (x > 0 && !visited[p - 1] && faceSkinMap[p - 1] >= 0.25) { visited[p - 1] = 1; stack[sp++] = p - 1; }
          if (x < w - 1 && !visited[p + 1] && faceSkinMap[p + 1] >= 0.25) { visited[p + 1] = 1; stack[sp++] = p + 1; }
          if (y > 0 && !visited[p - w] && faceSkinMap[p - w] >= 0.25) { visited[p - w] = 1; stack[sp++] = p - w; }
          if (y < h - 1 && !visited[p + w] && faceSkinMap[p + w] >= 0.25) { visited[p + w] = 1; stack[sp++] = p + w; }
        }

        const bw = x1 - x0 + 1, bh = y1 - y0 + 1;
        const aspect = bh / Math.max(1, bw);
        if (count >= minCluster && aspect > 0.4 && aspect < 2.8) {
          const candBox = { x0, y0, x1, y1 };
          const covered = foundFaces.some(f => iouOrOverlap(f.bbox, candBox));
          if (!covered) {
            const pad = Math.max(bw, bh) * 0.9;
            const cx0 = Math.max(0, Math.floor(x0 - pad));
            const cy0 = Math.max(0, Math.floor(y0 - pad));
            const cx1 = Math.min(w, Math.ceil(x1 + pad));
            const cy1 = Math.min(h, Math.ceil(y1 + pad));
            const beforeCount = foundFaces.length;
            runLandmarkerOnCrop(cx0, cy0, cx1 - cx0, cy1 - cy0, 384);
            if (foundFaces.length === beforeCount) {
              // Keep as a skin-segmented face even if landmarks didn't trigger
              foundFaces.push({ landmarks: null, bbox: candBox });
            }
          }
        }
      }
    }

    // Sort faces left-to-right for consistent numbering
    foundFaces.sort((a, b) => a.bbox.x0 - b.bbox.x0);
    return foundFaces;
  }

  /**
   * Draw a smooth closed Catmull-Rom spline curve through `points` ([{x,y}, ...]).
   */
  function fillSmoothPolygon(ctx, points) {
    const k = points.length;
    if (k < 3) return;
    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 0; i < k; i++) {
      const p0 = points[(i - 1 + k) % k];
      const p1 = points[i];
      const p2 = points[(i + 1) % k];
      const p3 = points[(i + 2) % k];
      const cp1x = p1.x + (p2.x - p0.x) / 6;
      const cp1y = p1.y + (p2.y - p0.y) / 6;
      const cp2x = p2.x - (p3.x - p1.x) / 6;
      const cp2y = p2.y - (p3.y - p1.y) / 6;
      ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, p2.x, p2.y);
    }
    ctx.closePath();
    ctx.fill();
  }

  function updateAiResultUI(bodyPixels, facePixels, bodyPct, facePct, faceCount, aiAvailable) {
    if (DOM.subPersonCount) {
      DOM.subPersonCount.textContent = !aiAvailable ? 'AI unavailable' : (bodyPixels > 0 ? `Traced (${bodyPct}%)` : 'No person found');
    }
    if (DOM.subFaceCount) {
      if (!aiAvailable) {
        DOM.subFaceCount.textContent = 'AI unavailable';
      } else if (facePixels > 0) {
        const fLabel = faceCount > 1 ? `${faceCount} faces` : '1 face';
        DOM.subFaceCount.textContent = `${fLabel} (${facePct}%)`;
      } else {
        DOM.subFaceCount.textContent = 'No face found';
      }
    }
    if (DOM.aiDetectionBanner) {
      DOM.aiDetectionBanner.style.display = 'flex';
      if (bodyPixels > 0 || facePixels > 0) {
        const fText = faceCount > 0 ? `${faceCount} ${faceCount === 1 ? 'Face' : 'Faces'} (${facePct}%)` : `Face (${facePct}%)`;
        DOM.aiDetectionText.innerHTML = `<i class="fa-solid fa-shapes"></i> <b>Edge-Refined Human Contour:</b> Body (${bodyPct}%) &amp; ${fText}. Or use <b>Drag &amp; Select ROI</b>.`;
      } else if (!aiAvailable) {
        DOM.aiDetectionText.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> <b>AI models could not be loaded</b> (internet connection required). Use <b>Drag &amp; Select ROI</b> or <b>Entire Image</b>.`;
      } else {
        DOM.aiDetectionText.innerHTML = `<i class="fa-solid fa-crosshairs"></i> <b>No person detected.</b> Drag directly on the image to select any area to encrypt, or choose <b>Entire Image</b>.`;
      }
    }
  }

  /**
   * Run AI Human Segmentation + Multi-Face Detection + Edge-Detection Refinement.
   */
  async function runAISegmentation(img) {
    if (!img) return;
    const token = ++state.segToken;
    state.isAiDetecting = true;
    state.bodyMask = null;
    state.faceMask = null;
    state.allMask = null;
    state.detectedFaces = [];
    state.detectedBodyStats = { pixelCount: 0, coveragePct: 0, topX: 0, topY: 0 };
    state.detectedFaceStats = { pixelCount: 0, coveragePct: 0, topX: 0, topY: 0, count: 0 };
    if (DOM.subPersonCount) DOM.subPersonCount.textContent = 'Tracing…';
    if (DOM.subFaceCount) DOM.subFaceCount.textContent = 'Tracing…';

    setAiBadge('scanning', '<i class="fa-solid fa-circle-notch fa-spin"></i> ' +
      (state.aiModelsLoaded ? 'Detecting Faces & Edges...' : 'Loading Neural Vision...'));

    await aiReadyPromise;
    if (token !== state.segToken) return;

    if (!imageSegmenter) {
      state.isAiDetecting = false;
      setAiBadge('error', '<i class="fa-solid fa-triangle-exclamation"></i> AI Offline – use Drag & Select ROI');
      updateAiResultUI(0, 0, 0, 0, 0, false);
      renderEncOriginalWithOverlays();
      return;
    }

    setAiBadge('scanning', '<i class="fa-solid fa-circle-notch fa-spin"></i> Tracing Human & Face Edges...');
    await new Promise(r => setTimeout(r, 30));

    const W = img.width;
    const H = img.height;
    const scale = Math.min(1, SEG_WORK_MAX / Math.max(W, H));
    const w = Math.max(1, Math.round(W * scale));
    const h = Math.max(1, Math.round(H * scale));
    const n = w * h;

    try {
      const workCanvas = document.createElement('canvas');
      workCanvas.width = w;
      workCanvas.height = h;
      const wctx = workCanvas.getContext('2d', { willReadFrequently: true });
      wctx.drawImage(img, 0, 0, w, h);
      const rgba = wctx.getImageData(0, 0, w, h).data;
      const rgb = new Float32Array(n * 3);
      for (let i = 0; i < n; i++) {
        rgb[i * 3] = rgba[i * 4] / 255;
        rgb[i * 3 + 1] = rgba[i * 4 + 1] / 255;
        rgb[i * 3 + 2] = rgba[i * 4 + 2] / 255;
      }

      // Compute Sobel colour edge map for true edge snapping
      const sobel = computeSobelEdges(rgb, w, h);

      // 1. Full-frame + Tiled High-Res Multiclass Person Segmentation
      const masks = await runSegmenter(workCanvas);
      if (token !== state.segToken) return;
      if (!masks.length) throw new Error('Segmenter returned no masks');

      const numClasses = masks.length;
      const classMaps = masks.map(m => resampleBilinear(m.data, m.w, m.h, w, h));

      // Fuse overlapping left/right high-res tiles so group photos get 2x higher neural resolution
      if (w >= 320 && numClasses >= 4) {
        const tileW = Math.round(w * 0.62);
        const tileRects = [
          [0, 0, tileW, h],
          [w - tileW, 0, tileW, h]
        ];
        const accum = Array.from({ length: numClasses }, () => new Float32Array(n));
        const weightSum = new Float32Array(n);
        for (let c = 0; c < numClasses; c++) {
          accum[c].set(classMaps[c]);
        }
        weightSum.fill(1.0);

        for (const [rx, ry, rw, rh] of tileRects) {
          const subMaps = await segmentSubRect(workCanvas, rx, ry, rw, rh);
          if (token !== state.segToken) return;
          for (let y = 0; y < rh; y++) {
            const wy = 1 - 0.5 * Math.pow((y - rh * 0.5) / (rh * 0.5), 2);
            for (let x = 0; x < rw; x++) {
              const wx = 1 - 0.5 * Math.pow((x - rw * 0.5) / (rw * 0.5), 2);
              const wt = Math.max(0.2, wx * wy) * 1.6;
              const gi = (ry + y) * w + (rx + x);
              const si = y * rw + x;
              for (let c = 0; c < numClasses; c++) {
                accum[c][gi] += subMaps[c][si] * wt;
              }
              weightSum[gi] += wt;
            }
          }
        }
        for (let c = 0; c < numClasses; c++) {
          const dst = classMaps[c];
          const src = accum[c];
          for (let i = 0; i < n; i++) dst[i] = src[i] / weightSum[i];
        }
      }

      const bgConf = classMaps[0];
      const hairConf = numClasses >= 2 ? classMaps[1] : new Float32Array(n);
      const bodySkinConf = numClasses >= 3 ? classMaps[2] : new Float32Array(n);
      const faceSkinConf = numClasses >= 4 ? classMaps[3] : null;
      const clothesConf = numClasses >= 5 ? classMaps[4] : new Float32Array(n);
      const accConf = numClasses >= 6 ? classMaps[5] : new Float32Array(n);

      const bodyCoarse = new Float32Array(n);
      for (let i = 0; i < n; i++) {
        bodyCoarse[i] = numClasses >= 2 ? Math.min(1, Math.max(0, 1 - bgConf[i])) : bgConf[i];
      }

      // 2. Multi-scale + Tiled + Skin-Proposal Face Detection (finds all 4+ faces)
      const detectedFaces = detectAllFacesMultiScale(workCanvas, w, h, faceSkinConf);
      if (token !== state.segToken) return;

      // 3. Per-Face High-Resolution Segmentation + Anatomical Landmark Fusion
      const faceCoarse = new Float32Array(n);

      for (let fIdx = 0; fIdx < detectedFaces.length; fIdx++) {
        const face = detectedFaces[fIdx];
        const { bbox, landmarks } = face;
        const fw = Math.max(16, bbox.x1 - bbox.x0);
        const fh = Math.max(16, bbox.y1 - bbox.y0);

        // Extract a padded crop around this single face and segment it at full 256x256 resolution
        const padX = Math.round(fw * 0.45);
        const padY = Math.round(fh * 0.50);
        const rx = Math.max(0, Math.floor(bbox.x0 - padX));
        const ry = Math.max(0, Math.floor(bbox.y0 - padY));
        const rw = Math.min(w - rx, Math.ceil(bbox.x1 - bbox.x0 + padX * 2));
        const rh = Math.min(h - ry, Math.ceil(bbox.y1 - bbox.y0 + padY * 2));

        let localMasks = null;
        if (rw >= 20 && rh >= 20) {
          try {
            localMasks = await segmentSubRect(workCanvas, rx, ry, rw, rh);
          } catch (e) {
            localMasks = null;
          }
        }
        if (token !== state.segToken) return;

        // Blend high-res local face segmentation into global class maps as well
        if (localMasks && localMasks.length >= 4) {
          for (let y = 0; y < rh; y++) {
            for (let x = 0; x < rw; x++) {
              const gi = (ry + y) * w + (rx + x);
              const li = y * rw + x;
              const lBg = localMasks[0][li];
              const lPerson = Math.min(1, Math.max(0, 1 - lBg));
              if (lPerson > bodyCoarse[gi]) bodyCoarse[gi] = 0.4 * bodyCoarse[gi] + 0.6 * lPerson;
            }
          }
        }

        if (landmarks) {
          // Compute face centre
          const cx = (bbox.x0 + bbox.x1) * 0.5 - rx;
          const cy = (bbox.y0 + bbox.y1) * 0.5 - ry;

          // A) Outer anatomical face envelope (smooth spline through FACE_OVAL_IDX,
          //    expanded slightly at forehead so hairline can be carved by neural hair mask,
          //    and tight along the chin/jawline so neck skin is excluded).
          const outerPts = FACE_OVAL_IDX.map(idx => {
            const pt = landmarks[idx];
            const px = pt.x * w - rx;
            const py = pt.y * h - ry;
            const dx = px - cx;
            const dy = py - cy;
            const isForehead = FOREHEAD_SET.has(idx);
            const scaleX = isForehead ? 1.08 : 1.03;
            const scaleY = isForehead ? 1.16 : 1.01;
            return { x: cx + dx * scaleX, y: cy + dy * scaleY };
          });

          // B) Inner facial features core (inset spline covering brows, eyes, nose, mouth)
          const innerPts = FACE_OVAL_IDX.map(idx => {
            const pt = landmarks[idx];
            const px = pt.x * w - rx;
            const py = pt.y * h - ry;
            return { x: cx + (px - cx) * 0.76, y: cy + (py - cy) * 0.76 };
          });

          const cOuter = document.createElement('canvas');
          cOuter.width = rw;
          cOuter.height = rh;
          const ctxOut = cOuter.getContext('2d');
          ctxOut.fillStyle = '#ffffff';
          fillSmoothPolygon(ctxOut, outerPts);
          const outerAlphaRaw = ctxOut.getImageData(0, 0, rw, rh).data;

          const cInner = document.createElement('canvas');
          cInner.width = rw;
          cInner.height = rh;
          const ctxIn = cInner.getContext('2d');
          ctxIn.fillStyle = '#ffffff';
          fillSmoothPolygon(ctxIn, innerPts);
          const innerAlphaRaw = ctxIn.getImageData(0, 0, rw, rh).data;

          const outerFloat = new Float32Array(rw * rh);
          const innerFloat = new Float32Array(rw * rh);
          for (let i = 0; i < rw * rh; i++) {
            outerFloat[i] = outerAlphaRaw[i * 4 + 3] / 255;
            innerFloat[i] = innerAlphaRaw[i * 4 + 3] / 255;
          }

          // Feather the outer anatomical boundary so guided filter & neural skin mask
          // snap the contour onto the true jawline / cheek / hairline edges
          const featherR = Math.max(2, Math.round(Math.min(fw, fh) * 0.055));
          const outerSmooth = boxMean(outerFloat, rw, rh, featherR);
          const innerSmooth = boxMean(innerFloat, rw, rh, Math.max(1, Math.round(featherR * 0.5)));

          for (let y = 0; y < rh; y++) {
            for (let x = 0; x < rw; x++) {
              const li = y * rw + x;
              const env = outerSmooth[li];
              if (env < 0.02) continue;

              const gi = (ry + y) * w + (rx + x);
              const pBg = localMasks ? localMasks[0][li] : bgConf[gi];
              const pHair = (localMasks && localMasks[1]) ? localMasks[1][li] : hairConf[gi];
              const pBody = (localMasks && localMasks[2]) ? localMasks[2][li] : bodySkinConf[gi];
              const pFace = (localMasks && localMasks[3]) ? localMasks[3][li] : (faceSkinConf ? faceSkinConf[gi] : 0.5);
              const pClothes = (localMasks && localMasks[4]) ? localMasks[4][li] : clothesConf[gi];
              const pAcc = (localMasks && localMasks[5]) ? localMasks[5][li] : accConf[gi];

              // Neural probability that pixel is face (vs hair, background, clothes, or neck)
              const fgFace = pFace + 0.35 * pAcc;
              const nonFace = pBg + pHair * 1.15 + pClothes + pBody * 0.55;
              const neuralFaceProb = fgFace / (fgFace + nonFace + 1e-4);

              // Combine inner core (protects eyes/brows/mouth) with neural skin boundary & anatomical jawline
              const core = innerSmooth[li] * (1 - Math.min(0.85, pHair + pBg));
              const combined = env * (0.68 * neuralFaceProb + 0.32 * env);
              const val = Math.min(1, Math.max(core * 0.92, combined));
              if (val > faceCoarse[gi]) faceCoarse[gi] = val;
            }
          }
        } else {
          // Fallback for a face without landmarks (e.g., extreme profile): use high-res neural face-skin mask
          for (let y = 0; y < rh; y++) {
            for (let x = 0; x < rw; x++) {
              const li = y * rw + x;
              const gi = (ry + y) * w + (rx + x);
              const pBg = localMasks ? localMasks[0][li] : bgConf[gi];
              const pHair = (localMasks && localMasks[1]) ? localMasks[1][li] : hairConf[gi];
              const pFace = (localMasks && localMasks[3]) ? localMasks[3][li] : (faceSkinConf ? faceSkinConf[gi] : 0);
              const pAcc = (localMasks && localMasks[5]) ? localMasks[5][li] : accConf[gi];
              const prob = (pFace + 0.25 * pAcc) / (pFace + 0.25 * pAcc + pBg + pHair + 1e-4);
              const val = pFace > 0.15 ? prob : 0;
              if (val > faceCoarse[gi]) faceCoarse[gi] = val;
            }
          }
        }
      }

      if (token !== state.segToken) return;

      // 4. Edge-Detection Boundary Snapping (Sobel + Local FG/BG Colour Affinity + Guided Filter)
      const bodyRadius = Math.max(4, Math.min(10, Math.round(Math.max(w, h) / 150)));
      const bodyAlpha = refineAlphaWithEdges(rgb, sobel, w, h, bodyCoarse, { radius: bodyRadius, eps: 2e-4 });
      cleanupAlpha(bodyAlpha, w, h, Math.max(40, Math.round(n * 0.001)), Math.max(40, Math.round(n * 0.0015)));

      let faceAlpha = null;
      if (detectedFaces.length > 0) {
        const faceRadius = Math.max(3, Math.min(7, Math.round(Math.max(w, h) / 210)));
        faceAlpha = refineAlphaWithEdges(rgb, sobel, w, h, faceCoarse, { radius: faceRadius, eps: 1.5e-4 });
        // Keep each face (even small ones in group photos) while filling internal eye/brow/mouth holes
        cleanupAlpha(faceAlpha, w, h, 25, Math.max(80, Math.round(n * 0.002)));
        for (let i = 0; i < n; i++) {
          if (faceAlpha[i] > bodyAlpha[i]) bodyAlpha[i] = faceAlpha[i];
        }
      }

      if (token !== state.segToken) return;

      // 5. Upscale to full image resolution (W x H)
      const totalPixels = W * H;
      const body = alphaToFullResMask(bodyAlpha, w, h, W, H);
      const face = faceAlpha
        ? alphaToFullResMask(faceAlpha, w, h, W, H)
        : { mask: new Uint8Array(totalPixels), count: 0, topX: 0, topY: 0 };

      // Compute per-face top coordinates in full-res pixels for canvas badges
      const invScaleX = W / w;
      const invScaleY = H / h;
      const faceBoxesFull = detectedFaces.map((f, idx) => ({
        index: idx + 1,
        cx: Math.round(((f.bbox.x0 + f.bbox.x1) * 0.5) * invScaleX),
        topY: Math.round(f.bbox.y0 * invScaleY),
        x0: Math.round(f.bbox.x0 * invScaleX),
        y0: Math.round(f.bbox.y0 * invScaleY),
        x1: Math.round(f.bbox.x1 * invScaleX),
        y1: Math.round(f.bbox.y1 * invScaleY)
      }));

      const minBody = totalPixels * 0.0015;
      const bodyPixels = body.count >= minBody ? body.count : 0;
      const facePixels = face.count >= 35 ? face.count : 0;

      const bodyPct = parseFloat(((bodyPixels / totalPixels) * 100).toFixed(1));
      const facePct = parseFloat(((facePixels / totalPixels) * 100).toFixed(1));

      state.bodyMask = bodyPixels > 0 ? body.mask : null;
      state.faceMask = facePixels > 0 ? face.mask : null;
      state.allMask = state.bodyMask;
      state.detectedFaces = facePixels > 0 ? faceBoxesFull : [];
      state.detectedBodyStats = { pixelCount: bodyPixels, coveragePct: bodyPct, topX: body.topX, topY: body.topY };
      state.detectedFaceStats = {
        pixelCount: facePixels,
        coveragePct: facePct,
        topX: faceBoxesFull.length > 0 ? faceBoxesFull[0].cx : face.topX,
        topY: faceBoxesFull.length > 0 ? faceBoxesFull[0].topY : face.topY,
        count: facePixels > 0 ? Math.max(1, faceBoxesFull.length) : 0
      };

      setAiBadge('ready', '<i class="fa-solid fa-circle-check"></i> Edge-Refined Analysis Ready');
      updateAiResultUI(bodyPixels, facePixels, bodyPct, facePct, state.detectedFaceStats.count, true);
    } catch (err) {
      console.error('AI segmentation failed:', err);
      setAiBadge('warning', '<i class="fa-solid fa-triangle-exclamation"></i> Detection failed – use Drag & Select ROI');
      updateAiResultUI(0, 0, 0, 0, 0, true);
    } finally {
      if (token === state.segToken) state.isAiDetecting = false;
    }

    renderEncOriginalWithOverlays();
  }

  /**
   * Helper: Get canvas pixel coordinates from mouse/touch event
   */
  function getCanvasPixelCoords(canvas, evt) {
    const rect = canvas.getBoundingClientRect();
    const scaleX = canvas.width / rect.width;
    const scaleY = canvas.height / rect.height;
    const clientX = evt.touches ? evt.touches[0].clientX : evt.clientX;
    const clientY = evt.touches ? evt.touches[0].clientY : evt.clientY;
    return {
      x: Math.max(0, Math.min(canvas.width, Math.round((clientX - rect.left) * scaleX))),
      y: Math.max(0, Math.min(canvas.height, Math.round((clientY - rect.top) * scaleY)))
    };
  }

  /**
   * Update ROI Status text in helper bar
   */
  function updateRoiStatusUI() {
    if (state.encScope === 'custom') {
      if (DOM.encRoiHelper) DOM.encRoiHelper.style.display = 'flex';
      if (state.customRoi.active && state.customRoi.width > 0 && state.customRoi.height > 0) {
        if (DOM.roiStatusText) {
          DOM.roiStatusText.innerHTML = `<b>Selected ROI:</b> X: ${state.customRoi.x}, Y: ${state.customRoi.y} | <b>Size:</b> ${state.customRoi.width} × ${state.customRoi.height} px (${(state.customRoi.width * state.customRoi.height).toLocaleString()} pixels). Ready to encrypt!`;
        }
        if (DOM.subCustomCount) {
          DOM.subCustomCount.textContent = `${state.customRoi.width}×${state.customRoi.height} px`;
        }
      } else {
        if (DOM.roiStatusText) {
          DOM.roiStatusText.innerHTML = `Click and drag on the <b>Original Image canvas</b> to frame any area (e.g. signature, ID number, confidential text).`;
        }
        if (DOM.subCustomCount) {
          DOM.subCustomCount.textContent = `Drag on canvas`;
        }
      }
    } else {
      if (DOM.encRoiHelper) DOM.encRoiHelper.style.display = 'none';
    }
  }

  /**
   * Draw exact non-rectangular silhouette mask, custom ROI box, and glowing boundary contours
   */
  function renderEncOriginalWithOverlays() {
    if (!state.encImage) return;
    renderToCanvas(state.encImage, DOM.canvasEncOrig, DOM.phEncOrig);

    const canvas = DOM.canvasEncOrig;
    const ctx = canvas.getContext('2d');
    const W = canvas.width;
    const H = canvas.height;

    const scale = Math.max(1, W / 900);
    const t = Math.max(1, Math.round(scale * 1.5)); // contour line thickness in image pixels
    const scope = state.encScope;

    // 1. Entire Image Scope
    if (scope === 'full') {
      ctx.save();
      ctx.strokeStyle = 'rgba(37, 99, 235, 0.6)';
      ctx.lineWidth = Math.max(3, Math.floor(4 * scale));
      ctx.setLineDash([12, 8]);
      ctx.strokeRect(0, 0, W, H);
      ctx.restore();
      return;
    }

    // 2. Custom Drag & Select ROI Scope
    if (scope === 'custom') {
      if (state.customRoi.active && state.customRoi.width > 0 && state.customRoi.height > 0) {
        const { x, y, width: w, height: h } = state.customRoi;
        
        ctx.save();
        // Translucent golden fill
        ctx.fillStyle = 'rgba(245, 158, 11, 0.22)';
        ctx.fillRect(x, y, w, h);

        // Dashed glowing border
        ctx.strokeStyle = '#f59e0b';
        ctx.lineWidth = Math.max(2.5, Math.floor(3.5 * scale));
        ctx.setLineDash([8, 6]);
        ctx.strokeRect(x, y, w, h);

        // Corner grab anchors
        const handleRadius = Math.max(4, Math.floor(6 * scale));
        ctx.fillStyle = '#f59e0b';
        const corners = [
          [x, y], [x + w, y], [x, y + h], [x + w, y + h],
          [x + w / 2, y], [x + w / 2, y + h], [x, y + h / 2], [x + w, y + h / 2]
        ];
        corners.forEach(([cx, cy]) => {
          ctx.beginPath();
          ctx.arc(cx, cy, handleRadius, 0, Math.PI * 2);
          ctx.fill();
        });

        // Floating pill badge
        const fontSize = Math.max(12, Math.floor(14 * scale));
        const pillH = Math.max(24, Math.floor(28 * scale));
        ctx.font = `bold ${fontSize}px sans-serif`;
        const text = `📐 Custom ROI (${w} × ${h} px)`;
        const textW = ctx.measureText(text).width;
        const bx = Math.max(10, Math.min(W - textW - 24, x));
        const by = Math.max(10, y > pillH + 10 ? y - pillH - 6 : y + h + 8);

        ctx.fillStyle = '#d97706';
        ctx.beginPath();
        ctx.roundRect ? ctx.roundRect(bx, by, textW + 20, pillH, 6) : ctx.rect(bx, by, textW + 20, pillH);
        ctx.fill();
        ctx.fillStyle = '#ffffff';
        ctx.fillText(text, bx + 10, by + fontSize + 4);
        ctx.restore();
      }
      return;
    }

    // 3. Neural Body & Face Contour Overlays
    const overlayCanvas = document.createElement('canvas');
    overlayCanvas.width = W;
    overlayCanvas.height = H;
    const oCtx = overlayCanvas.getContext('2d');
    const overlayImgData = oCtx.createImageData(W, H);
    const overlayBuf = overlayImgData.data;

    const showBody = (scope === 'person') && state.bodyMask;
    const showFace = (scope === 'face') && state.faceMask;

    if (showBody) {
      const mask = state.bodyMask;
      for (let y = 0; y < H; y++) {
        for (let x = 0; x < W; x++) {
          const idx = y * W + x;
          if (mask[idx] === 1) {
            const bufIdx = idx * 4;
            const isEdge = (
              x < t || x >= W - t || y < t || y >= H - t ||
              mask[idx - t] === 0 || mask[idx + t] === 0 ||
              mask[idx - t * W] === 0 || mask[idx + t * W] === 0
            );

            if (isEdge) {
              overlayBuf[bufIdx] = 37;      // R
              overlayBuf[bufIdx + 1] = 99;  // G
              overlayBuf[bufIdx + 2] = 235; // B
              overlayBuf[bufIdx + 3] = 255; // Alpha
            } else {
              overlayBuf[bufIdx] = 37;
              overlayBuf[bufIdx + 1] = 99;
              overlayBuf[bufIdx + 2] = 235;
              overlayBuf[bufIdx + 3] = 48; // Translucent tint
            }
          }
        }
      }
    }

    if (showFace) {
      const mask = state.faceMask;
      for (let y = 0; y < H; y++) {
        for (let x = 0; x < W; x++) {
          const idx = y * W + x;
          if (mask[idx] === 1) {
            const bufIdx = idx * 4;
            const isEdge = (
              x < t || x >= W - t || y < t || y >= H - t ||
              mask[idx - t] === 0 || mask[idx + t] === 0 ||
              mask[idx - t * W] === 0 || mask[idx + t * W] === 0
            );

            if (isEdge) {
              overlayBuf[bufIdx] = 5;       // R
              overlayBuf[bufIdx + 1] = 150; // G
              overlayBuf[bufIdx + 2] = 105; // B
              overlayBuf[bufIdx + 3] = 255; // Solid contour
            } else {
              overlayBuf[bufIdx] = 5;
              overlayBuf[bufIdx + 1] = 150;
              overlayBuf[bufIdx + 2] = 105;
              overlayBuf[bufIdx + 3] = 75; // Emerald tint
            }
          }
        }
      }
    }

    oCtx.putImageData(overlayImgData, 0, 0);

    ctx.save();
    ctx.shadowColor = (scope === 'face') ? 'rgba(5, 150, 105, 0.6)' : 'rgba(37, 99, 235, 0.6)';
    ctx.shadowBlur = Math.max(6, Math.floor(10 * scale));
    ctx.drawImage(overlayCanvas, 0, 0);
    ctx.restore();

    const fontSize = Math.max(12, Math.floor(14 * scale));
    const pillH = Math.max(24, Math.floor(28 * scale));
    ctx.font = `bold ${fontSize}px sans-serif`;

    if (showBody && state.detectedBodyStats.pixelCount > 0) {
      const text = `👤 Body Silhouette (${state.detectedBodyStats.coveragePct}%)`;
      const textW = ctx.measureText(text).width;
      const bx = Math.max(10, Math.min(W - textW - 24, state.detectedBodyStats.topX - textW / 2));
      const by = Math.max(10, state.detectedBodyStats.topY - pillH - 6);

      ctx.save();
      ctx.fillStyle = '#2563eb';
      ctx.beginPath();
      ctx.roundRect ? ctx.roundRect(bx, by, textW + 20, pillH, 6) : ctx.rect(bx, by, textW + 20, pillH);
      ctx.fill();
      ctx.fillStyle = '#ffffff';
      ctx.fillText(text, bx + 10, by + fontSize + 4);
      ctx.restore();
    }

    if (showFace && state.detectedFaceStats.pixelCount > 0) {
      const faces = Array.isArray(state.detectedFaces) && state.detectedFaces.length > 0
        ? state.detectedFaces
        : [{ index: 1, cx: state.detectedFaceStats.topX, topY: state.detectedFaceStats.topY }];

      if (faces.length > 1) {
        // Draw compact edge-traced badge above each detected face
        const smallFont = Math.max(11, Math.floor(12.5 * scale));
        const smallPillH = Math.max(20, Math.floor(23 * scale));
        ctx.font = `bold ${smallFont}px sans-serif`;
        faces.forEach((f, i) => {
          const label = `Face #${i + 1}`;
          const tw = ctx.measureText(label).width;
          const fx = Math.max(6, Math.min(W - tw - 16, f.cx - (tw + 16) / 2));
          const fy = Math.max(6, f.topY - smallPillH - 5);
          ctx.save();
          ctx.fillStyle = 'rgba(5, 150, 105, 0.92)';
          ctx.beginPath();
          ctx.roundRect ? ctx.roundRect(fx, fy, tw + 16, smallPillH, 5) : ctx.rect(fx, fy, tw + 16, smallPillH);
          ctx.fill();
          ctx.fillStyle = '#ffffff';
          ctx.fillText(label, fx + 8, fy + smallFont + 3);
          ctx.restore();
        });
      } else {
        const text = `😀 Face Contour (${state.detectedFaceStats.coveragePct}%)`;
        const textW = ctx.measureText(text).width;
        const fx = Math.max(10, Math.min(W - textW - 24, state.detectedFaceStats.topX - textW / 2));
        const fy = Math.max(10, state.detectedFaceStats.topY - pillH - 6);

        ctx.save();
        ctx.fillStyle = '#059669';
        ctx.beginPath();
        ctx.roundRect ? ctx.roundRect(fx, fy, textW + 20, pillH, 6) : ctx.rect(fx, fy, textW + 20, pillH);
        ctx.fill();
        ctx.fillStyle = '#ffffff';
        ctx.fillText(text, fx + 10, fy + fontSize + 4);
        ctx.restore();
      }
    }
  }

  /**
   * Get active target mask or bounding box based on user scope selection
   */
  function getActiveScopeMask() {
    if (state.encScope === 'person') {
      return state.bodyMask;
    } else if (state.encScope === 'face') {
      return state.faceMask;
    } else if (state.encScope === 'custom' && state.customRoi.active && state.customRoi.width > 0 && state.customRoi.height > 0) {
      return [{
        x: state.customRoi.x,
        y: state.customRoi.y,
        width: state.customRoi.width,
        height: state.customRoi.height
      }];
    }
    return null; // Entire Image
  }

  /* ==========================================================================
     Encryption Metadata (auto-detect scope & key type during decryption)
     --------------------------------------------------------------------------
     The exact pixel mask / ROI used for encryption is stored in a PNG "tEXt"
     chunk (keyword "BitShield"). Pixel data is untouched, so restoration stays
     100% lossless, and the Decrypt tab never needs to ask for a scope.
     ========================================================================== */
  const META_KEYWORD = 'BitShield';
  const SCOPE_LABELS = { full: 'Entire Image', person: 'Body Silhouette', face: 'Face Contour', custom: 'Custom ROI' };

  function bytesToBase64(bytes) {
    let bin = '';
    const CHUNK = 0x8000;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return btoa(bin);
  }

  function base64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // Run-length encode a binary mask (alternating runs, starting with 0s) as LEB128 varints.
  function encodeMaskRLE(mask) {
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
    return bytesToBase64(Uint8Array.from(bytes));
  }

  function decodeMaskRLE(b64, total) {
    const bytes = base64ToBytes(b64);
    const mask = new Uint8Array(total);
    let pos = 0, cur = 0, i = 0;
    while (i < bytes.length && pos < total) {
      let v = 0, shift = 0, b;
      do { b = bytes[i++]; v |= (b & 0x7F) << shift; shift += 7; } while (b & 0x80 && i < bytes.length);
      v >>>= 0;
      if (cur === 1) mask.fill(1, pos, Math.min(total, pos + v));
      pos += v;
      cur ^= 1;
    }
    return mask;
  }

  // Build in-memory metadata from the mask actually passed to the encryptor.
  function buildEncryptionMeta(scope, activeMask, keyType, w, h) {
    const meta = { scope, keyType, w, h, mask: null, roi: null };
    if (activeMask instanceof Uint8Array) {
      meta.mask = new Uint8Array(activeMask);
    } else if (Array.isArray(activeMask) && activeMask[0]) {
      const r = activeMask[0];
      meta.roi = { x: r.x, y: r.y, width: r.width, height: r.height };
    } else {
      meta.scope = 'full';
    }
    return meta;
  }

  function serializeMeta(meta) {
    const obj = { v: 1, scope: meta.scope, keyType: meta.keyType, w: meta.w, h: meta.h };
    if (meta.mask) obj.rle = encodeMaskRLE(meta.mask);
    if (meta.roi) obj.roi = meta.roi;
    return JSON.stringify(obj);
  }

  function parseMeta(text) {
    const obj = JSON.parse(text);
    if (!obj || obj.v !== 1 || !obj.w || !obj.h) return null;
    return {
      scope: obj.scope || 'full',
      keyType: obj.keyType === 'image' ? 'image' : 'text',
      w: obj.w,
      h: obj.h,
      mask: obj.rle ? decodeMaskRLE(obj.rle, obj.w * obj.h) : null,
      roi: obj.roi || null
    };
  }

  function getMetaDecryptionMask(meta) {
    if (!meta) return null;
    if (meta.mask) return meta.mask;
    if (meta.roi) return [meta.roi];
    return null; // Entire image
  }

  // --- Minimal PNG chunk read/write ---
  const CRC_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      t[n] = c >>> 0;
    }
    return t;
  })();

  function crc32(bytes) {
    let c = 0xFFFFFFFF;
    for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
    return (c ^ 0xFFFFFFFF) >>> 0;
  }

  function isPngBytes(bytes) {
    const sig = [137, 80, 78, 71, 13, 10, 26, 10];
    return bytes.length > 8 && sig.every((b, i) => bytes[i] === b);
  }

  function chunkType(bytes, offset) {
    return String.fromCharCode(bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7]);
  }

  function embedPngTextChunk(pngBytes, keyword, text) {
    if (!isPngBytes(pngBytes)) return pngBytes;
    const dv = new DataView(pngBytes.buffer, pngBytes.byteOffset, pngBytes.byteLength);
    let offset = 8, iendPos = -1;
    while (offset + 8 <= pngBytes.length) {
      const len = dv.getUint32(offset);
      if (chunkType(pngBytes, offset) === 'IEND') { iendPos = offset; break; }
      offset += 12 + len;
    }
    if (iendPos < 0) return pngBytes;

    const enc = new TextEncoder();
    const kw = enc.encode(keyword);
    const tx = enc.encode(text);
    const data = new Uint8Array(kw.length + 1 + tx.length);
    data.set(kw, 0);
    data[kw.length] = 0;
    data.set(tx, kw.length + 1);

    const chunk = new Uint8Array(12 + data.length);
    const cdv = new DataView(chunk.buffer);
    cdv.setUint32(0, data.length);
    chunk.set([0x74, 0x45, 0x58, 0x74], 4); // "tEXt"
    chunk.set(data, 8);
    cdv.setUint32(8 + data.length, crc32(chunk.subarray(4, 8 + data.length)));

    const out = new Uint8Array(pngBytes.length + chunk.length);
    out.set(pngBytes.subarray(0, iendPos), 0);
    out.set(chunk, iendPos);
    out.set(pngBytes.subarray(iendPos), iendPos + chunk.length);
    return out;
  }

  function readPngTextChunk(bytes, keyword) {
    if (!isPngBytes(bytes)) return null;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const dec = new TextDecoder();
    let offset = 8;
    while (offset + 12 <= bytes.length) {
      const len = dv.getUint32(offset);
      const type = chunkType(bytes, offset);
      if (offset + 12 + len > bytes.length) break;
      if (type === 'tEXt') {
        const data = bytes.subarray(offset + 8, offset + 8 + len);
        const nul = data.indexOf(0);
        if (nul > 0 && dec.decode(data.subarray(0, nul)) === keyword) {
          return dec.decode(data.subarray(nul + 1));
        }
      }
      if (type === 'IEND') break;
      offset += 12 + len;
    }
    return null;
  }

  /* ==========================================================================
     Tab 1: Encrypt Scope Controls & Drag Event Listeners
     ========================================================================== */
  function setScope(scopeKey, targetBtn) {
    state.encScope = scopeKey;
    [DOM.btnScopeFull, DOM.btnScopePerson, DOM.btnScopeFace, DOM.btnScopeCustom].forEach(b => {
      if (b) b.classList.remove('active');
    });
    if (targetBtn) targetBtn.classList.add('active');

    // Update cursor styling on canvas container
    const compBox = DOM.canvasEncOrig ? DOM.canvasEncOrig.parentElement : null;
    if (compBox) {
      if (scopeKey === 'custom') compBox.classList.add('drawing-roi');
      else compBox.classList.remove('drawing-roi');
    }

    updateRoiStatusUI();
    renderEncOriginalWithOverlays();
  }

  if (DOM.btnScopeFull) DOM.btnScopeFull.addEventListener('click', () => setScope('full', DOM.btnScopeFull));
  if (DOM.btnScopePerson) DOM.btnScopePerson.addEventListener('click', () => setScope('person', DOM.btnScopePerson));
  if (DOM.btnScopeFace) DOM.btnScopeFace.addEventListener('click', () => setScope('face', DOM.btnScopeFace));
  if (DOM.btnScopeCustom) DOM.btnScopeCustom.addEventListener('click', () => setScope('custom', DOM.btnScopeCustom));

  if (DOM.btnClearRoi) {
    DOM.btnClearRoi.addEventListener('click', () => {
      state.customRoi = { x: 0, y: 0, width: 0, height: 0, active: false };
      updateRoiStatusUI();
      renderEncOriginalWithOverlays();
    });
  }

  // Interactive Drag & Select ROI on canvasEncOrig
  if (DOM.canvasEncOrig) {
    const handleDragStart = (e) => {
      if (!state.encImage) return;
      state.isDraggingRoi = true;
      state.dragStart = getCanvasPixelCoords(DOM.canvasEncOrig, e);
      state.customRoi = { x: state.dragStart.x, y: state.dragStart.y, width: 0, height: 0, active: true };
      if (state.encScope !== 'custom') {
        setScope('custom', DOM.btnScopeCustom);
      }
    };

    const handleDragMove = (e) => {
      if (!state.isDraggingRoi || !state.encImage) return;
      const current = getCanvasPixelCoords(DOM.canvasEncOrig, e);
      const rx = Math.min(state.dragStart.x, current.x);
      const ry = Math.min(state.dragStart.y, current.y);
      const rw = Math.abs(current.x - state.dragStart.x);
      const rh = Math.abs(current.y - state.dragStart.y);
      state.customRoi = { x: rx, y: ry, width: rw, height: rh, active: true };
      renderEncOriginalWithOverlays();
      updateRoiStatusUI();
    };

    const handleDragEnd = () => {
      if (!state.isDraggingRoi) return;
      state.isDraggingRoi = false;
      if (state.customRoi.width < 5 || state.customRoi.height < 5) {
        state.customRoi.active = false;
      }
      renderEncOriginalWithOverlays();
      updateRoiStatusUI();
    };

    DOM.canvasEncOrig.addEventListener('mousedown', handleDragStart);
    window.addEventListener('mousemove', (e) => {
      if (state.isDraggingRoi) handleDragMove(e);
    });
    window.addEventListener('mouseup', handleDragEnd);

    DOM.canvasEncOrig.addEventListener('touchstart', (e) => {
      e.preventDefault();
      handleDragStart(e);
    }, { passive: false });
    DOM.canvasEncOrig.addEventListener('touchmove', (e) => {
      if (state.isDraggingRoi) {
        e.preventDefault();
        handleDragMove(e);
      }
    }, { passive: false });
    DOM.canvasEncOrig.addEventListener('touchend', handleDragEnd);
  }

  // Encrypt Tab: Image Upload & Dropzone Handling
  function handleEncImageUpload(file) {
    if (!file) return;
    const base = (file.name || 'image').replace(/\.[^/.]+$/, '');
    state.encFileName = base || 'image';
    loadImage(file, (img) => {
      state.encImage = img;
      state.customRoi = { x: 0, y: 0, width: 0, height: 0, active: false };
      renderToCanvas(img, DOM.canvasEncOrig, DOM.phEncOrig);

      // Refresh view: Clear previous encrypted result, metrics & download button
      clearEncryptedResultView();

      // Refresh key source selection: Reset to Text Password, clear inputs & badges
      refreshEncKeySourceUI();

      updateEncButtonState();
      updateRoiStatusUI();

      // Run Neural Body & Face Contour Segmentation
      runAISegmentation(img);
    });
  }

  if (DOM.encFileInput) {
    DOM.encFileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        handleEncImageUpload(e.target.files[0]);
      }
      e.target.value = '';
    });
  }

  if (DOM.encDropZone) {
    DOM.encDropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      DOM.encDropZone.classList.add('dragover');
    });
    DOM.encDropZone.addEventListener('dragleave', () => {
      DOM.encDropZone.classList.remove('dragover');
    });
    DOM.encDropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      DOM.encDropZone.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleEncImageUpload(e.dataTransfer.files[0]);
      }
    });
  }

  // Encrypt Process Execution (3-Stage Pipeline)
  DOM.btnProcessEncrypt.addEventListener('click', async (e) => {
    if (!state.encImage) return;

    // 1. If Text Password mode: Validate password entered
    if (state.encKeyType === 'text') {
      const pwdVal = DOM.encPassword ? DOM.encPassword.value.trim() : '';
      if (!pwdVal) {
        e.preventDefault();
        if (DOM.encPassword) {
          DOM.encPassword.classList.add('input-invalid');
          DOM.encPassword.focus();
          setTimeout(() => DOM.encPassword.classList.remove('input-invalid'), 1200);
        }
        alert("Please enter a password first to encrypt the image!");
        return;
      }
    }

    // 2. If Image Key mode: Validate key image is uploaded
    if (state.encKeyType === 'image' && !state.encKeyImage) {
      e.preventDefault();
      if (DOM.encKeyImageDropzone) {
        DOM.encKeyImageDropzone.scrollIntoView({ behavior: 'smooth', block: 'center' });
        DOM.encKeyImageDropzone.classList.add('highlight-pulse');
        setTimeout(() => DOM.encKeyImageDropzone.classList.remove('highlight-pulse'), 1500);
      }
      if (DOM.encKeyImageInput) DOM.encKeyImageInput.click();
      alert("Please upload an image to use as your encryption key before encrypting!");
      return;
    }

    // Resolve key from text password OR key image
    let effectiveKey = '';
    if (state.encKeyType === 'image') {
      effectiveKey = state.encKeyImage.hex;
    } else {
      effectiveKey = DOM.encPassword.value;
    }

    DOM.btnProcessEncrypt.disabled = true;
    DOM.btnProcessEncrypt.classList.remove('btn-key-needed');
    DOM.btnProcessEncrypt.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Encrypting & Packing .msbx (100k SHA-256)...';

    setTimeout(async () => {
      try {
        // Temporary canvas to read original clean pixels without overlays
        const tempCanvas = document.createElement('canvas');
        tempCanvas.width = state.encImage.width;
        tempCanvas.height = state.encImage.height;
        const tempCtx = tempCanvas.getContext('2d');
        tempCtx.drawImage(state.encImage, 0, 0);

        const imgData = tempCtx.getImageData(0, 0, tempCanvas.width, tempCanvas.height);
        const activeMask = getActiveScopeMask();
        const kVal = DOM.encKSelect ? (parseInt(DOM.encKSelect.value, 10) || 2) : 2;

        // Cache original copy for ground-truth fidelity verification in Decrypt tab
        state.lastOriginalImageData = new ImageData(
          new Uint8ClampedArray(imgData.data),
          imgData.width,
          imgData.height
        );
        state.lastEncryptedScope = state.encScope;
        state.lastEncryptedPassword = DOM.encPassword.value;
        state.lastEncryptedKeyType = state.encKeyType;
        state.lastEncryptedKeyImage = state.encKeyImage ? { ...state.encKeyImage } : null;
        state.lastEncryptedRoi = (state.encScope === 'custom' && state.customRoi.active) ? { ...state.customRoi } : null;
        state.lastEncryptedMeta = buildEncryptionMeta(
          state.encScope,
          activeMask,
          state.encKeyType,
          imgData.width,
          imgData.height
        );

        // Execute Chapter 4 3-Stage Reversible Encryption & Pack Portable .msbx Container
        const result = await BitEngine.encryptToMSBX(imgData, effectiveKey, activeMask, {
          k: kVal,
          iterations: BitEngine.DEFAULT_KDF_ITERATIONS,
          keyType: state.encKeyType === 'image' ? 'image' : 'text',
          scope: state.encScope
        });

        // Cache encrypted .msbx binary container & preview ImageData
        state.lastEncryptedMSBX = result.msbxBytes;
        state.lastEncryptedHeader = result.header;
        state.lastEncryptedImageData = new ImageData(
          new Uint8ClampedArray(result.imageData.data),
          result.imageData.width,
          result.imageData.height
        );

        const canvas = DOM.canvasEncResult;
        renderToCanvas(state.encImage, canvas, DOM.phEncResult);
        const ctx = canvas.getContext('2d');
        ctx.putImageData(result.imageData, 0, 0);

        // Metrics display
        DOM.valEncMse.textContent = result.mse;
        DOM.valEncPsnr.textContent = result.psnr + (result.psnr === '∞' ? '' : ' dB');
        DOM.valEncSwapped.textContent = result.swappedCount.toLocaleString();
        DOM.encMetrics.style.display = 'flex';

        if (DOM.btnDownloadMsbx) DOM.btnDownloadMsbx.disabled = false;
        if (DOM.btnDownloadEncrypted) DOM.btnDownloadEncrypted.disabled = false;
        renderMsbxHeaderCard(
          DOM.encMsbxInfo,
          result.header,
          result.msbxBytes.byteLength,
          'Generated Portable .msbx Container (68-Byte Header)'
        );
      } catch (err) {
        console.error('Encryption failed:', err);
        alert('Encryption failed: ' + (err && err.message ? err.message : String(err)));
      } finally {
        updateEncButtonState();
      }
    }, 50);
  });

  // Download Portable .msbx Container File
  if (DOM.btnDownloadMsbx) {
    DOM.btnDownloadMsbx.addEventListener('click', () => {
      if (!state.lastEncryptedMSBX) {
        alert('Please encrypt an image first to generate a portable .msbx container.');
        return;
      }
      const blob = new Blob([state.lastEncryptedMSBX], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.download = `${state.encFileName || 'encrypted'}.msbx`;
      link.href = url;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    });
  }

  // Export Quality Slider & Secondary Preview Image Download
  DOM.encExportFormat.addEventListener('change', (e) => {
    DOM.jpegQualityGroup.style.display = (e.target.value === 'image/jpeg') ? 'block' : 'none';
  });

  DOM.encQuality.addEventListener('input', (e) => {
    DOM.qualityVal.textContent = e.target.value;
  });

  DOM.btnDownloadEncrypted.addEventListener('click', () => {
    const format = DOM.encExportFormat.value;
    const quality = parseFloat(DOM.encQuality.value);
    const canvas = DOM.canvasEncResult;
    const ext = format.split('/')[1] === 'jpeg' ? 'jpg' : format.split('/')[1];

    if (format === 'image/bmp' && state.lastEncryptedImageData) {
      const bmpBlob = BitEngine.imageDataToBMPBlob(state.lastEncryptedImageData);
      const url = URL.createObjectURL(bmpBlob);
      const link = document.createElement('a');
      link.download = `${state.encFileName || 'encrypted'}_preview.bmp`;
      link.href = url;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
      return;
    }

    // When exporting preview as PNG, embed the BitShield metadata chunk
    if (format === 'image/png' && state.lastEncryptedMeta) {
      try {
        const dataUrl = canvas.toDataURL('image/png');
        const b64 = dataUrl.split(',')[1];
        const pngBytes = base64ToBytes(b64);
        const withMeta = embedPngTextChunk(pngBytes, META_KEYWORD, serializeMeta(state.lastEncryptedMeta));
        const blob = new Blob([withMeta], { type: 'image/png' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.download = `${state.encFileName || 'encrypted'}_preview.png`;
        link.href = url;
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 5000);
        return;
      } catch (err) {
        console.warn('Metadata chunk embed fallback:', err);
      }
    }

    const link = document.createElement('a');
    link.download = `${state.encFileName || 'encrypted'}_preview.${ext}`;
    link.href = canvas.toDataURL(format, quality);
    link.click();
  });

  // Preview Tabs Toggle (Side-by-Side vs Encrypted Only)
  const prevTabs = document.querySelectorAll('.prev-tab');
  if (prevTabs.length > 0) {
    prevTabs.forEach(btn => {
      btn.addEventListener('click', () => {
        prevTabs.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const view = btn.getAttribute('data-view');
        const comp = document.getElementById('enc-comparison');
        if (comp) {
          const origBox = comp.querySelector('.comp-box:first-child');
          const resBox = comp.querySelector('.comp-box:last-child');
          if (view === 'result') {
            if (origBox) origBox.style.display = 'none';
            if (resBox) resBox.classList.add('full-width');
          } else {
            if (origBox) origBox.style.display = 'flex';
            if (resBox) resBox.classList.remove('full-width');
          }
        }
      });
    });
  }

  /* ==========================================================================
     Tab 2: Decrypt & Restore Logic (.msbx Container + Auto-Detected Region & Key)
     ========================================================================== */
  function updateDecScopeBanner(meta) {
    if (!DOM.decScopeInfo || !DOM.decScopeInfoText) return;
    if (!meta) {
      DOM.decScopeInfo.style.display = 'none';
      return;
    }
    const label = SCOPE_LABELS[meta.scope] || 'Entire Image';
    const keyHint = meta.keyType === 'image'
      ? 'Encrypted with an <b>Image Key</b> — upload the matching key image below (or enter password).'
      : 'Enter your password or upload your key image below to decrypt and verify the SHA-256 tag.';
    DOM.decScopeInfo.className = 'dec-scope-info';
    DOM.decScopeInfo.style.display = 'flex';
    DOM.decScopeInfoText.innerHTML = `<b>Auto-detected encrypted region:</b> ${label}. ${keyHint}`;
  }

  function renderImageDataToCanvas(imgData, canvas, placeholder) {
    if (!canvas || !imgData) return;
    const ctx = canvas.getContext('2d');
    canvas.style.display = 'block';
    canvas.width = imgData.width;
    canvas.height = imgData.height;
    ctx.putImageData(imgData, 0, 0);
    if (placeholder) placeholder.style.display = 'none';
  }

  function loadMsbxIntoDecryptTab(msbxBytes, sourceName) {
    hideDecError();
    clearDecryptedResultView();

    try {
      const inspected = BitEngine.inspectMSBX(msbxBytes);
      state.decMsbxBytes = new Uint8Array(msbxBytes);
      state.decMsbxHeader = inspected.header;
      state.decImage = null;
      state.decFileName = (sourceName || 'restored_photo').replace(/\.[^/.]+$/, '') || 'restored_photo';
      state.decMeta = {
        scope: inspected.header.scope || 'full',
        keyType: inspected.header.keyType || 'text',
        w: inspected.header.width,
        h: inspected.header.height,
        mask: inspected.mask,
        roi: null
      };

      renderImageDataToCanvas(inspected.previewImageData, DOM.canvasDecOrig, DOM.phDecOrig);
      refreshDecKeySourceUI();
      renderMsbxHeaderCard(
        DOM.decMsbxMeta,
        inspected.header,
        msbxBytes.byteLength,
        `Loaded .msbx Container (${sourceName || 'encrypted.msbx'})`
      );
      updateDecScopeBanner(state.decMeta);
      updateDecButtonState();
    } catch (err) {
      state.decMsbxBytes = null;
      state.decMsbxHeader = null;
      state.decImage = null;
      state.decMeta = null;
      clearCanvasAndShowPlaceholder(DOM.canvasDecOrig, DOM.phDecOrig);
      clearDecryptedResultView();
      if (DOM.decMsbxMeta) {
        DOM.decMsbxMeta.style.display = 'none';
        DOM.decMsbxMeta.innerHTML = '';
      }
      if (DOM.decScopeInfo) DOM.decScopeInfo.style.display = 'none';
      const msg = err && err.message ? err.message : String(err);
      showDecError('Invalid or Corrupted .msbx Container', msg);
      updateDecButtonState();
      alert(msg);
    }
  }

  // 1-Click Test: Transfer encrypted .msbx container from Encrypt Tab to Decrypt Tab
  if (DOM.btnUseEncryptedFromEnc) {
    DOM.btnUseEncryptedFromEnc.addEventListener('click', () => {
      if (state.lastEncryptedMSBX) {
        loadMsbxIntoDecryptTab(state.lastEncryptedMSBX, `${state.encFileName || 'encrypted'}.msbx`);
        return;
      }

      if (!state.lastEncryptedImageData) {
        alert("Please execute encryption on an image in the Encrypt Tab first!");
        return;
      }

      const tempCanvas = document.createElement('canvas');
      tempCanvas.width = state.lastEncryptedImageData.width;
      tempCanvas.height = state.lastEncryptedImageData.height;
      const tCtx = tempCanvas.getContext('2d');
      tCtx.putImageData(state.lastEncryptedImageData, 0, 0);

      const img = new Image();
      img.onload = () => {
        hideDecError();
        state.decMsbxBytes = null;
        state.decMsbxHeader = null;
        if (DOM.decMsbxMeta) DOM.decMsbxMeta.style.display = 'none';
        state.decImage = img;
        state.decMeta = state.lastEncryptedMeta || {
          scope: 'full',
          keyType: state.lastEncryptedKeyType || 'text',
          w: img.width,
          h: img.height,
          mask: null,
          roi: null
        };
        renderToCanvas(img, DOM.canvasDecOrig, DOM.phDecOrig);
        clearDecryptedResultView();
        refreshDecKeySourceUI();
        updateDecScopeBanner(state.decMeta);
        updateDecButtonState();
      };
      img.src = tempCanvas.toDataURL('image/png');
    });
  }

  function isKnownRasterSignature(bytes) {
    if (!bytes || bytes.length < 4) return false;
    // PNG: 89 50 4E 47
    if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) return true;
    // BMP: 42 4D ("BM")
    if (bytes[0] === 0x42 && bytes[1] === 0x4D) return true;
    // JPEG: FF D8 FF
    if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) return true;
    // WEBP: "RIFF"...."WEBP"
    if (bytes.length >= 12 &&
        bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
        bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) return true;
    // GIF: "GIF8"
    if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) return true;
    return false;
  }

  async function handleDecImageUpload(file) {
    if (!file) return;

    let rawBytes = null;
    try {
      const buf = await file.arrayBuffer();
      rawBytes = new Uint8Array(buf);
    } catch (err) {
      showDecError('File Read Error', 'Could not read the uploaded file.');
      return;
    }

    const isMsbxExt = /\.msbx$/i.test(file.name || '');
    const isMsbxMagic = rawBytes.length >= 4 &&
      rawBytes[0] === 0x4D && rawBytes[1] === 0x53 && rawBytes[2] === 0x42 && rawBytes[3] === 0x58;

    // Route .msbx files (or non-raster binary containers) through the Chapter 4 .msbx parser
    if (isMsbxExt || isMsbxMagic || !isKnownRasterSignature(rawBytes)) {
      loadMsbxIntoDecryptTab(rawBytes, file.name);
      return;
    }

    // Legacy fallback: lossless PNG / BMP image upload
    hideDecError();
    state.decMsbxBytes = null;
    state.decMsbxHeader = null;
    if (DOM.decMsbxMeta) {
      DOM.decMsbxMeta.style.display = 'none';
      DOM.decMsbxMeta.innerHTML = '';
    }

    let embeddedMeta = null;
    try {
      const rawText = readPngTextChunk(rawBytes, META_KEYWORD);
      if (rawText) embeddedMeta = parseMeta(rawText);
    } catch (e) {
      embeddedMeta = null;
    }

    loadImage(file, (img) => {
      state.decImage = img;
      state.decFileName = (file.name || 'restored_photo').replace(/\.[^/.]+$/, '') || 'restored_photo';
      renderToCanvas(img, DOM.canvasDecOrig, DOM.phDecOrig);
      clearDecryptedResultView();
      refreshDecKeySourceUI();

      if (embeddedMeta && embeddedMeta.w === img.width && embeddedMeta.h === img.height) {
        state.decMeta = embeddedMeta;
      } else if (state.lastEncryptedMeta &&
                 state.lastEncryptedMeta.w === img.width &&
                 state.lastEncryptedMeta.h === img.height) {
        state.decMeta = state.lastEncryptedMeta;
      } else {
        state.decMeta = { scope: 'full', keyType: 'text', w: img.width, h: img.height, mask: null, roi: null };
      }

      updateDecScopeBanner(state.decMeta);
      updateDecButtonState();
    });
  }

  if (DOM.decFileInput) {
    DOM.decFileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        handleDecImageUpload(e.target.files[0]);
      }
      e.target.value = '';
    });
  }

  if (DOM.decDropZone) {
    DOM.decDropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      DOM.decDropZone.classList.add('dragover');
    });
    DOM.decDropZone.addEventListener('dragleave', () => {
      DOM.decDropZone.classList.remove('dragover');
    });
    DOM.decDropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      DOM.decDropZone.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleDecImageUpload(e.dataTransfer.files[0]);
      }
    });
  }

  DOM.btnProcessDecrypt.addEventListener('click', async (e) => {
    if (!state.decImage && !state.decMsbxBytes) return;

    const pwdVal = DOM.decPassword ? DOM.decPassword.value.trim() : '';
    const hasPwd = pwdVal.length > 0;
    const hasImgKey = !!state.decKeyImage;

    if (!hasPwd && !hasImgKey) {
      e.preventDefault();
      if (DOM.decPassword) {
        DOM.decPassword.classList.add('input-invalid');
        DOM.decPassword.focus();
        setTimeout(() => DOM.decPassword.classList.remove('input-invalid'), 1200);
      }
      alert("Please enter the decryption password OR upload the key image to decrypt!");
      return;
    }

    // Resolve candidate key(s): if both are supplied, try the header's keyType first
    let primaryKey = '';
    let fallbackKey = null;
    if (hasImgKey && hasPwd) {
      if (state.decMeta && state.decMeta.keyType === 'image') {
        primaryKey = state.decKeyImage.hex;
        fallbackKey = DOM.decPassword.value;
      } else {
        primaryKey = DOM.decPassword.value;
        fallbackKey = state.decKeyImage.hex;
      }
    } else if (hasImgKey) {
      primaryKey = state.decKeyImage.hex;
    } else {
      primaryKey = DOM.decPassword.value;
    }

    hideDecError();
    DOM.btnProcessDecrypt.disabled = true;
    DOM.btnProcessDecrypt.classList.remove('btn-key-needed');
    DOM.btnProcessDecrypt.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Verifying SHA-256 Tag & Reversing 3 Stages...';

    setTimeout(async () => {
      try {
        // Path A: Portable .msbx Container Decryption + 32-Byte SHA-256 Tag Verification
        if (state.decMsbxBytes) {
          let result = null;
          try {
            result = await BitEngine.decryptFromMSBX(state.decMsbxBytes, primaryKey);
          } catch (firstErr) {
            if (fallbackKey !== null) {
              result = await BitEngine.decryptFromMSBX(state.decMsbxBytes, fallbackKey);
            } else {
              throw firstErr;
            }
          }

          state.lastDecryptedImageData = new ImageData(
            new Uint8ClampedArray(result.imageData.data),
            result.imageData.width,
            result.imageData.height
          );

          renderImageDataToCanvas(result.imageData, DOM.canvasDecResult, DOM.phDecResult);

          // Check ground-truth fidelity against original image if available in session
          if (state.lastOriginalImageData &&
              state.lastOriginalImageData.width === result.imageData.width &&
              state.lastOriginalImageData.height === result.imageData.height) {
            const fidelity = BitEngine.calculateMetrics(state.lastOriginalImageData, result.imageData);
            DOM.valDecMse.textContent = fidelity.mse.toFixed(4);
            DOM.valDecPsnr.textContent = fidelity.psnr === Infinity ? '∞ dB' : (fidelity.psnr + ' dB');
          } else {
            DOM.valDecMse.textContent = '0.0000';
            DOM.valDecPsnr.textContent = '∞ dB';
          }

          DOM.valDecSwapped.textContent = result.swappedCount.toLocaleString();
          const titleEl = document.getElementById('dec-fidelity-title');
          const descEl = document.getElementById('dec-fidelity-desc');
          if (titleEl) {
            titleEl.textContent = 'SHA-256 Verification Tag Matched • 0 Different Pixels';
          }
          if (descEl) {
            descEl.innerHTML = `68-byte <code>.msbx</code> header verified (${result.header.iterations.toLocaleString()} SHA-256 iterations, <i>k</i> = ${result.header.k}). Exact lossless recovery achieved (<code>MSE = 0.0000</code>, <code>PSNR = ∞ dB</code>).`;
          }

          DOM.decMetrics.style.display = 'flex';
          DOM.decFidelityCard.style.display = 'flex';
          DOM.btnDownloadRestored.disabled = false;
          return;
        }

        // Path B: Legacy Encrypted PNG/BMP Image Decryption
        const tempCanvas = document.createElement('canvas');
        tempCanvas.width = state.decImage.width;
        tempCanvas.height = state.decImage.height;
        const tempCtx = tempCanvas.getContext('2d');
        tempCtx.drawImage(state.decImage, 0, 0);

        const inputImgData = tempCtx.getImageData(0, 0, tempCanvas.width, tempCanvas.height);
        const decMask = getMetaDecryptionMask(state.decMeta);

        const result = await BitEngine.decryptImage(inputImgData, primaryKey, decMask);
        state.lastDecryptedImageData = new ImageData(
          new Uint8ClampedArray(result.imageData.data),
          result.imageData.width,
          result.imageData.height
        );

        renderImageDataToCanvas(result.imageData, DOM.canvasDecResult, DOM.phDecResult);

        if (state.lastOriginalImageData &&
            state.lastOriginalImageData.width === result.imageData.width &&
            state.lastOriginalImageData.height === result.imageData.height) {
          const fidelity = BitEngine.calculateMetrics(state.lastOriginalImageData, result.imageData);
          DOM.valDecMse.textContent = fidelity.mse.toFixed(4);
          DOM.valDecPsnr.textContent = fidelity.psnr === Infinity ? '∞ dB' : (fidelity.psnr + ' dB');
        } else {
          DOM.valDecMse.textContent = result.mse;
          DOM.valDecPsnr.textContent = result.psnr + (result.psnr === '∞' ? '' : ' dB');
        }

        DOM.valDecSwapped.textContent = result.swappedCount.toLocaleString();
        DOM.decMetrics.style.display = 'flex';
        DOM.decFidelityCard.style.display = 'flex';
        DOM.btnDownloadRestored.disabled = false;
      } catch (err) {
        // Never display or allow saving a partially recovered image when verification fails
        clearDecryptedResultView();
        const msg = err && err.message ? err.message : String(err);
        showDecError('Decryption Failed — Image Not Restored', msg);
        alert(msg);
      } finally {
        updateDecButtonState();
      }
    }, 50);
  });

  DOM.btnDownloadRestored.addEventListener('click', () => {
    if (!state.lastDecryptedImageData && (!DOM.canvasDecResult || DOM.canvasDecResult.width === 0)) {
      alert('No verified decrypted image is available to save.');
      return;
    }
    const format = DOM.decExportFormat.value;
    const canvas = DOM.canvasDecResult;
    const baseName = state.decFileName || 'restored_photo';

    // Genuine uncompressed 24-bit Windows BMP export
    if (format === 'image/bmp') {
      const ctx = canvas.getContext('2d');
      const imgData = state.lastDecryptedImageData || ctx.getImageData(0, 0, canvas.width, canvas.height);
      const bmpBlob = BitEngine.imageDataToBMPBlob(imgData);
      const url = URL.createObjectURL(bmpBlob);
      const link = document.createElement('a');
      link.download = `${baseName}_restored.bmp`;
      link.href = url;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
      return;
    }

    const link = document.createElement('a');
    const ext = format.split('/')[1] === 'jpeg' ? 'jpg' : format.split('/')[1];
    link.download = `${baseName}_restored.${ext}`;
    link.href = canvas.toDataURL(format, 0.95);
    link.click();
  });

  /* ==========================================================================
     Tab 3: Invisible Steganography Logic
     ========================================================================== */
  DOM.stegoTypeBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      DOM.stegoTypeBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const type = btn.getAttribute('data-type');
      DOM.stegoEmbedSub.style.display = (type === 'embed') ? 'block' : 'none';
      DOM.stegoExtractSub.style.display = (type === 'extract') ? 'block' : 'none';
    });
  });

  DOM.stegoCoverInput.addEventListener('change', (e) => {
    loadImage(e.target.files[0], (img) => {
      state.stegoCover = img;
      DOM.btnStegoEmbed.disabled = false;
    });
  });

  DOM.stegoStegoInput.addEventListener('change', (e) => {
    loadImage(e.target.files[0], (img) => {
      state.stegoStego = img;
      DOM.btnStegoExtract.disabled = false;
    });
  });

  DOM.btnStegoEmbed.addEventListener('click', async () => {
    if (!state.stegoCover) return;
    const text = DOM.stegoSecretText.value;
    if (!text) {
      alert("Please enter a secret text message to hide.");
      return;
    }

    const canvas = DOM.canvasStegoResult;
    renderToCanvas(state.stegoCover, canvas, DOM.phStegoResult);
    const ctx = canvas.getContext('2d');
    const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    try {
      const embeddedData = await BitEngine.embedStegoPayload(imgData, text, DOM.stegoPwd.value);
      ctx.putImageData(embeddedData, 0, 0);
      DOM.extractedPayloadDisplay.textContent = `[SUCCESS] Message securely embedded into image. (${text.length} characters stored)`;
      DOM.btnDownloadStego.disabled = false;
    } catch (err) {
      alert(err.message);
    }
  });

  DOM.btnStegoExtract.addEventListener('click', async () => {
    if (!state.stegoStego) return;

    const canvas = DOM.canvasStegoResult;
    renderToCanvas(state.stegoStego, canvas, DOM.phStegoResult);
    const ctx = canvas.getContext('2d');
    const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    try {
      const extractedText = await BitEngine.extractStegoPayload(imgData, DOM.stegoExtPwd.value);
      DOM.extractedPayloadDisplay.textContent = extractedText;
    } catch (err) {
      DOM.extractedPayloadDisplay.textContent = `❌ [ERROR] ${err.message}`;
    }
  });

  DOM.btnDownloadStego.addEventListener('click', () => {
    const link = document.createElement('a');
    link.download = 'stego_carrier.png';
    link.href = DOM.canvasStegoResult.toDataURL('image/png');
    link.click();
  });

  /* ==========================================================================
     VIDEO SUITE SHARED BRIDGE (Connects Encrypt Page & Decrypt Page)
     ========================================================================== */
  const FYP_VideoBridge = {
    lastEncryptedBlob: null,
    lastEncryptedUrl: null,
    lastEncryptedName: '',
    lastPassword: '',
    lastAlgo: '3stage',
    lastFps: '24',
    onVideoEncrypted: null
  };

  /* ==========================================================================
     PAGE 1: VIDEO ENCRYPTION MODULE (Upload, Scramble, Preview & Export)
     ========================================================================== */
  function initVideoEncryptModule() {
    const encDOM = {
      dropZone: document.getElementById('video-enc-drop-zone'),
      fileInput: document.getElementById('video-enc-file-input'),
      dropText: document.getElementById('video-enc-drop-text'),
      dropIcon: document.getElementById('video-enc-drop-icon'),
      metaChip: document.getElementById('video-enc-meta-chip'),
      metaName: document.getElementById('meta-video-enc-name'),
      metaDuration: document.getElementById('meta-video-enc-duration'),
      metaRes: document.getElementById('meta-video-enc-res'),
      metaFrames: document.getElementById('meta-video-enc-frames'),
      password: document.getElementById('video-enc-password'),
      togglePwd: document.getElementById('toggle-video-enc-pwd'),
      algoSelect: document.getElementById('video-enc-algo-select'),
      fpsSelect: document.getElementById('video-enc-fps-select'),
      scaleSelect: document.getElementById('video-enc-scale-select'),
      progressBox: document.getElementById('video-enc-progress-box'),
      progressStatus: document.getElementById('video-enc-progress-status'),
      progressPct: document.getElementById('video-enc-progress-pct'),
      progressFill: document.getElementById('video-enc-progress-fill'),
      progressDetails: document.getElementById('video-enc-progress-details'),
      progressEta: document.getElementById('video-enc-progress-eta'),
      btnProcess: document.getElementById('btn-process-video-enc'),
      btnCancel: document.getElementById('btn-cancel-video-enc'),
      origPlayer: document.getElementById('video-enc-orig-player'),
      phOrig: document.getElementById('ph-video-enc-orig'),
      resultPlayer: document.getElementById('video-enc-result-player'),
      phResult: document.getElementById('ph-video-enc-result'),
      origTime: document.getElementById('video-enc-orig-time'),
      resultTime: document.getElementById('video-enc-result-time'),
      liveBox: document.getElementById('video-enc-live-box'),
      liveBadge: document.getElementById('live-frame-enc-badge'),
      canvasThumb: document.getElementById('canvas-video-enc-thumb'),
      btnSyncPlay: document.getElementById('btn-sync-play-enc'),
      btnSyncPause: document.getElementById('btn-sync-pause-enc'),
      btnSyncReset: document.getElementById('btn-sync-reset-enc'),
      metricsBar: document.getElementById('video-enc-metrics-bar'),
      valFrames: document.getElementById('val-video-enc-frames'),
      valSpeed: document.getElementById('val-video-enc-speed'),
      valMse: document.getElementById('val-video-enc-mse'),
      valPsnr: document.getElementById('val-video-enc-psnr'),
      btnDownload: document.getElementById('btn-download-video-enc'),
      btnGotoDecrypt: document.getElementById('btn-goto-decrypt')
    };

    const encState = {
      videoLoaded: false,
      videoFile: null,
      videoUrl: null,
      processedBlob: null,
      processedUrl: null,
      isProcessing: false,
      cancelRequested: false
    };

    if (encDOM.togglePwd && encDOM.password) {
      setupPwdToggle(encDOM.togglePwd, encDOM.password);
    }

    if (encDOM.dropZone && encDOM.fileInput) {
      encDOM.dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        encDOM.dropZone.classList.add('drag-active');
      });

      encDOM.dropZone.addEventListener('dragleave', () => {
        encDOM.dropZone.classList.remove('drag-active');
      });

      encDOM.dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        encDOM.dropZone.classList.remove('drag-active');
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
          handleEncVideoSelect(e.dataTransfer.files[0]);
        }
      });

      encDOM.fileInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files.length > 0) {
          handleEncVideoSelect(e.target.files[0]);
        }
      });
    }

    function handleEncVideoSelect(file) {
      if (!file) return;

      const isVideo = (file.type && file.type.startsWith('video/')) ||
        /\.(mp4|webm|mov|mkv|avi|m4v|3gp|wmv|flv|ts|ogv)$/i.test(file.name);

      if (!isVideo) {
        alert(`"${file.name}" does not appear to be a recognized video file. Please select an MP4, WebM, MOV, MKV, or AVI file.`);
        return;
      }

      encState.videoFile = file;
      if (encState.videoUrl) URL.revokeObjectURL(encState.videoUrl);
      encState.videoUrl = URL.createObjectURL(file);
      loadEncVideoIntoPlayer(encState.videoUrl, file.name);

      setTimeout(() => {
        if (encDOM.fileInput) encDOM.fileInput.value = '';
      }, 600);
    }

    function loadEncVideoIntoPlayer(url, name = "uploaded_video.mp4") {
      const video = encDOM.origPlayer;
      if (!video) return;

      if (encDOM.phOrig) encDOM.phOrig.style.display = 'none';
      video.style.display = 'block';

      if (encDOM.dropZone) {
        encDOM.dropZone.classList.add('has-file');
        if (encDOM.dropIcon) {
          encDOM.dropIcon.className = 'fa-solid fa-circle-check drop-icon';
          encDOM.dropIcon.style.color = '#059669';
        }
        if (encDOM.dropText) {
          encDOM.dropText.innerHTML = `✅ <b>Selected:</b> <span style="color: #059669;">${name}</span>`;
        }
      }

      video.src = url;
      video.muted = true;
      video.loop = true;
      video.playsInline = true;
      video.controls = true;

      const onMeta = () => {
        const dur = video.duration || 0;
        const w = video.videoWidth || 640;
        const h = video.videoHeight || 360;
        const fps = parseInt(encDOM.fpsSelect ? encDOM.fpsSelect.value : "24", 10);
        const estFrames = Math.max(1, Math.round(dur * fps));

        if (encDOM.metaName) encDOM.metaName.textContent = name;
        if (encDOM.metaDuration) encDOM.metaDuration.textContent = dur.toFixed(1) + 's';
        if (encDOM.metaRes) encDOM.metaRes.textContent = `${w} × ${h}`;
        if (encDOM.metaFrames) encDOM.metaFrames.textContent = `~${estFrames} frames`;
        if (encDOM.metaChip) encDOM.metaChip.style.display = 'flex';

        if (encDOM.dropText) {
          encDOM.dropText.innerHTML = `✅ <b>Selected:</b> ${name} (${dur.toFixed(1)}s, ${w}×${h})`;
        }

        encState.videoLoaded = true;
        if (encDOM.btnProcess) encDOM.btnProcess.disabled = false;

        video.play().catch(() => {
          video.currentTime = 0.05;
        });
      };

      video.onloadedmetadata = onMeta;
      video.addEventListener('loadeddata', onMeta, { once: true });
      video.addEventListener('canplay', onMeta, { once: true });

      if (video.readyState >= 1) onMeta();

      video.onerror = () => {
        alert(`The browser was unable to decode "${name}". Please ensure it is an MP4 (H.264) or WebM video.`);
        if (encDOM.phOrig) encDOM.phOrig.style.display = 'flex';
        video.style.display = 'none';
        if (encDOM.dropZone) encDOM.dropZone.classList.remove('has-file');
      };
    }

    // Process Video Encryption
    if (encDOM.btnProcess) {
      encDOM.btnProcess.addEventListener('click', async () => {
        if (!encState.videoLoaded) return;

        const video = encDOM.origPlayer;
        const password = encDOM.password ? encDOM.password.value : '';
        const algo = encDOM.algoSelect ? encDOM.algoSelect.value : '3stage';
        const targetFps = parseInt(encDOM.fpsSelect ? encDOM.fpsSelect.value : '24', 10);
        const scaleMode = encDOM.scaleSelect ? encDOM.scaleSelect.value : 'optimized';

        let targetW = video.videoWidth || 640;
        let targetH = video.videoHeight || 360;

        if (scaleMode === 'optimized' && targetW > 640) {
          const scale = 640 / targetW;
          targetW = 640;
          targetH = Math.round((targetH * scale) / 2) * 2;
        } else {
          targetW = Math.round(targetW / 2) * 2;
          targetH = Math.round(targetH / 2) * 2;
        }

        const duration = Math.min(video.duration, 8.0);
        const totalFrames = Math.max(1, Math.floor(duration * targetFps));

        encState.isProcessing = true;
        encState.cancelRequested = false;
        encDOM.btnProcess.disabled = true;
        if (encDOM.btnCancel) encDOM.btnCancel.style.display = 'inline-flex';
        if (encDOM.progressBox) encDOM.progressBox.style.display = 'block';
        if (encDOM.liveBox) encDOM.liveBox.style.display = 'block';
        if (encDOM.progressFill) encDOM.progressFill.style.width = '0%';
        if (encDOM.progressPct) encDOM.progressPct.textContent = '0%';
        if (encDOM.progressStatus) {
          encDOM.progressStatus.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Initializing Video Encryption...';
        }

        const offCanvas = document.createElement('canvas');
        offCanvas.width = targetW;
        offCanvas.height = targetH;
        const offCtx = offCanvas.getContext('2d', { willReadFrequently: true });

        if (encDOM.canvasThumb) {
          encDOM.canvasThumb.width = targetW;
          encDOM.canvasThumb.height = targetH;
        }
        const thumbCtx = encDOM.canvasThumb ? encDOM.canvasThumb.getContext('2d') : null;

        const master32 = await BitEngine.createFastMasterKey(password);
        const processedFrames = [];
        let totalMse = 0;
        let totalSwapped = 0;
        const startTime = performance.now();

        for (let i = 0; i < totalFrames; i++) {
          if (encState.cancelRequested) break;

          const t = i / targetFps;
          video.currentTime = Math.min(t, video.duration - 0.01);

          await new Promise(resolve => {
            const onSeek = () => { video.removeEventListener('seeked', onSeek); resolve(); };
            video.addEventListener('seeked', onSeek, { once: true });
            setTimeout(onSeek, 250);
          });

          offCtx.drawImage(video, 0, 0, targetW, targetH);
          const imgData = offCtx.getImageData(0, 0, targetW, targetH);

          const frameStats = BitEngine.encryptVideoFrame(imgData, master32, i, algo);
          totalMse += frameStats.mse;
          totalSwapped += frameStats.swappedCount;

          processedFrames.push(imgData);
          if (thumbCtx) thumbCtx.putImageData(imgData, 0, 0);

          const pct = Math.round(((i + 1) / totalFrames) * 100);
          if (encDOM.progressFill) encDOM.progressFill.style.width = pct + '%';
          if (encDOM.progressPct) encDOM.progressPct.textContent = pct + '%';
          if (encDOM.progressDetails) {
            const curFps = Math.round((i + 1) / (Math.max(0.01, (performance.now() - startTime) / 1000)));
            encDOM.progressDetails.textContent = `Frame ${i + 1} / ${totalFrames} (${curFps} FPS)`;
          }

          const elapsedSec = (performance.now() - startTime) / 1000;
          const estTotal = (elapsedSec / (i + 1)) * totalFrames;
          const eta = Math.max(0, estTotal - elapsedSec).toFixed(1);
          if (encDOM.progressEta) encDOM.progressEta.textContent = `ETA: ${eta}s`;
          if (encDOM.liveBadge) encDOM.liveBadge.textContent = `Frame ${i + 1} / ${totalFrames}`;

          if (i % 2 === 0) await new Promise(r => setTimeout(r, 0));
        }

        if (encState.cancelRequested || processedFrames.length === 0) {
          encState.isProcessing = false;
          encDOM.btnProcess.disabled = false;
          if (encDOM.btnCancel) encDOM.btnCancel.style.display = 'none';
          if (encDOM.progressStatus) encDOM.progressStatus.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Encryption Cancelled';
          return;
        }

        if (encDOM.progressStatus) encDOM.progressStatus.innerHTML = '<i class="fa-solid fa-film fa-spin"></i> Compiling Encrypted WebM Stream...';
        if (encDOM.progressEta) encDOM.progressEta.textContent = 'Finalizing stream...';

        const recCanvas = document.createElement('canvas');
        recCanvas.width = targetW;
        recCanvas.height = targetH;
        const recCtx = recCanvas.getContext('2d');

        const stream = recCanvas.captureStream(targetFps);
        let mimeType = 'video/webm;codecs=vp9';
        if (!MediaRecorder.isTypeSupported(mimeType)) mimeType = 'video/webm;codecs=vp8';
        if (!MediaRecorder.isTypeSupported(mimeType)) mimeType = 'video/webm';

        const recorder = new MediaRecorder(stream, { mimeType, videoBitsPerSecond: 3000000 });
        const chunks = [];
        recorder.ondataavailable = e => { if (e.data.size > 0) chunks.push(e.data); };

        recorder.onstop = () => {
          const blob = new Blob(chunks, { type: mimeType });
          if (encState.processedUrl) URL.revokeObjectURL(encState.processedUrl);
          encState.processedBlob = blob;
          encState.processedUrl = URL.createObjectURL(blob);

          encDOM.resultPlayer.src = encState.processedUrl;
          encDOM.resultPlayer.load();
          if (encDOM.phResult) encDOM.phResult.style.display = 'none';
          encDOM.resultPlayer.style.display = 'block';

          if (encDOM.btnDownload) encDOM.btnDownload.disabled = false;
          if (encDOM.btnGotoDecrypt) encDOM.btnGotoDecrypt.style.display = 'block';
          if (encDOM.btnSyncPlay) encDOM.btnSyncPlay.disabled = false;
          if (encDOM.btnSyncPause) encDOM.btnSyncPause.disabled = false;
          if (encDOM.btnSyncReset) encDOM.btnSyncReset.disabled = false;

          const totalTimeSec = (performance.now() - startTime) / 1000;
          const avgFps = (totalFrames / Math.max(0.01, totalTimeSec)).toFixed(1);
          const avgMse = (totalMse / totalFrames).toFixed(2);
          const avgPsnr = avgMse > 0 ? (10 * Math.log10((255 * 255) / avgMse)).toFixed(2) : '∞';

          if (encDOM.valFrames) encDOM.valFrames.textContent = totalFrames;
          if (encDOM.valSpeed) encDOM.valSpeed.textContent = `${avgFps} FPS`;
          if (encDOM.valMse) encDOM.valMse.textContent = avgMse;
          if (encDOM.valPsnr) encDOM.valPsnr.textContent = `${avgPsnr} dB`;
          if (encDOM.metricsBar) encDOM.metricsBar.style.display = 'flex';

          if (encDOM.progressStatus) {
            encDOM.progressStatus.innerHTML = '<i class="fa-solid fa-circle-check" style="color: var(--accent-emerald);"></i> Encryption Complete!';
          }

          // Register in shared bridge for seamless decryption
          FYP_VideoBridge.lastEncryptedBlob = blob;
          FYP_VideoBridge.lastEncryptedUrl = encState.processedUrl;
          FYP_VideoBridge.lastEncryptedName = `encrypted_${encState.videoFile ? encState.videoFile.name : 'video.webm'}`;
          FYP_VideoBridge.lastPassword = password;
          FYP_VideoBridge.lastAlgo = algo;
          FYP_VideoBridge.lastFps = targetFps.toString();
          if (typeof FYP_VideoBridge.onVideoEncrypted === 'function') {
            FYP_VideoBridge.onVideoEncrypted();
          }

          encState.isProcessing = false;
          encDOM.btnProcess.disabled = false;
          if (encDOM.btnCancel) encDOM.btnCancel.style.display = 'none';
        };

        recorder.start();

        let frameIdx = 0;
        const streamInterval = 1000 / targetFps;
        const playTimer = setInterval(() => {
          if (frameIdx < processedFrames.length && !encState.cancelRequested) {
            recCtx.putImageData(processedFrames[frameIdx], 0, 0);
            frameIdx++;
          } else {
            clearInterval(playTimer);
            setTimeout(() => {
              if (recorder.state !== 'inactive') recorder.stop();
            }, 150);
          }
        }, streamInterval);
      });
    }

    if (encDOM.btnCancel) {
      encDOM.btnCancel.addEventListener('click', () => {
        encState.cancelRequested = true;
      });
    }

    // Synchronized Dual Playback Controls (Encrypt Tab)
    if (encDOM.btnSyncPlay) {
      encDOM.btnSyncPlay.addEventListener('click', () => {
        encDOM.resultPlayer.currentTime = encDOM.origPlayer.currentTime;
        encDOM.origPlayer.play();
        encDOM.resultPlayer.play();
      });
    }

    if (encDOM.btnSyncPause) {
      encDOM.btnSyncPause.addEventListener('click', () => {
        encDOM.origPlayer.pause();
        encDOM.resultPlayer.pause();
      });
    }

    if (encDOM.btnSyncReset) {
      encDOM.btnSyncReset.addEventListener('click', () => {
        encDOM.origPlayer.pause();
        encDOM.resultPlayer.pause();
        encDOM.origPlayer.currentTime = 0;
        encDOM.resultPlayer.currentTime = 0;
      });
    }

    if (encDOM.origPlayer) {
      encDOM.origPlayer.addEventListener('timeupdate', () => {
        const cur = encDOM.origPlayer.currentTime;
        const dur = encDOM.origPlayer.duration || 0;
        if (encDOM.origTime) encDOM.origTime.textContent = `${cur.toFixed(1)}s / ${dur.toFixed(1)}s`;
      });
    }

    if (encDOM.resultPlayer) {
      encDOM.resultPlayer.addEventListener('timeupdate', () => {
        const cur = encDOM.resultPlayer.currentTime;
        const dur = encDOM.resultPlayer.duration || 0;
        if (encDOM.resultTime) encDOM.resultTime.textContent = `${cur.toFixed(1)}s / ${dur.toFixed(1)}s`;
      });
    }

    if (encDOM.btnDownload) {
      encDOM.btnDownload.addEventListener('click', () => {
        if (!encState.processedBlob) return;
        const link = document.createElement('a');
        link.href = encState.processedUrl;
        link.download = `encrypted_video_${Date.now()}.webm`;
        link.click();
      });
    }

    // One-click jump to Decrypt tab with the encrypted video loaded
    if (encDOM.btnGotoDecrypt) {
      encDOM.btnGotoDecrypt.addEventListener('click', () => {
        const decTabBtn = document.getElementById('tab-btn-video-dec');
        if (decTabBtn) decTabBtn.click();
        const bridgeBtn = document.getElementById('btn-use-last-encrypted');
        if (bridgeBtn) bridgeBtn.click();
      });
    }
  }

  /* ==========================================================================
     PAGE 2: VIDEO DECRYPTION MODULE (Upload, Invert, Preview & Export)
     ========================================================================== */
  function initVideoDecryptModule() {
    const decDOM = {
      bridgeBox: document.getElementById('dec-bridge-box'),
      btnUseLast: document.getElementById('btn-use-last-encrypted'),
      dropZone: document.getElementById('video-dec-drop-zone'),
      fileInput: document.getElementById('video-dec-file-input'),
      dropText: document.getElementById('video-dec-drop-text'),
      dropIcon: document.getElementById('video-dec-drop-icon'),
      metaChip: document.getElementById('video-dec-meta-chip'),
      metaName: document.getElementById('meta-video-dec-name'),
      metaDuration: document.getElementById('meta-video-dec-duration'),
      metaRes: document.getElementById('meta-video-dec-res'),
      metaFrames: document.getElementById('meta-video-dec-frames'),
      password: document.getElementById('video-dec-password'),
      togglePwd: document.getElementById('toggle-video-dec-pwd'),
      algoSelect: document.getElementById('video-dec-algo-select'),
      fpsSelect: document.getElementById('video-dec-fps-select'),
      scaleSelect: document.getElementById('video-dec-scale-select'),
      progressBox: document.getElementById('video-dec-progress-box'),
      progressStatus: document.getElementById('video-dec-progress-status'),
      progressPct: document.getElementById('video-dec-progress-pct'),
      progressFill: document.getElementById('video-dec-progress-fill'),
      progressDetails: document.getElementById('video-dec-progress-details'),
      progressEta: document.getElementById('video-dec-progress-eta'),
      btnProcess: document.getElementById('btn-process-video-dec'),
      btnCancel: document.getElementById('btn-cancel-video-dec'),
      origPlayer: document.getElementById('video-dec-orig-player'),
      phOrig: document.getElementById('ph-video-dec-orig'),
      resultPlayer: document.getElementById('video-dec-result-player'),
      phResult: document.getElementById('ph-video-dec-result'),
      origTime: document.getElementById('video-dec-orig-time'),
      resultTime: document.getElementById('video-dec-result-time'),
      liveBox: document.getElementById('video-dec-live-box'),
      liveBadge: document.getElementById('live-frame-dec-badge'),
      canvasThumb: document.getElementById('canvas-video-dec-thumb'),
      btnSyncPlay: document.getElementById('btn-sync-play-dec'),
      btnSyncPause: document.getElementById('btn-sync-pause-dec'),
      btnSyncReset: document.getElementById('btn-sync-reset-dec'),
      metricsBar: document.getElementById('video-dec-metrics-bar'),
      valFrames: document.getElementById('val-video-dec-frames'),
      valSpeed: document.getElementById('val-video-dec-speed'),
      valQuality: document.getElementById('val-video-dec-quality'),
      valStatus: document.getElementById('val-video-dec-status'),
      btnDownload: document.getElementById('btn-download-video-dec')
    };

    const decState = {
      videoLoaded: false,
      videoFile: null,
      videoUrl: null,
      processedBlob: null,
      processedUrl: null,
      isProcessing: false,
      cancelRequested: false
    };

    if (decDOM.togglePwd && decDOM.password) {
      setupPwdToggle(decDOM.togglePwd, decDOM.password);
    }

    // Bridge Notification: Show bridge button if video was encrypted in Encrypt page
    FYP_VideoBridge.onVideoEncrypted = () => {
      if (decDOM.bridgeBox) decDOM.bridgeBox.style.display = 'block';
    };

    if (decDOM.btnUseLast) {
      decDOM.btnUseLast.addEventListener('click', () => {
        if (!FYP_VideoBridge.lastEncryptedUrl) return;

        if (FYP_VideoBridge.lastPassword && decDOM.password) {
          decDOM.password.value = FYP_VideoBridge.lastPassword;
        }
        if (FYP_VideoBridge.lastAlgo && decDOM.algoSelect) {
          decDOM.algoSelect.value = FYP_VideoBridge.lastAlgo;
        }
        if (FYP_VideoBridge.lastFps && decDOM.fpsSelect) {
          decDOM.fpsSelect.value = FYP_VideoBridge.lastFps;
        }

        loadDecVideoIntoPlayer(FYP_VideoBridge.lastEncryptedUrl, FYP_VideoBridge.lastEncryptedName || "encrypted_video.webm");
      });
    }

    if (decDOM.dropZone && decDOM.fileInput) {
      decDOM.dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        decDOM.dropZone.classList.add('drag-active');
      });

      decDOM.dropZone.addEventListener('dragleave', () => {
        decDOM.dropZone.classList.remove('drag-active');
      });

      decDOM.dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        decDOM.dropZone.classList.remove('drag-active');
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
          handleDecVideoSelect(e.dataTransfer.files[0]);
        }
      });

      decDOM.fileInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files.length > 0) {
          handleDecVideoSelect(e.target.files[0]);
        }
      });
    }

    function handleDecVideoSelect(file) {
      if (!file) return;

      const isVideo = (file.type && file.type.startsWith('video/')) ||
        /\.(mp4|webm|mov|mkv|avi|m4v|3gp|wmv|flv|ts|ogv)$/i.test(file.name);

      if (!isVideo) {
        alert(`"${file.name}" does not appear to be a recognized video file. Please select a video (WebM, MP4, etc.).`);
        return;
      }

      decState.videoFile = file;
      if (decState.videoUrl) URL.revokeObjectURL(decState.videoUrl);
      decState.videoUrl = URL.createObjectURL(file);
      loadDecVideoIntoPlayer(decState.videoUrl, file.name);

      setTimeout(() => {
        if (decDOM.fileInput) decDOM.fileInput.value = '';
      }, 600);
    }

    function loadDecVideoIntoPlayer(url, name = "encrypted_video.webm") {
      const video = decDOM.origPlayer;
      if (!video) return;

      if (decDOM.phOrig) decDOM.phOrig.style.display = 'none';
      video.style.display = 'block';

      if (decDOM.dropZone) {
        decDOM.dropZone.classList.add('has-file');
        if (decDOM.dropIcon) {
          decDOM.dropIcon.className = 'fa-solid fa-circle-check drop-icon';
          decDOM.dropIcon.style.color = '#059669';
        }
        if (decDOM.dropText) {
          decDOM.dropText.innerHTML = `✅ <b>Selected:</b> <span style="color: #059669;">${name}</span>`;
        }
      }

      video.src = url;
      video.muted = true;
      video.loop = true;
      video.playsInline = true;
      video.controls = true;

      const onMeta = () => {
        const dur = video.duration || 0;
        const w = video.videoWidth || 640;
        const h = video.videoHeight || 360;
        const fps = parseInt(decDOM.fpsSelect ? decDOM.fpsSelect.value : "24", 10);
        const estFrames = Math.max(1, Math.round(dur * fps));

        if (decDOM.metaName) decDOM.metaName.textContent = name;
        if (decDOM.metaDuration) decDOM.metaDuration.textContent = dur.toFixed(1) + 's';
        if (decDOM.metaRes) decDOM.metaRes.textContent = `${w} × ${h}`;
        if (decDOM.metaFrames) decDOM.metaFrames.textContent = `~${estFrames} frames`;
        if (decDOM.metaChip) decDOM.metaChip.style.display = 'flex';

        if (decDOM.dropText) {
          decDOM.dropText.innerHTML = `✅ <b>Selected:</b> ${name} (${dur.toFixed(1)}s, ${w}×${h})`;
        }

        decState.videoLoaded = true;
        if (decDOM.btnProcess) decDOM.btnProcess.disabled = false;

        video.play().catch(() => {
          video.currentTime = 0.05;
        });
      };

      video.onloadedmetadata = onMeta;
      video.addEventListener('loadeddata', onMeta, { once: true });
      video.addEventListener('canplay', onMeta, { once: true });

      if (video.readyState >= 1) onMeta();

      video.onerror = () => {
        alert(`The browser was unable to decode "${name}". Please ensure it is a valid video file.`);
        if (decDOM.phOrig) decDOM.phOrig.style.display = 'flex';
        video.style.display = 'none';
        if (decDOM.dropZone) decDOM.dropZone.classList.remove('has-file');
      };
    }

    // Process Video Decryption
    if (decDOM.btnProcess) {
      decDOM.btnProcess.addEventListener('click', async () => {
        if (!decState.videoLoaded) return;

        const video = decDOM.origPlayer;
        const password = decDOM.password ? decDOM.password.value : '';
        const algo = decDOM.algoSelect ? decDOM.algoSelect.value : '3stage';
        const targetFps = parseInt(decDOM.fpsSelect ? decDOM.fpsSelect.value : '24', 10);
        const scaleMode = decDOM.scaleSelect ? decDOM.scaleSelect.value : 'optimized';

        let targetW = video.videoWidth || 640;
        let targetH = video.videoHeight || 360;

        if (scaleMode === 'optimized' && targetW > 640) {
          const scale = 640 / targetW;
          targetW = 640;
          targetH = Math.round((targetH * scale) / 2) * 2;
        } else {
          targetW = Math.round(targetW / 2) * 2;
          targetH = Math.round(targetH / 2) * 2;
        }

        const duration = Math.min(video.duration, 8.0);
        const totalFrames = Math.max(1, Math.floor(duration * targetFps));

        decState.isProcessing = true;
        decState.cancelRequested = false;
        decDOM.btnProcess.disabled = true;
        if (decDOM.btnCancel) decDOM.btnCancel.style.display = 'inline-flex';
        if (decDOM.progressBox) decDOM.progressBox.style.display = 'block';
        if (decDOM.liveBox) decDOM.liveBox.style.display = 'block';
        if (decDOM.progressFill) decDOM.progressFill.style.width = '0%';
        if (decDOM.progressPct) decDOM.progressPct.textContent = '0%';
        if (decDOM.progressStatus) {
          decDOM.progressStatus.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Initializing Video Decryption...';
        }

        const offCanvas = document.createElement('canvas');
        offCanvas.width = targetW;
        offCanvas.height = targetH;
        const offCtx = offCanvas.getContext('2d', { willReadFrequently: true });

        if (decDOM.canvasThumb) {
          decDOM.canvasThumb.width = targetW;
          decDOM.canvasThumb.height = targetH;
        }
        const thumbCtx = decDOM.canvasThumb ? decDOM.canvasThumb.getContext('2d') : null;

        const master32 = await BitEngine.createFastMasterKey(password);
        const processedFrames = [];
        const startTime = performance.now();

        for (let i = 0; i < totalFrames; i++) {
          if (decState.cancelRequested) break;

          const t = i / targetFps;
          video.currentTime = Math.min(t, video.duration - 0.01);

          await new Promise(resolve => {
            const onSeek = () => { video.removeEventListener('seeked', onSeek); resolve(); };
            video.addEventListener('seeked', onSeek, { once: true });
            setTimeout(onSeek, 250);
          });

          offCtx.drawImage(video, 0, 0, targetW, targetH);
          const imgData = offCtx.getImageData(0, 0, targetW, targetH);

          BitEngine.decryptVideoFrame(imgData, master32, i, algo);

          processedFrames.push(imgData);
          if (thumbCtx) thumbCtx.putImageData(imgData, 0, 0);

          const pct = Math.round(((i + 1) / totalFrames) * 100);
          if (decDOM.progressFill) decDOM.progressFill.style.width = pct + '%';
          if (decDOM.progressPct) decDOM.progressPct.textContent = pct + '%';
          if (decDOM.progressDetails) {
            const curFps = Math.round((i + 1) / (Math.max(0.01, (performance.now() - startTime) / 1000)));
            decDOM.progressDetails.textContent = `Frame ${i + 1} / ${totalFrames} (${curFps} FPS)`;
          }

          const elapsedSec = (performance.now() - startTime) / 1000;
          const estTotal = (elapsedSec / (i + 1)) * totalFrames;
          const eta = Math.max(0, estTotal - elapsedSec).toFixed(1);
          if (decDOM.progressEta) decDOM.progressEta.textContent = `ETA: ${eta}s`;
          if (decDOM.liveBadge) decDOM.liveBadge.textContent = `Frame ${i + 1} / ${totalFrames}`;

          if (i % 2 === 0) await new Promise(r => setTimeout(r, 0));
        }

        if (decState.cancelRequested || processedFrames.length === 0) {
          decState.isProcessing = false;
          decDOM.btnProcess.disabled = false;
          if (decDOM.btnCancel) decDOM.btnCancel.style.display = 'none';
          if (decDOM.progressStatus) decDOM.progressStatus.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Decryption Cancelled';
          return;
        }

        if (decDOM.progressStatus) decDOM.progressStatus.innerHTML = '<i class="fa-solid fa-film fa-spin"></i> Compiling Restored WebM Stream...';
        if (decDOM.progressEta) decDOM.progressEta.textContent = 'Finalizing stream...';

        const recCanvas = document.createElement('canvas');
        recCanvas.width = targetW;
        recCanvas.height = targetH;
        const recCtx = recCanvas.getContext('2d');

        const stream = recCanvas.captureStream(targetFps);
        let mimeType = 'video/webm;codecs=vp9';
        if (!MediaRecorder.isTypeSupported(mimeType)) mimeType = 'video/webm;codecs=vp8';
        if (!MediaRecorder.isTypeSupported(mimeType)) mimeType = 'video/webm';

        const recorder = new MediaRecorder(stream, { mimeType, videoBitsPerSecond: 3000000 });
        const chunks = [];
        recorder.ondataavailable = e => { if (e.data.size > 0) chunks.push(e.data); };

        recorder.onstop = () => {
          const blob = new Blob(chunks, { type: mimeType });
          if (decState.processedUrl) URL.revokeObjectURL(decState.processedUrl);
          decState.processedBlob = blob;
          decState.processedUrl = URL.createObjectURL(blob);

          decDOM.resultPlayer.src = decState.processedUrl;
          decDOM.resultPlayer.load();
          if (decDOM.phResult) decDOM.phResult.style.display = 'none';
          decDOM.resultPlayer.style.display = 'block';

          if (decDOM.btnDownload) decDOM.btnDownload.disabled = false;
          if (decDOM.btnSyncPlay) decDOM.btnSyncPlay.disabled = false;
          if (decDOM.btnSyncPause) decDOM.btnSyncPause.disabled = false;
          if (decDOM.btnSyncReset) decDOM.btnSyncReset.disabled = false;

          const totalTimeSec = (performance.now() - startTime) / 1000;
          const avgFps = (totalFrames / Math.max(0.01, totalTimeSec)).toFixed(1);

          if (decDOM.valFrames) decDOM.valFrames.textContent = totalFrames;
          if (decDOM.valSpeed) decDOM.valSpeed.textContent = `${avgFps} FPS`;
          if (decDOM.metricsBar) decDOM.metricsBar.style.display = 'flex';

          if (decDOM.progressStatus) {
            decDOM.progressStatus.innerHTML = '<i class="fa-solid fa-circle-check" style="color: var(--accent-emerald);"></i> Decryption Complete!';
          }

          decState.isProcessing = false;
          decDOM.btnProcess.disabled = false;
          if (decDOM.btnCancel) decDOM.btnCancel.style.display = 'none';
        };

        recorder.start();

        let frameIdx = 0;
        const streamInterval = 1000 / targetFps;
        const playTimer = setInterval(() => {
          if (frameIdx < processedFrames.length && !decState.cancelRequested) {
            recCtx.putImageData(processedFrames[frameIdx], 0, 0);
            frameIdx++;
          } else {
            clearInterval(playTimer);
            setTimeout(() => {
              if (recorder.state !== 'inactive') recorder.stop();
            }, 150);
          }
        }, streamInterval);
      });
    }

    if (decDOM.btnCancel) {
      decDOM.btnCancel.addEventListener('click', () => {
        decState.cancelRequested = true;
      });
    }

    // Synchronized Dual Playback Controls (Decrypt Tab)
    if (decDOM.btnSyncPlay) {
      decDOM.btnSyncPlay.addEventListener('click', () => {
        decDOM.resultPlayer.currentTime = decDOM.origPlayer.currentTime;
        decDOM.origPlayer.play();
        decDOM.resultPlayer.play();
      });
    }

    if (decDOM.btnSyncPause) {
      decDOM.btnSyncPause.addEventListener('click', () => {
        decDOM.origPlayer.pause();
        decDOM.resultPlayer.pause();
      });
    }

    if (decDOM.btnSyncReset) {
      decDOM.btnSyncReset.addEventListener('click', () => {
        decDOM.origPlayer.pause();
        decDOM.resultPlayer.pause();
        decDOM.origPlayer.currentTime = 0;
        decDOM.resultPlayer.currentTime = 0;
      });
    }

    if (decDOM.origPlayer) {
      decDOM.origPlayer.addEventListener('timeupdate', () => {
        const cur = decDOM.origPlayer.currentTime;
        const dur = decDOM.origPlayer.duration || 0;
        if (decDOM.origTime) decDOM.origTime.textContent = `${cur.toFixed(1)}s / ${dur.toFixed(1)}s`;
      });
    }

    if (decDOM.resultPlayer) {
      decDOM.resultPlayer.addEventListener('timeupdate', () => {
        const cur = decDOM.resultPlayer.currentTime;
        const dur = decDOM.resultPlayer.duration || 0;
        if (decDOM.resultTime) decDOM.resultTime.textContent = `${cur.toFixed(1)}s / ${dur.toFixed(1)}s`;
      });
    }

    if (decDOM.btnDownload) {
      decDOM.btnDownload.addEventListener('click', () => {
        if (!decState.processedBlob) return;
        const link = document.createElement('a');
        link.href = decState.processedUrl;
        link.download = `restored_video_${Date.now()}.webm`;
        link.click();
      });
    }
  }

  // Initialize both video modules
  initVideoEncryptModule();
  initVideoDecryptModule();

});
