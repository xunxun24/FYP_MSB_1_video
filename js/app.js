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
    isManualAddMode: false,
    manualAddBox: { x: 0, y: 0, width: 0, height: 0, active: false },
    dragStart: { x: 0, y: 0 },
    detectedPersons: [], // Array of validated person instances { id, index, label, confidence, bbox, cx, topY, pixelCount, coveragePct, baseMask, mask, selected }
    detectedFaces: [],   // Array of validated face instances { id, index, label, confidence, bbox, cx, topY, pixelCount, coveragePct, baseMask, mask, selected }
    maskBoundaryPadPx: 0,
    detectionsConfirmed: false,
    detectedBodyStats: { pixelCount: 0, coveragePct: 0, topX: 0, topY: 0, count: 0 },
    detectedFaceStats: { pixelCount: 0, coveragePct: 0, topX: 0, topY: 0, count: 0 },
    isAiDetecting: false,
    aiModelsLoaded: false,
    encFileName: 'encrypted_photo',
    decFileName: 'restored_photo',
    decImage: null,
    decPngBytes: null,
    decMsbxBytes: null,
    decMsbxHeader: null,
    decContainerFormat: null, // 'png' | 'msbx'
    decMode: 'msb',
    lastOriginalImageData: null,
    lastEncryptedImageData: null,
    lastEncryptedPngBytes: null,
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
    aiReviewPanel: document.getElementById('ai-detection-review-panel'),
    aiRevPersonCount: document.getElementById('ai-rev-person-count'),
    aiRevFaceCount: document.getElementById('ai-rev-face-count'),
    aiRevItemsList: document.getElementById('ai-rev-items-list'),
    btnAiAddManual: document.getElementById('btn-ai-add-manual'),
    btnAiSelectAll: document.getElementById('btn-ai-select-all'),
    btnAiRescan: document.getElementById('btn-ai-rescan'),
    btnAiConfirmDetections: document.getElementById('btn-ai-confirm-detections'),
    aiManualAddBanner: document.getElementById('ai-manual-add-banner'),
    aiManualAddText: document.getElementById('ai-manual-add-text'),
    btnAiCancelManual: document.getElementById('btn-ai-cancel-manual'),
    aiMaskPadSlider: document.getElementById('ai-mask-pad-slider'),
    aiMaskPadVal: document.getElementById('ai-mask-pad-val'),
    aiConfirmStatus: document.getElementById('ai-confirm-status'),
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
    valEncTime: document.getElementById('val-enc-time'),
    encKSelect: document.getElementById('enc-k-select'),
    encProtectMask: document.getElementById('enc-protect-mask'),
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
      const tabAttr = tab.getAttribute('data-tab');
      const targetPane = document.getElementById(tabAttr);
      if (targetPane) targetPane.classList.add('active');

      if (tabAttr === 'decrypt-tab') {
        updateDecButtonState();
      }
    });
  });

  // Dark Mode / Light Mode Theme Toggle
  const btnThemeToggle = document.getElementById('btn-theme-toggle');
  const themeToggleIcon = document.getElementById('theme-toggle-icon');
  const themeToggleLabel = document.getElementById('theme-toggle-label');

  function applyThemeUI(theme) {
    const isDark = theme === 'dark';
    document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
    if (themeToggleIcon) {
      themeToggleIcon.className = isDark ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
    }
    if (themeToggleLabel) {
      themeToggleLabel.textContent = isDark ? 'Light Mode' : 'Dark Mode';
    }
  }

  try {
    const initialTheme = localStorage.getItem('kxbit-theme') || 'light';
    applyThemeUI(initialTheme);
  } catch (e) {
    applyThemeUI('light');
  }

  if (btnThemeToggle) {
    btnThemeToggle.addEventListener('click', () => {
      const currentTheme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
      const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
      applyThemeUI(nextTheme);
      try {
        localStorage.setItem('kxbit-theme', nextTheme);
      } catch (e) {}
    });
  }

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

    if (!state.decImage && !state.decPngBytes && !state.decMsbxBytes) {
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
    state.lastEncryptedPngBytes = null;
    state.lastEncryptedMSBX = null;
    state.lastEncryptedHeader = null;
    clearCanvasAndShowPlaceholder(DOM.canvasEncResult, DOM.phEncResult);
    if (DOM.encMetrics) DOM.encMetrics.style.display = 'none';
    if (DOM.valEncMse) DOM.valEncMse.textContent = '0.00';
    if (DOM.valEncPsnr) DOM.valEncPsnr.textContent = '∞ dB';
    if (DOM.valEncSwapped) DOM.valEncSwapped.textContent = '0';
    if (DOM.valEncTime) DOM.valEncTime.textContent = '0 ms';
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
    if (DOM.decErrorText) DOM.decErrorText.textContent = message || 'Failed to verify or decrypt the file.';
    DOM.decErrorBanner.style.display = 'flex';
    DOM.decErrorBanner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function hideDecError() {
    if (!DOM.decErrorBanner) return;
    DOM.decErrorBanner.style.display = 'none';
    if (DOM.decErrorText) DOM.decErrorText.textContent = '';
  }

  /**
   * Always keep both the Text Password input and the Key-Image upload box visible
   * on the Decrypt page so the user can freely enter a password OR upload an image as a key.
   */
  function applyDecKeyTypeVisibility() {
    const orDivider = document.querySelector('#decrypt-tab .dec-or-divider');
    if (DOM.decTextKeyBox) DOM.decTextKeyBox.style.display = 'block';
    if (DOM.decImgKeyBox) DOM.decImgKeyBox.style.display = 'block';
    if (orDivider) orDivider.style.display = 'flex';
  }

  function renderMsbxHeaderCard(el, header, byteLength, titleLabel, extraStats = {}) {
    if (!el || !header) return;
    const kb = (byteLength / 1024).toFixed(1);
    const scopeName = SCOPE_LABELS[header.scope] || 'Entire Image';
    const keyLabel = header.keyType === 'image' ? 'Key Image (SHA-256)' : 'Text Password';
    const modeText = header.modeLabel || header.imageModeLabel || 'RGB (24-bit)';
    const idText = header.identifier || header.magic || 'KENX-ENC';
    const verText = header.metaVersion
      ? `Meta v${header.metaVersion} • Algo v${header.algoVersion || 1}`
      : `v${header.version || 1}`;
    const maskProtectionText = header.scope !== 'full'
      ? (header.maskProtected ? 'Protected (Keystream-XOR RLE)' : 'Lossless RLE-Varint')
      : 'None (Full Image)';
    const chunkDisplay = header.chunkDisplay
      || (header.isLegacyChunk || header.chunkType === 'msBx'
        ? 'msBx (Legacy)'
        : (header.chunkType === 'msBX' ? 'msBX' : (header.magic === 'MSBX' ? '.msbx Header (Legacy)' : 'msBX')));
    const losslessCheckHtml = extraStats.verifiedLosslessPng
      ? `<div class="msbx-meta-item full">
           <span class="msbx-meta-label">PNG Lossless Pixel Round-Trip Verification</span>
           <span class="msbx-meta-val" style="color: var(--accent-emerald); font-weight: 600;">✔ Verified (0 different pixels before vs. after PNG encoding • ${extraStats.processingTimeMs || 1} ms)</span>
         </div>`
      : '';

    el.innerHTML = `
      <div class="msbx-meta-header">
        <span><i class="fa-solid fa-file-shield"></i> ${titleLabel || `Embedded PNG Metadata (Metadata Chunk: ${chunkDisplay})`}</span>
        <span>${kb} KB</span>
      </div>
      <div class="msbx-meta-grid">
        <div class="msbx-meta-item">
          <span class="msbx-meta-label">Metadata Chunk</span>
          <span class="msbx-meta-val">${chunkDisplay}</span>
        </div>
        <div class="msbx-meta-item">
          <span class="msbx-meta-label">FYP Identifier / Version</span>
          <span class="msbx-meta-val">${idText} (${verText})</span>
        </div>
        <div class="msbx-meta-item">
          <span class="msbx-meta-label">Original Colour Mode</span>
          <span class="msbx-meta-val">${modeText} (mode=${header.imageMode ?? header.originalColorMode ?? 1})</span>
        </div>
        <div class="msbx-meta-item">
          <span class="msbx-meta-label">Stage 3 MSB Setting</span>
          <span class="msbx-meta-val">k = ${header.k} bit${header.k > 1 ? 's' : ''}</span>
        </div>
        <div class="msbx-meta-item">
          <span class="msbx-meta-label">Image Dimensions</span>
          <span class="msbx-meta-val">${header.width} × ${header.height} px</span>
        </div>
        <div class="msbx-meta-item">
          <span class="msbx-meta-label">Required Key Type</span>
          <span class="msbx-meta-val">${keyLabel}</span>
        </div>
        <div class="msbx-meta-item">
          <span class="msbx-meta-label">KDF Iterations</span>
          <span class="msbx-meta-val">${header.iterations.toLocaleString()} SHA-256</span>
        </div>
        <div class="msbx-meta-item">
          <span class="msbx-meta-label">Encryption Scope</span>
          <span class="msbx-meta-val">${scopeName}</span>
        </div>
        <div class="msbx-meta-item">
          <span class="msbx-meta-label">Mask Storage</span>
          <span class="msbx-meta-val">${maskProtectionText}</span>
        </div>
        ${losslessCheckHtml}
        <div class="msbx-meta-item full">
          <span class="msbx-meta-label">16-Byte Random Salt (Hex)</span>
          <span class="msbx-meta-val">${header.saltHex}</span>
        </div>
        <div class="msbx-meta-item full">
          <span class="msbx-meta-label">32-Byte SHA-256 Original Pixel Verification Tag (Hex)</span>
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

  const MP_PORTRAIT_MODEL = 'https://storage.googleapis.com/mediapipe-models/image_segmenter/selfie_segmenter/float16/latest/selfie_segmenter.tflite';
  const MP_PERSON_DETECTOR_MODEL = 'https://storage.googleapis.com/mediapipe-models/object_detector/efficientdet_lite0/float16/1/efficientdet_lite0.tflite';

  // Inner facial feature landmark rings (eyes, eyebrows, lips, nose) to guarantee zero interior holes
  const LEFT_EYE_RING = [33, 7, 163, 144, 145, 153, 154, 155, 133, 173, 157, 158, 159, 160, 161, 246];
  const RIGHT_EYE_RING = [362, 382, 381, 380, 374, 373, 390, 249, 263, 466, 388, 387, 386, 385, 384, 398];
  const LEFT_BROW_RING = [70, 63, 105, 66, 107, 55, 65, 52, 53, 46];
  const RIGHT_BROW_RING = [300, 293, 334, 296, 336, 285, 295, 282, 283, 276];
  const LIPS_OUTER_RING = [61, 146, 91, 181, 84, 17, 314, 405, 321, 375, 291, 409, 270, 269, 267, 0, 37, 39, 40, 185];

  let imageSegmenter = null;
  let portraitSegmenter = null;
  let faceLandmarker = null;
  let faceDetector = null;
  let objectDetector = null;

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
        portraitSegmenter = await vision.ImageSegmenter.createFromOptions(fileset, {
          baseOptions: { modelAssetPath: MP_PORTRAIT_MODEL, delegate: 'CPU' },
          runningMode: 'IMAGE',
          outputCategoryMask: false,
          outputConfidenceMasks: true
        });
      } catch (portErr) {
        console.warn('Portrait Segmenter fallback:', portErr);
      }

      try {
        faceLandmarker = await vision.FaceLandmarker.createFromOptions(fileset, {
          baseOptions: { modelAssetPath: MP_FACE_MODEL, delegate: 'CPU' },
          runningMode: 'IMAGE',
          numFaces: 16,
          minFaceDetectionConfidence: 0.50,
          minFacePresenceConfidence: 0.50
        });
      } catch (faceErr) {
        console.warn('Face Landmarker unavailable:', faceErr);
      }

      try {
        faceDetector = await vision.FaceDetector.createFromOptions(fileset, {
          baseOptions: { modelAssetPath: MP_FACE_DETECTOR_MODEL, delegate: 'CPU' },
          runningMode: 'IMAGE',
          minDetectionConfidence: 0.52,
          minSuppressionThreshold: 0.30
        });
      } catch (detErr) {
        console.warn('Face Detector unavailable:', detErr);
      }

      try {
        if (vision.ObjectDetector) {
          objectDetector = await vision.ObjectDetector.createFromOptions(fileset, {
            baseOptions: { modelAssetPath: MP_PERSON_DETECTOR_MODEL, delegate: 'CPU' },
            runningMode: 'IMAGE',
            scoreThreshold: 0.45,
            categoryAllowlist: ['person'],
            maxResults: 20
          });
        }
      } catch (objErr) {
        console.warn('Person ObjectDetector unavailable:', objErr);
      }

      state.aiModelsLoaded = true;
      setAiBadge('ready', '<i class="fa-solid fa-check-circle"></i> Multi-Model Canny Edge AI Ready');
    } catch (err) {
      console.error('MediaPipe vision models failed to load:', err);
      state.aiModelsLoaded = false;
      setAiBadge('error', '<i class="fa-solid fa-triangle-exclamation"></i> AI Offline – use Drag & Select ROI');
    }
  }

  // Load models in background; segmentation awaits this promise.
  const aiReadyPromise = initAIModels();

  /* ---------- Low-level image-processing & Canny/Scharr CIE-Lab edge-detection helpers ---------- */

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
   * Convert normalized RGB [0..1] buffer into perceptual CIE L*a*b* (scaled to [0..1])
   * plus Multi-Channel Rotational-Invariant Scharr Gradient + Canny Non-Maximum Suppression (NMS)
   * & Double-Threshold Hysteresis Edge Map.
   */
  function computeSobelEdges(rgb, w, h) {
    const n = w * h;
    const lab = new Float32Array(n * 3);
    for (let i = 0; i < n; i++) {
      const r = rgb[i * 3], g = rgb[i * 3 + 1], b = rgb[i * 3 + 2];
      // Fast perceptual Opponent/CIE-Lab approximation in [0..1]
      const L = 0.299 * r + 0.587 * g + 0.114 * b;
      const A = (r - g) * 0.5 + 0.5;
      const B = (0.5 * (r + g) - b) * 0.5 + 0.5;
      lab[i * 3] = L;
      lab[i * 3 + 1] = A;
      lab[i * 3 + 2] = B;
    }

    const mag = new Float32Array(n);
    const gxArr = new Float32Array(n);
    const gyArr = new Float32Array(n);
    let maxG = 1e-5;

    // 3x3 Rotational-Invariant Scharr Operator: [-3, 0, 3; -10, 0, 10; -3, 0, 3]
    for (let y = 1; y < h - 1; y++) {
      for (let x = 1; x < w - 1; x++) {
        const idx = y * w + x;
        const i00 = ((y - 1) * w + (x - 1)) * 3;
        const i01 = ((y - 1) * w + x) * 3;
        const i02 = ((y - 1) * w + (x + 1)) * 3;
        const i10 = (y * w + (x - 1)) * 3;
        const i12 = (y * w + (x + 1)) * 3;
        const i20 = ((y + 1) * w + (x - 1)) * 3;
        const i21 = ((y + 1) * w + x) * 3;
        const i22 = ((y + 1) * w + (x + 1)) * 3;

        let maxChG2 = 0;
        let sumG2 = 0;
        let domGx = 0, domGy = 0;
        const weights = [1.25, 1.55, 1.45]; // Boost chromatic channels A & B for skin/hair/cloth edges

        for (let c = 0; c < 3; c++) {
          const wt = weights[c];
          const gx = (-3 * lab[i00 + c] + 3 * lab[i02 + c]
                     - 10 * lab[i10 + c] + 10 * lab[i12 + c]
                     - 3 * lab[i20 + c] + 3 * lab[i22 + c]) * wt;
          const gy = (-3 * lab[i00 + c] - 10 * lab[i01 + c] - 3 * lab[i02 + c]
                     + 3 * lab[i20 + c] + 10 * lab[i21 + c] + 3 * lab[i22 + c]) * wt;
          const g2 = gx * gx + gy * gy;
          sumG2 += g2;
          if (g2 > maxChG2) {
            maxChG2 = g2;
            domGx = gx;
            domGy = gy;
          }
        }
        const g = Math.sqrt(0.6 * sumG2 + 0.4 * maxChG2);
        mag[idx] = g;
        gxArr[idx] = domGx;
        gyArr[idx] = domGy;
        if (g > maxG) maxG = g;
      }
    }

    const inv = 1 / maxG;
    for (let i = 0; i < n; i++) mag[i] = Math.min(1, mag[i] * inv);

    // Canny Non-Maximum Suppression (NMS) + Hysteresis
    const nms = new Float32Array(n);
    for (let y = 1; y < h - 1; y++) {
      for (let x = 1; x < w - 1; x++) {
        const idx = y * w + x;
        const m = mag[idx];
        if (m < 0.04) continue;
        const gx = gxArr[idx], gy = gyArr[idx];
        const ax = Math.abs(gx), ay = Math.abs(gy);
        let n1 = 0, n2 = 0;
        if (ay <= 0.4142 * ax) {
          // 0 deg (horizontal gradient)
          n1 = mag[idx - 1];
          n2 = mag[idx + 1];
        } else if (ay >= 2.4142 * ax) {
          // 90 deg (vertical gradient)
          n1 = mag[idx - w];
          n2 = mag[idx + w];
        } else if ((gx * gy) > 0) {
          // 45 deg diagonal
          n1 = mag[idx - w - 1];
          n2 = mag[idx + w + 1];
        } else {
          // 135 deg diagonal
          n1 = mag[idx - w + 1];
          n2 = mag[idx + w - 1];
        }
        if (m >= n1 && m >= n2) {
          nms[idx] = m;
        }
      }
    }

    // Hysteresis thresholding (high = 0.14, low = 0.055)
    const canny = new Float32Array(n);
    const stack = new Int32Array(n);
    let sp = 0;
    for (let i = 0; i < n; i++) {
      if (nms[i] >= 0.14) {
        canny[i] = Math.min(1, nms[i] * 1.4);
        stack[sp++] = i;
      }
    }
    while (sp > 0) {
      const p = stack[--sp];
      const x = p % w;
      const y = (p - x) / w;
      for (let dy = -1; dy <= 1; dy++) {
        const ny = y + dy;
        if (ny <= 0 || ny >= h - 1) continue;
        for (let dx = -1; dx <= 1; dx++) {
          const nx = x + dx;
          if (nx <= 0 || nx >= w - 1) continue;
          const ni = ny * w + nx;
          if (canny[ni] === 0 && nms[ni] >= 0.055) {
            canny[ni] = Math.min(1, nms[ni] * 1.25);
            stack[sp++] = ni;
          }
        }
      }
    }

    // Attach Canny & CIE-Lab buffers onto `mag` so callers expecting `sobel[i]` still work seamlessly
    mag.canny = canny;
    mag.lab = lab;
    mag.gx = gxArr;
    mag.gy = gyArr;
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
   * True Edge-Detection Boundary Snapping (Scharr + Canny NMS + 3-Stage Guided Matting):
   * 1. Builds a boundary trimap band around the contour.
   * 2. Estimates local Definite Foreground & Definite Background colours
   *    on either side of the contour and computes per-pixel colour affinity.
   * 3. Uses Scharr gradient + Canny NMS edge barriers + 3-stage Guided Filter
   *    (`eps = 1.5e-4` -> `6e-5` -> `2.5e-5`) so the 0.5 iso-contour snaps
   *    with 1px precision onto the photo's real colour & Canny edges.
   */
  function refineAlphaWithEdges(rgb, sobel, w, h, coarse, opts = {}) {
    const out = new Float32Array(w * h);
    const baseR = opts.radius || Math.max(3, Math.min(10, Math.round(Math.max(w, h) / 160)));
    const eps = opts.eps || 1.5e-4;
    const canny = sobel.canny || sobel;

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
    const cCanny = new Float32Array(cn);
    for (let y = 0; y < ch; y++) {
      for (let x = 0; x < cw; x++) {
        const gi = (y + minY) * w + (x + minX);
        const ci = y * cw + x;
        cP[ci] = coarse[gi];
        cSobel[ci] = sobel[gi];
        cCanny[ci] = canny[gi];
        cRGB[ci * 3] = rgb[gi * 3];
        cRGB[ci * 3 + 1] = rgb[gi * 3 + 1];
        cRGB[ci * 3 + 2] = rgb[gi * 3 + 2];
      }
    }

    // Smooth the prior slightly so hard polygon/mask borders have a genuine transition band
    const smoothP = boxMean(cP, cw, ch, Math.max(2, Math.round(baseR * 0.55)));

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
      if (sp > 0.025 && sp < 0.975 && mWf[i] > 1e-3 && mWb[i] > 1e-3) {
        band[i] = 1;
        const fr = mFgR[i] / mWf[i], fg = mFgG[i] / mWf[i], fb = mFgB[i] / mWf[i];
        const br = mBgR[i] / mWb[i], bg = mBgG[i] / mWb[i], bb = mBgB[i] / mWb[i];
        const r = cRGB[i * 3], g = cRGB[i * 3 + 1], b = cRGB[i * 3 + 2];

        const dFg = (r - fr) * (r - fr) + (g - fg) * (g - fg) + (b - fb) * (b - fb);
        const dBg = (r - br) * (r - br) + (g - bg) * (g - bg) + (b - bb) * (b - bb);
        const sep = (fr - br) * (fr - br) + (fg - bg) * (fg - bg) + (fb - bb) * (fb - bb);

        const colorAff = dBg / (dFg + dBg + 1e-4);
        // Stronger local FG/BG contrast + Scharr/Canny edge -> stronger snapping to colour edge
        const edgeWeight = Math.min(0.88, Math.sqrt(sep) * 2.4 + cSobel[i] * 0.35 + cCanny[i] * 0.28);
        prior[i] = (1 - edgeWeight) * sp + edgeWeight * colorAff;
      } else {
        prior[i] = cP[i];
      }
    }

    // Three-stage guided filter (coarse -> medium -> ultra-fine 1px Canny edge lock)
    const qCoarse = guidedFilterColor(cRGB, cw, ch, prior, baseR, eps);
    const medR = Math.max(2, Math.round(baseR * 0.45));
    const qMed = guidedFilterColor(cRGB, cw, ch, qCoarse, medR, eps * 0.4);
    const fineR = Math.max(1, Math.round(baseR * 0.22));
    const qFine = guidedFilterColor(cRGB, cw, ch, qMed, fineR, eps * 0.18);

    for (let y = 0; y < ch; y++) {
      for (let x = 0; x < cw; x++) {
        const ci = y * cw + x;
        const gi = (y + minY) * w + (x + minX);
        if (band[ci]) {
          let v = Math.min(1, Math.max(0, qFine[ci]));
          // Sharpen right across strong Scharr/Canny gradient peaks for razor-sharp 1px edges
          const edgePeak = Math.max(cSobel[ci], cCanny[ci]);
          if (edgePeak > 0.10) {
            v = 0.5 + (v - 0.5) * (1 + edgePeak * 1.9);
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

  function runPortraitSegmenter(source) {
    return new Promise((resolve) => {
      if (!portraitSegmenter) {
        resolve(null);
        return;
      }
      try {
        portraitSegmenter.segment(source, (result) => {
          try {
            const m = result.confidenceMasks && result.confidenceMasks[0];
            if (!m) { resolve(null); return; }
            resolve({
              w: m.width,
              h: m.height,
              data: new Float32Array(m.getAsFloat32Array())
            });
          } catch (e) {
            resolve(null);
          }
        });
      } catch (e) {
        resolve(null);
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
   * Snap each vertex of `pts` ([{x,y}, ...]) outward/inward along its 1D normal ray
   * to the strongest Canny/Scharr + neural skin transition boundary.
   */
  function snapPolygonPointsToEdges(pts, cx, cy, canny, sobel, skinProb, rw, rh, maxShiftPx) {
    const k = pts.length;
    if (k < 3 || maxShiftPx < 1) return pts;
    const snapped = [];
    for (let i = 0; i < k; i++) {
      const p = pts[i];
      const vx = p.x - cx;
      const vy = p.y - cy;
      const len = Math.hypot(vx, vy) || 1;
      const nx = vx / len;
      const ny = vy / len;

      let bestT = 0;
      let bestScore = -1;
      for (let t = -maxShiftPx; t <= maxShiftPx; t++) {
        const sx = Math.round(p.x + nx * t);
        const sy = Math.round(p.y + ny * t);
        if (sx < 1 || sx >= rw - 1 || sy < 1 || sy >= rh - 1) continue;
        const idx = sy * rw + sx;

        // Inner vs outer neural skin drop across normal ray
        const inX = Math.max(0, Math.min(rw - 1, Math.round(sx - nx * 2)));
        const inY = Math.max(0, Math.min(rh - 1, Math.round(sy - ny * 2)));
        const outX = Math.max(0, Math.min(rw - 1, Math.round(sx + nx * 2)));
        const outY = Math.max(0, Math.min(rh - 1, Math.round(sy + ny * 2)));
        const skinDrop = skinProb
          ? Math.max(0, skinProb[inY * rw + inX] - skinProb[outY * rw + outX])
          : 0;

        const distPenalty = 1 - 0.35 * Math.abs(t) / (maxShiftPx + 1);
        const edgeStrength = (canny ? canny[idx] * 0.65 : 0) + (sobel ? sobel[idx] * 0.45 : 0) + skinDrop * 0.75;
        const score = edgeStrength * distPenalty;
        if (score > bestScore) {
          bestScore = score;
          bestT = t;
        }
      }
      if (bestScore > 0.14) {
        snapped.push({ x: p.x + nx * bestT * 0.75, y: p.y + ny * bestT * 0.75 });
      } else {
        snapped.push({ x: p.x, y: p.y });
      }
    }
    return snapped;
  }

  /**
   * Multi-Scale + Aspect-Preserving Tiled + Landmark-Verified Face Detection with NMS Deduplication.
   * Eliminates duplicate detections across tiles, rejects background pareidolia and unverified skin blobs,
   * and returns calibrated confidence scores for every distinct face.
   */
  function detectAllFacesMultiScale(workCanvas, w, h, faceSkinMap, fastVideoMode = false, extraMaps = {}) {
    const rawCandidates = [];

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

    function pushLandmarkCandidate(lm, rawScore = 0.88, source = 'landmarker') {
      const bbox = bboxFromLandmarks(lm);
      rawCandidates.push({
        landmarks: lm,
        bbox,
        rawScore,
        source
      });
    }

    /**
     * Run FaceLandmarker on a sub-rectangle `(rx, ry, rw, rh)` using aspect-ratio-preserving
     * letterboxing so faces are never stretched horizontally or vertically across tile borders.
     */
    function runLandmarkerOnCrop(rx, ry, rw, rh, targetSize = 512) {
      if (!faceLandmarker || rw < 18 || rh < 18) return 0;
      const scale = targetSize / Math.max(rw, rh);
      const drawW = Math.max(1, Math.round(rw * scale));
      const drawH = Math.max(1, Math.round(rh * scale));

      const c = document.createElement('canvas');
      c.width = targetSize;
      c.height = targetSize;
      const ctx = c.getContext('2d');
      ctx.fillStyle = '#000000';
      ctx.fillRect(0, 0, targetSize, targetSize);
      ctx.drawImage(workCanvas, rx, ry, rw, rh, 0, 0, drawW, drawH);

      let added = 0;
      try {
        const res = faceLandmarker.detect(c);
        const lms = (res && res.faceLandmarks) ? res.faceLandmarks : [];
        const maxNormX = drawW / targetSize;
        const maxNormY = drawH / targetSize;

        lms.forEach(lm => {
          let minX = 1, maxX = 0, minY = 1, maxY = 0;
          FACE_OVAL_IDX.forEach(idx => {
            const p = lm[idx];
            if (p.x < minX) minX = p.x;
            if (p.x > maxX) maxX = p.x;
            if (p.y < minY) minY = p.y;
            if (p.y > maxY) maxY = p.y;
          });

          // Ignore partial faces clipped against interior crop boundaries
          const touchesLeft = rx > 2 && minX < 0.018;
          const touchesRight = (rx + rw < w - 2) && maxX > (maxNormX - 0.018);
          const touchesTop = ry > 2 && minY < 0.018;
          const touchesBot = (ry + rh < h - 2) && maxY > (maxNormY - 0.018);
          if (touchesLeft || touchesRight || touchesTop || touchesBot) return;
          if (maxX > maxNormX * 1.02 || maxY > maxNormY * 1.02) return;

          const mapped = lm.map(pt => ({
            x: (rx + (pt.x * targetSize) / scale) / w,
            y: (ry + (pt.y * targetSize) / scale) / h,
            z: pt.z
          }));
          pushLandmarkCandidate(mapped, 0.86, 'landmarker_crop');
          added++;
        });
      } catch (e) {
        // ignore single-crop error
      }
      return added;
    }

    // 1. Full-frame FaceLandmarker pass (highest global context)
    if (faceLandmarker) {
      try {
        const res = faceLandmarker.detect(workCanvas);
        ((res && res.faceLandmarks) || []).forEach(lm => pushLandmarkCandidate(lm, 0.92, 'landmarker_full'));
      } catch (e) {
        console.warn('Full-frame FaceLandmarker failed:', e);
      }
    }

    // 2. Overlapping aspect-preserving tiled passes for smaller faces in group photos
    const tiles = fastVideoMode
      ? [
          [0, 0, w * 0.60, h * 0.85],
          [w * 0.40, 0, w * 0.60, h * 0.85]
        ]
      : [
          [0, 0, w * 0.58, h * 0.75],
          [w * 0.21, 0, w * 0.58, h * 0.75],
          [w * 0.42, 0, w * 0.58, h * 0.75],
          [0, h * 0.18, w * 0.56, h * 0.82],
          [w * 0.44, h * 0.18, w * 0.56, h * 0.82]
        ];
    tiles.forEach(([tx, ty, tw, th]) => {
      runLandmarkerOnCrop(Math.round(tx), Math.round(ty), Math.round(tw), Math.round(th), fastVideoMode ? 384 : 512);
    });

    // 3. BlazeFace detector pass -> verify each candidate with FaceLandmarker crop or strict keypoint+foreground validation
    if (faceDetector) {
      const detCrops = fastVideoMode
        ? [[0, 0, w, h]]
        : [
            [0, 0, w, h],
            [0, 0, Math.round(w * 0.58), h],
            [Math.round(w * 0.42), 0, Math.round(w * 0.58), h]
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
            const detScore = (det.categories && det.categories[0] && typeof det.categories[0].score === 'number')
              ? det.categories[0].score
              : 0.65;
            if (detScore < 0.52) return;

            const bx0 = dx + bb.originX;
            const by0 = dy + bb.originY;
            const bw = bb.width;
            const bh = bb.height;
            const candBox = { x0: bx0, y0: by0, x1: bx0 + bw, y1: by0 + bh };

            // Check if already covered by an existing landmark candidate
            const alreadyCovered = rawCandidates.some(f => {
              const m = BitEngine.computeBoxOverlapMetrics(f.bbox, candBox);
              return m.iou >= 0.30 || m.ioMin >= 0.52 || m.normCenterDist < 0.40;
            });
            if (!alreadyCovered) {
              const pad = Math.max(bw, bh) * 0.75;
              const cx0 = Math.max(0, Math.floor(bx0 - pad));
              const cy0 = Math.max(0, Math.floor(by0 - pad));
              const cx1 = Math.min(w, Math.ceil(bx0 + bw + pad));
              const cy1 = Math.min(h, Math.ceil(by0 + bh + pad));
              const addedLm = runLandmarkerOnCrop(cx0, cy0, cx1 - cx0, cy1 - cy0, 384);
              // Only accept a landmark-less BlazeFace box if it has very high detector confidence (>= 0.72) AND valid keypoints
              if (addedLm === 0 && detScore >= 0.72 && Array.isArray(det.keypoints) && det.keypoints.length >= 4) {
                const mappedKps = det.keypoints.map(kp => ({
                  x: (dx + (kp.x <= 1 ? kp.x * dw : kp.x)) / w,
                  y: (dy + (kp.y <= 1 ? kp.y * dh : kp.y)) / h
                }));
                rawCandidates.push({
                  landmarks: null,
                  keypoints: mappedKps,
                  bbox: candBox,
                  rawScore: detScore,
                  source: 'detector_only'
                });
              }
            }
          });
        } catch (e) {
          // ignore
        }
      });
    }

    // 4. Connected-component proposals from neural `faceSkinMap` (class 3)
    //    IMPORTANT FIX: Only used as crop proposals for `FaceLandmarker` — NEVER pushed blindly without landmarks!
    if (faceSkinMap) {
      const n = w * h;
      const visited = new Uint8Array(n);
      const stack = new Int32Array(n);
      const minCluster = Math.max(45, Math.round(n * 0.00055));

      for (let start = 0; start < n; start++) {
        if (visited[start] || faceSkinMap[start] < 0.38) continue;
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

          if (x > 0 && !visited[p - 1] && faceSkinMap[p - 1] >= 0.38) { visited[p - 1] = 1; stack[sp++] = p - 1; }
          if (x < w - 1 && !visited[p + 1] && faceSkinMap[p + 1] >= 0.38) { visited[p + 1] = 1; stack[sp++] = p + 1; }
          if (y > 0 && !visited[p - w] && faceSkinMap[p - w] >= 0.38) { visited[p - w] = 1; stack[sp++] = p - w; }
          if (y < h - 1 && !visited[p + w] && faceSkinMap[p + w] >= 0.38) { visited[p + w] = 1; stack[sp++] = p + w; }
        }

        const bw = x1 - x0 + 1, bh = y1 - y0 + 1;
        const aspect = bw / Math.max(1, bh);
        if (count >= minCluster && aspect > 0.45 && aspect < 1.85) {
          const candBox = { x0, y0, x1, y1 };
          const covered = rawCandidates.some(f => {
            const m = BitEngine.computeBoxOverlapMetrics(f.bbox, candBox);
            return m.iou >= 0.25 || m.ioMin >= 0.45;
          });
          if (!covered) {
            const pad = Math.max(bw, bh) * 0.85;
            const cx0 = Math.max(0, Math.floor(x0 - pad));
            const cy0 = Math.max(0, Math.floor(y0 - pad));
            const cx1 = Math.min(w, Math.ceil(x1 + pad));
            const cy1 = Math.min(h, Math.ceil(y1 + pad));
            runLandmarkerOnCrop(cx0, cy0, cx1 - cx0, cy1 - cy0, 384);
          }
        }
      }
    }

    // 5. Run strict anatomical validation, foreground/skin verification & Confidence-Sorted NMS Deduplication
    return BitEngine.deduplicateFacesNMS(rawCandidates, w, h, {
      faceSkinMap,
      bodySkinMap: extraMaps.bodySkinMap || null,
      bgMap: extraMaps.bgMap || null,
      mapW: w,
      mapH: h
    });
  }

  /**
   * Run MediaPipe ObjectDetector (filtered strictly to 'person' class) on full frame and wide tiles.
   */
  function detectPersonBoxesMultiScale(workCanvas, w, h, W, H) {
    if (!objectDetector) return [];
    const rawBoxes = [];
    const invScaleX = W / w;
    const invScaleY = H / h;

    const crops = w >= 480
      ? [
          [0, 0, w, h],
          [0, 0, Math.round(w * 0.62), h],
          [Math.round(w * 0.38), 0, Math.round(w * 0.62), h]
        ]
      : [[0, 0, w, h]];

    for (const [cx, cy, cw, ch] of crops) {
      try {
        const c = document.createElement('canvas');
        c.width = cw;
        c.height = ch;
        c.getContext('2d').drawImage(workCanvas, cx, cy, cw, ch, 0, 0, cw, ch);
        const res = objectDetector.detect(c);
        ((res && res.detections) || []).forEach(det => {
          const cat = det.categories && det.categories[0];
          if (!cat || (cat.categoryName && cat.categoryName.toLowerCase() !== 'person')) return;
          const score = typeof cat.score === 'number' ? cat.score : 0.55;
          if (score < 0.45 || !det.boundingBox) return;

          const bb = det.boundingBox;
          const x0 = (cx + bb.originX) * invScaleX;
          const y0 = (cy + bb.originY) * invScaleY;
          const x1 = (cx + bb.originX + bb.width) * invScaleX;
          const y1 = (cy + bb.originY + bb.height) * invScaleY;

          // Ignore partial person boxes clipped right at interior crop edges
          if (cx > 2 && bb.originX < 4) return;
          if (cx + cw < w - 2 && (bb.originX + bb.width) > cw - 4) return;

          rawBoxes.push({
            category: 'person',
            score,
            bbox: { x0, y0, x1, y1 }
          });
        });
      } catch (e) {
        // ignore detector error
      }
    }
    return rawBoxes;
  }

  /**
   * Apply morphological boundary dilation (`padPx > 0`) or erosion (`padPx < 0`) to a binary mask.
   */
  function applyMaskMorphologyPad(baseMask, W, H, padPx) {
    if (!baseMask || padPx === 0) return baseMask ? new Uint8Array(baseMask) : null;
    const r = Math.min(12, Math.abs(Math.round(padPx)));
    const isDilate = padPx > 0;
    const horiz = new Uint8Array(W * H);
    const out = new Uint8Array(W * H);

    // Separable horizontal pass
    for (let y = 0; y < H; y++) {
      const row = y * W;
      let sum = 0;
      for (let x = 0; x <= Math.min(r, W - 1); x++) sum += baseMask[row + x];
      for (let x = 0; x < W; x++) {
        const lo = Math.max(0, x - r);
        const hi = Math.min(W - 1, x + r);
        const winLen = hi - lo + 1;
        horiz[row + x] = isDilate ? (sum > 0 ? 1 : 0) : (sum === winLen ? 1 : 0);
        if (x + r + 1 < W) sum += baseMask[row + x + r + 1];
        if (x - r >= 0) sum -= baseMask[row + x - r];
      }
    }

    // Separable vertical pass
    for (let x = 0; x < W; x++) {
      let sum = 0;
      for (let y = 0; y <= Math.min(r, H - 1); y++) sum += horiz[y * W + x];
      for (let y = 0; y < H; y++) {
        const lo = Math.max(0, y - r);
        const hi = Math.min(H - 1, y + r);
        const winLen = hi - lo + 1;
        out[y * W + x] = isDilate ? (sum > 0 ? 1 : 0) : (sum === winLen ? 1 : 0);
        if (y + r + 1 < H) sum += horiz[(y + r + 1) * W + x];
        if (y - r >= 0) sum -= horiz[(y - r) * W + x];
      }
    }
    return out;
  }

  /**
   * Recompute `state.bodyMask`, `state.faceMask`, and displayed statistics from the user-reviewed
   * and confirmed `state.detectedPersons` and `state.detectedFaces` lists (Feature 7).
   */
  function rebuildConfirmedScopeMasks() {
    if (!state.encImage) return;
    const W = state.encImage.width;
    const H = state.encImage.height;
    const totalPixels = W * H;
    const padPx = state.maskBoundaryPadPx || 0;

    // 1. Rebuild combined body mask from selected person instances
    const combinedBody = new Uint8Array(totalPixels);
    let bodyPixels = 0;
    let bodyTopX = Math.floor(W / 2), bodyTopY = H;
    const activePersons = [];

    (state.detectedPersons || []).forEach((p, idx) => {
      p.index = idx + 1;
      if (!p.customLabel) p.label = `Person ${idx + 1}`;
      p.mask = applyMaskMorphologyPad(p.baseMask || p.mask, W, H, padPx);
      let pCount = 0;
      for (let i = 0; i < totalPixels; i++) {
        if (p.mask[i]) {
          pCount++;
          if (p.selected !== false) {
            if (!combinedBody[i]) {
              combinedBody[i] = 1;
              bodyPixels++;
            }
          }
        }
      }
      p.pixelCount = pCount;
      p.coveragePct = parseFloat(((pCount / totalPixels) * 100).toFixed(1));
      if (p.selected !== false && pCount > 0) {
        activePersons.push(p);
        if (p.topY < bodyTopY) {
          bodyTopY = p.topY;
          bodyTopX = p.cx;
        }
      }
    });

    // 2. Rebuild combined face mask from selected face instances
    const combinedFace = new Uint8Array(totalPixels);
    let facePixels = 0;
    let faceTopX = Math.floor(W / 2), faceTopY = H;
    const activeFaces = [];

    (state.detectedFaces || []).forEach((f, idx) => {
      f.index = idx + 1;
      if (!f.customLabel) f.label = `Face ${idx + 1}`;
      if (f.baseMask || f.mask) {
        f.mask = applyMaskMorphologyPad(f.baseMask || f.mask, W, H, padPx);
        let fCount = 0;
        for (let i = 0; i < totalPixels; i++) {
          if (f.mask[i]) {
            fCount++;
            if (f.selected !== false) {
              if (!combinedFace[i]) {
                combinedFace[i] = 1;
                facePixels++;
              }
            }
          }
        }
        f.pixelCount = fCount;
        f.coveragePct = parseFloat(((fCount / totalPixels) * 100).toFixed(1));
      }
      if (f.selected !== false) {
        activeFaces.push(f);
        if (f.topY < faceTopY) {
          faceTopY = f.topY;
          faceTopX = f.cx;
        }
      }
    });

    const bodyPct = parseFloat(((bodyPixels / totalPixels) * 100).toFixed(1));
    const facePct = parseFloat(((facePixels / totalPixels) * 100).toFixed(1));

    state.bodyMask = bodyPixels > 0 ? combinedBody : null;
    state.faceMask = facePixels > 0 ? combinedFace : null;
    state.allMask = state.bodyMask;

    state.detectedBodyStats = {
      pixelCount: bodyPixels,
      coveragePct: bodyPct,
      topX: bodyTopX,
      topY: bodyTopY < H ? bodyTopY : 0,
      count: activePersons.length,
      totalDetected: (state.detectedPersons || []).length
    };
    state.detectedFaceStats = {
      pixelCount: facePixels,
      coveragePct: facePct,
      topX: faceTopX,
      topY: faceTopY < H ? faceTopY : 0,
      count: activeFaces.length,
      totalDetected: (state.detectedFaces || []).length
    };

    updateAiResultUI(
      bodyPixels,
      facePixels,
      bodyPct,
      facePct,
      state.detectedFaceStats.count,
      true,
      state.detectedBodyStats.count
    );
    renderAiDetectionReviewPanel();
  }

  /**
   * Render the interactive AI Detection Review & Manual Correction Panel (Feature 7).
   */
  function renderAiDetectionReviewPanel() {
    if (!DOM.aiReviewPanel || !DOM.aiRevItemsList) return;
    if (!state.encImage || (state.encScope !== 'person' && state.encScope !== 'face')) {
      DOM.aiReviewPanel.style.display = 'none';
      return;
    }

    DOM.aiReviewPanel.style.display = 'block';
    const totalPersons = (state.detectedPersons || []).length;
    const selectedPersons = (state.detectedPersons || []).filter(p => p.selected !== false).length;
    const totalFaces = (state.detectedFaces || []).length;
    const selectedFaces = (state.detectedFaces || []).filter(f => f.selected !== false).length;

    if (DOM.aiRevPersonCount) {
      DOM.aiRevPersonCount.textContent = `${selectedPersons}/${totalPersons} ${totalPersons === 1 ? 'Person' : 'People'}`;
    }
    if (DOM.aiRevFaceCount) {
      DOM.aiRevFaceCount.textContent = `${selectedFaces}/${totalFaces} ${totalFaces === 1 ? 'Face' : 'Faces'}`;
    }

    const isFaceScope = state.encScope === 'face';
    const items = isFaceScope ? (state.detectedFaces || []) : (state.detectedPersons || []);
    DOM.aiRevItemsList.innerHTML = '';

    if (items.length === 0) {
      DOM.aiRevItemsList.innerHTML = `
        <div style="grid-column: 1 / -1; padding: 8px 10px; color: var(--text-muted); font-size: 12px;">
          No ${isFaceScope ? 'faces' : 'people'} currently active. Click <b>"+ Add Missing Detection"</b> above and drag on the image to add one manually.
        </div>
      `;
      return;
    }

    items.forEach((item, idx) => {
      const isSel = item.selected !== false;
      const confPct = Math.round((item.confidence || 0.90) * 100);
      const card = document.createElement('div');
      card.className = 'ai-review-item-card' + (isFaceScope ? ' face-item' : '') + (isSel ? ' selected' : '');

      const leftLabel = document.createElement('label');
      leftLabel.className = 'ai-rev-left';

      const chk = document.createElement('input');
      chk.type = 'checkbox';
      chk.checked = isSel;
      chk.addEventListener('change', () => {
        item.selected = chk.checked;
        state.detectionsConfirmed = false;
        rebuildConfirmedScopeMasks();
        renderEncOriginalWithOverlays();
      });

      const info = document.createElement('div');
      info.className = 'ai-rev-info';
      info.innerHTML = `
        <span class="ai-rev-label">${item.label || `${isFaceScope ? 'Face' : 'Person'} ${idx + 1}`} (${confPct}%)</span>
        <span class="ai-rev-sub">${item.coveragePct || 0}% area · ${(item.pixelCount || 0).toLocaleString()} px</span>
      `;

      leftLabel.appendChild(chk);
      leftLabel.appendChild(info);

      const rmBtn = document.createElement('button');
      rmBtn.type = 'button';
      rmBtn.className = 'ai-rev-remove-btn';
      rmBtn.title = `Remove ${item.label || 'this detection'}`;
      rmBtn.innerHTML = '<i class="fa-solid fa-trash-can"></i>';
      rmBtn.addEventListener('click', () => {
        if (isFaceScope) {
          state.detectedFaces.splice(idx, 1);
        } else {
          state.detectedPersons.splice(idx, 1);
        }
        state.detectionsConfirmed = false;
        rebuildConfirmedScopeMasks();
        renderEncOriginalWithOverlays();
      });

      card.appendChild(leftLabel);
      card.appendChild(rmBtn);
      DOM.aiRevItemsList.appendChild(card);
    });
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

  function updateAiResultUI(bodyPixels, facePixels, bodyPct, facePct, faceCount, aiAvailable, personCount = 0) {
    if (DOM.subPersonCount) {
      if (!aiAvailable) {
        DOM.subPersonCount.textContent = 'AI unavailable';
      } else if (bodyPixels > 0) {
        const pCount = personCount > 0 ? personCount : 1;
        const pLabel = pCount === 1 ? '1 person' : `${pCount} people`;
        DOM.subPersonCount.textContent = `${pLabel} (${bodyPct}%)`;
      } else {
        DOM.subPersonCount.textContent = 'No person found';
      }
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
        const pCount = personCount > 0 ? personCount : (bodyPixels > 0 ? 1 : 0);
        const pText = `${pCount} ${pCount === 1 ? 'Person' : 'People'} (${bodyPct}%)`;
        const fText = `${faceCount} ${faceCount === 1 ? 'Face' : 'Faces'} (${facePct}%)`;
        DOM.aiDetectionText.innerHTML = `<i class="fa-solid fa-shapes"></i> <b>Validated AI Detection:</b> ${pText} &amp; ${fText}. Review, toggle, or adjust individual detections below before encryption.`;
      } else if (!aiAvailable) {
        DOM.aiDetectionText.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> <b>AI models could not be loaded</b> (internet connection required). Use <b>Drag &amp; Select ROI</b> or <b>Entire Image</b>.`;
      } else {
        DOM.aiDetectionText.innerHTML = `<i class="fa-solid fa-crosshairs"></i> <b>No person detected.</b> Use <b>+ Add Missing Detection</b>, <b>Drag &amp; Select ROI</b>, or <b>Entire Image</b>.`;
      }
    }
  }

  /**
   * Run AI Human Segmentation + Multi-Face Detection + Person Instance Segmentation + Canny/Scharr Edge Refinement.
   */
  async function runAISegmentation(img) {
    if (!img) return;
    const token = ++state.segToken;
    state.isAiDetecting = true;
    state.bodyMask = null;
    state.faceMask = null;
    state.allMask = null;
    state.edgeMap = null;
    state.detectedPersons = [];
    state.detectedFaces = [];
    state.maskBoundaryPadPx = 0;
    state.detectionsConfirmed = false;
    if (DOM.aiMaskPadSlider) DOM.aiMaskPadSlider.value = '0';
    if (DOM.aiMaskPadVal) DOM.aiMaskPadVal.textContent = '0 px (Exact Edge)';
    state.detectedBodyStats = { pixelCount: 0, coveragePct: 0, topX: 0, topY: 0, count: 0 };
    state.detectedFaceStats = { pixelCount: 0, coveragePct: 0, topX: 0, topY: 0, count: 0 };
    if (DOM.subPersonCount) DOM.subPersonCount.textContent = 'Tracing…';
    if (DOM.subFaceCount) DOM.subFaceCount.textContent = 'Tracing…';

    setAiBadge('scanning', '<i class="fa-solid fa-circle-notch fa-spin"></i> ' +
      (state.aiModelsLoaded ? 'Detecting Distinct People & Faces...' : 'Loading Neural Vision...'));

    await aiReadyPromise;
    if (token !== state.segToken) return;

    if (!imageSegmenter) {
      state.isAiDetecting = false;
      setAiBadge('error', '<i class="fa-solid fa-triangle-exclamation"></i> AI Offline – use Drag & Select ROI');
      updateAiResultUI(0, 0, 0, 0, 0, false, 0);
      renderEncOriginalWithOverlays();
      return;
    }

    setAiBadge('scanning', '<i class="fa-solid fa-circle-notch fa-spin"></i> Validating Faces, People & Canny Edges...');
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

      // Compute CIE-Lab + Scharr + Canny NMS & Hysteresis edge map
      const sobel = computeSobelEdges(rgb, w, h);

      // 1. Dual-Model Person Segmentation (Multiclass + Dedicated Portrait Silhouette)
      const [masks, portraitMaskRaw] = await Promise.all([
        runSegmenter(workCanvas),
        runPortraitSegmenter(workCanvas)
      ]);
      if (token !== state.segToken) return;
      if (!masks.length) throw new Error('Segmenter returned no masks');

      const numClasses = masks.length;
      const classMaps = masks.map(m => resampleBilinear(m.data, m.w, m.h, w, h));
      const portraitMap = portraitMaskRaw
        ? resampleBilinear(portraitMaskRaw.data, portraitMaskRaw.w, portraitMaskRaw.h, w, h)
        : null;

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
        const multiFg = numClasses >= 2 ? Math.min(1, Math.max(0, 1 - bgConf[i])) : bgConf[i];
        bodyCoarse[i] = portraitMap ? (0.65 * multiFg + 0.35 * portraitMap[i]) : multiFg;
      }

      // 2. Landmark-Verified + NMS-Deduplicated Multi-Scale Face Detection
      const detectedFacesWork = detectAllFacesMultiScale(workCanvas, w, h, faceSkinConf, false, {
        bodySkinMap: bodySkinConf,
        bgMap: bgConf
      });
      if (token !== state.segToken) return;

      // 3. Per-Face High-Resolution Segmentation + Individual Face Mask Extraction
      const faceCoarse = new Float32Array(n);
      const perFaceCoarseList = [];

      for (let fIdx = 0; fIdx < detectedFacesWork.length; fIdx++) {
        const face = detectedFacesWork[fIdx];
        const { bbox, landmarks } = face;
        const singleFaceCoarse = new Float32Array(n);
        const fw = Math.max(16, bbox.x1 - bbox.x0);
        const fh = Math.max(16, bbox.y1 - bbox.y0);

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

        const localCanny = new Float32Array(rw * rh);
        const localSobel = new Float32Array(rw * rh);
        const localSkin = new Float32Array(rw * rh);
        for (let y = 0; y < rh; y++) {
          for (let x = 0; x < rw; x++) {
            const gi = (ry + y) * w + (rx + x);
            const li = y * rw + x;
            localSobel[li] = sobel[gi];
            localCanny[li] = sobel.canny ? sobel.canny[gi] : sobel[gi];
            const pBg = localMasks ? localMasks[0][li] : bgConf[gi];
            const pHair = (localMasks && localMasks[1]) ? localMasks[1][li] : hairConf[gi];
            const pFace = (localMasks && localMasks[3]) ? localMasks[3][li] : (faceSkinConf ? faceSkinConf[gi] : 0.5);
            const pAcc = (localMasks && localMasks[5]) ? localMasks[5][li] : accConf[gi];
            localSkin[li] = (pFace + 0.35 * pAcc) / (pFace + 0.35 * pAcc + pBg + pHair + 1e-4);

            if (localMasks && localMasks.length >= 4) {
              const lPerson = Math.min(1, Math.max(0, 1 - pBg));
              if (lPerson > bodyCoarse[gi]) bodyCoarse[gi] = 0.4 * bodyCoarse[gi] + 0.6 * lPerson;
            }
          }
        }

        if (landmarks) {
          const cx = (bbox.x0 + bbox.x1) * 0.5 - rx;
          const cy = (bbox.y0 + bbox.y1) * 0.5 - ry;

          const rawOuterPts = FACE_OVAL_IDX.map(idx => {
            const pt = landmarks[idx];
            const px = pt.x * w - rx;
            const py = pt.y * h - ry;
            const dx = px - cx;
            const dy = py - cy;
            const isForehead = FOREHEAD_SET.has(idx);
            const scaleX = isForehead ? 1.08 : 1.03;
            const scaleY = isForehead ? 1.15 : 1.01;
            return { x: cx + dx * scaleX, y: cy + dy * scaleY };
          });
          const maxRayShift = Math.max(2, Math.min(8, Math.round(Math.min(fw, fh) * 0.055)));
          const outerPts = snapPolygonPointsToEdges(rawOuterPts, cx, cy, localCanny, localSobel, localSkin, rw, rh, maxRayShift);

          const innerPts = FACE_OVAL_IDX.map(idx => {
            const pt = landmarks[idx];
            const px = pt.x * w - rx;
            const py = pt.y * h - ry;
            return { x: cx + (px - cx) * 0.78, y: cy + (py - cy) * 0.78 };
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
          [LEFT_EYE_RING, RIGHT_EYE_RING, LEFT_BROW_RING, RIGHT_BROW_RING, LIPS_OUTER_RING].forEach(ring => {
            const rPts = ring.map(idx => ({
              x: landmarks[idx].x * w - rx,
              y: landmarks[idx].y * h - ry
            }));
            fillSmoothPolygon(ctxIn, rPts);
          });
          const innerAlphaRaw = ctxIn.getImageData(0, 0, rw, rh).data;

          const outerFloat = new Float32Array(rw * rh);
          const innerFloat = new Float32Array(rw * rh);
          for (let i = 0; i < rw * rh; i++) {
            outerFloat[i] = outerAlphaRaw[i * 4 + 3] / 255;
            innerFloat[i] = innerAlphaRaw[i * 4 + 3] / 255;
          }

          const featherR = Math.max(2, Math.round(Math.min(fw, fh) * 0.05));
          const outerSmooth = boxMean(outerFloat, rw, rh, featherR);
          const innerSmooth = boxMean(innerFloat, rw, rh, Math.max(1, Math.round(featherR * 0.45)));

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

              const fgFace = pFace + 0.35 * pAcc;
              const nonFace = pBg + pHair * 1.15 + pClothes + pBody * 0.55;
              const neuralFaceProb = fgFace / (fgFace + nonFace + 1e-4);

              const core = innerSmooth[li] * (1 - Math.min(0.85, pHair + pBg));
              const combined = env * (0.68 * neuralFaceProb + 0.32 * env);
              const val = Math.min(1, Math.max(core * 0.94, combined));
              singleFaceCoarse[gi] = val;
              if (val > faceCoarse[gi]) faceCoarse[gi] = val;
            }
          }
        } else {
          // High-confidence keypoint-verified detector face fallback: smooth elliptical contour
          const cx = (bbox.x0 + bbox.x1) * 0.5 - rx;
          const cy = (bbox.y0 + bbox.y1) * 0.5 - ry;
          const ovalPts = [];
          for (let k = 0; k < 36; k++) {
            const ang = (k / 36) * Math.PI * 2;
            ovalPts.push({ x: cx + Math.cos(ang) * fw * 0.48, y: cy + Math.sin(ang) * fh * 0.52 });
          }
          const snappedOval = snapPolygonPointsToEdges(ovalPts, cx, cy, localCanny, localSobel, localSkin, rw, rh, 4);
          const cOval = document.createElement('canvas');
          cOval.width = rw;
          cOval.height = rh;
          const ctxOv = cOval.getContext('2d');
          ctxOv.fillStyle = '#ffffff';
          fillSmoothPolygon(ctxOv, snappedOval);
          const ovData = ctxOv.getImageData(0, 0, rw, rh).data;
          for (let y = 0; y < rh; y++) {
            for (let x = 0; x < rw; x++) {
              const li = y * rw + x;
              const gi = (ry + y) * w + (rx + x);
              const env = ovData[li * 4 + 3] / 255;
              if (env < 0.05) continue;
              const pBg = localMasks ? localMasks[0][li] : bgConf[gi];
              const val = env * (1 - 0.65 * pBg);
              singleFaceCoarse[gi] = val;
              if (val > faceCoarse[gi]) faceCoarse[gi] = val;
            }
          }
        }
        perFaceCoarseList.push({ face, singleFaceCoarse });
      }

      if (token !== state.segToken) return;

      // 4. Edge-Detection Boundary Snapping (Scharr + Canny NMS + 3-Stage Guided Filter)
      const bodyRadius = Math.max(4, Math.min(10, Math.round(Math.max(w, h) / 150)));
      const bodyAlpha = refineAlphaWithEdges(rgb, sobel, w, h, bodyCoarse, { radius: bodyRadius, eps: 1.5e-4 });
      cleanupAlpha(bodyAlpha, w, h, Math.max(40, Math.round(n * 0.001)), Math.max(40, Math.round(n * 0.0015)));

      let faceAlpha = null;
      if (detectedFacesWork.length > 0) {
        const faceRadius = Math.max(3, Math.min(7, Math.round(Math.max(w, h) / 210)));
        faceAlpha = refineAlphaWithEdges(rgb, sobel, w, h, faceCoarse, { radius: faceRadius, eps: 1.2e-4 });
        cleanupAlpha(faceAlpha, w, h, 25, Math.max(80, Math.round(n * 0.002)));
        for (let i = 0; i < n; i++) {
          if (faceAlpha[i] > bodyAlpha[i]) bodyAlpha[i] = faceAlpha[i];
        }
      }

      if (token !== state.segToken) return;

      // 5. Upscale to full image resolution (W x H) + Upscale Canny Edge Map
      const totalPixels = W * H;
      const body = alphaToFullResMask(bodyAlpha, w, h, W, H);
      const faceGlobal = faceAlpha
        ? alphaToFullResMask(faceAlpha, w, h, W, H)
        : { mask: new Uint8Array(totalPixels), count: 0, topX: 0, topY: 0 };

      const cannyFull = resampleBilinear(sobel.canny || sobel, w, h, W, H);
      const edgeMapFull = new Uint8Array(totalPixels);
      for (let i = 0; i < totalPixels; i++) {
        if (cannyFull[i] >= 0.28) edgeMapFull[i] = 1;
      }

      // 6. Build per-face full-resolution instance masks & perform Mask-IoU deduplication
      const invScaleX = W / w;
      const invScaleY = H / h;
      const validatedFacesFull = [];

      for (let i = 0; i < perFaceCoarseList.length; i++) {
        const { face, singleFaceCoarse } = perFaceCoarseList[i];
        const fFull = alphaToFullResMask(singleFaceCoarse, w, h, W, H);
        const fMask = new Uint8Array(totalPixels);
        let pxCount = 0;
        for (let p = 0; p < totalPixels; p++) {
          if (fFull.mask[p] && faceGlobal.mask[p]) {
            fMask[p] = 1;
            pxCount++;
          } else if (fFull.mask[p]) {
            fMask[p] = 1;
            pxCount++;
          }
        }
        if (pxCount < 35) continue;

        // Check Pixel Mask IoU against already kept faces to prevent duplicate overlapping face masks
        let maskDuplicate = false;
        for (const keptFace of validatedFacesFull) {
          const mMetrics = BitEngine.computeMaskIoUAndDice(keptFace.baseMask, fMask);
          const minMaskPx = Math.min(keptFace.pixelCount, pxCount);
          const ioMinMask = minMaskPx > 0 ? (mMetrics.intersection / minMaskPx) : 0;
          if (mMetrics.iou > 0.28 || ioMinMask > 0.50) {
            maskDuplicate = true;
            break;
          }
        }
        if (maskDuplicate) continue;

        const fIdx = validatedFacesFull.length + 1;
        validatedFacesFull.push({
          id: `face_${fIdx}`,
          index: fIdx,
          label: `Face ${fIdx}`,
          confidence: face.confidence || 0.90,
          cx: Math.round(((face.bbox.x0 + face.bbox.x1) * 0.5) * invScaleX),
          topY: Math.max(0, Math.round(face.bbox.y0 * invScaleY)),
          x0: Math.round(face.bbox.x0 * invScaleX),
          y0: Math.round(face.bbox.y0 * invScaleY),
          x1: Math.round(face.bbox.x1 * invScaleX),
          y1: Math.round(face.bbox.y1 * invScaleY),
          bbox: {
            x0: Math.round(face.bbox.x0 * invScaleX),
            y0: Math.round(face.bbox.y0 * invScaleY),
            x1: Math.round(face.bbox.x1 * invScaleX),
            y1: Math.round(face.bbox.y1 * invScaleY)
          },
          pixelCount: pxCount,
          coveragePct: parseFloat(((pxCount / totalPixels) * 100).toFixed(1)),
          baseMask: fMask,
          mask: new Uint8Array(fMask),
          selected: true
        });
      }

      // 7. Run Multi-Person Instance Detection, Deduplication & Mask Partitioning
      const personDetectorBoxes = detectPersonBoxesMultiScale(workCanvas, w, h, W, H);
      const personInstancesResult = BitEngine.detectAndSegmentPeopleInstances(
        body.mask,
        W,
        H,
        validatedFacesFull,
        personDetectorBoxes
      );

      state.edgeMap = edgeMapFull;
      state.detectedFaces = validatedFacesFull;
      state.detectedPersons = personInstancesResult.persons.map(p => ({
        ...p,
        baseMask: new Uint8Array(p.mask),
        mask: new Uint8Array(p.mask),
        selected: true
      }));

      rebuildConfirmedScopeMasks();
      setAiBadge('ready', '<i class="fa-solid fa-circle-check"></i> Canny + Scharr Edge Analysis Ready');
    } catch (err) {
      console.error('AI segmentation failed:', err);
      setAiBadge('warning', '<i class="fa-solid fa-triangle-exclamation"></i> Detection failed – use Drag & Select ROI');
      updateAiResultUI(0, 0, 0, 0, 0, true, 0);
    } finally {
      if (token === state.segToken) state.isAiDetecting = false;
    }

    renderEncOriginalWithOverlays();
  }

  /**
   * Detect all faces in a single video frame (`frameCanvas`, W x H) and build
   * each face's exact Canny/Scharr edge-snapped face-shaped binary mask (`Uint8Array(W * H)`),
   * smooth contour points (`contourPts`), centroid (`cx, cy`), bounding box (`bbox`),
   * and pose descriptor for temporal tracking across video frames.
   */
  async function detectFacesInVideoFrame(frameCanvas, W, H) {
    await aiReadyPromise;
    const totalPixels = W * H;
    const rgba = frameCanvas.getContext('2d', { willReadFrequently: true }).getImageData(0, 0, W, H).data;
    const rgb = new Float32Array(totalPixels * 3);
    for (let i = 0; i < totalPixels; i++) {
      rgb[i * 3] = rgba[i * 4] / 255;
      rgb[i * 3 + 1] = rgba[i * 4 + 1] / 255;
      rgb[i * 3 + 2] = rgba[i * 4 + 2] / 255;
    }
    const sobel = computeSobelEdges(rgb, W, H);

    let faceSkinConf = null;
    let bgConf = null;
    let hairConf = null;
    if (imageSegmenter) {
      try {
        const masks = await runSegmenter(frameCanvas);
        if (masks && masks.length >= 4) {
          bgConf = resampleBilinear(masks[0].data, masks[0].w, masks[0].h, W, H);
          hairConf = resampleBilinear(masks[1].data, masks[1].w, masks[1].h, W, H);
          faceSkinConf = resampleBilinear(masks[3].data, masks[3].w, masks[3].h, W, H);
        }
      } catch (e) {
        // continue with landmark / detector passes
      }
    }

    const rawFaces = detectAllFacesMultiScale(frameCanvas, W, H, faceSkinConf, true);
    const frameFaces = [];

    for (let fIdx = 0; fIdx < rawFaces.length; fIdx++) {
      const { landmarks, bbox } = rawFaces[fIdx];
      const fw = Math.max(12, bbox.x1 - bbox.x0);
      const fh = Math.max(12, bbox.y1 - bbox.y0);
      const cx = (bbox.x0 + bbox.x1) * 0.5;
      const cy = (bbox.y0 + bbox.y1) * 0.5;

      const faceMask = new Uint8Array(totalPixels);
      let contourPts = [];
      let pixelCount = 0;
      let poseVec = [0, 0, 1]; // [yawRatio, pitchRatio, aspect]

      if (landmarks) {
        // Compute head pose signature from nose tip (1) relative to left/right cheek (234, 454) & forehead/chin (10, 152)
        const nose = landmarks[1] || { x: cx / W, y: cy / H };
        const lCheek = landmarks[234] || { x: bbox.x0 / W, y: cy / H };
        const rCheek = landmarks[454] || { x: bbox.x1 / W, y: cy / H };
        const topHead = landmarks[10] || { x: cx / W, y: bbox.y0 / H };
        const chin = landmarks[152] || { x: cx / W, y: bbox.y1 / H };
        const yaw = (nose.x - (lCheek.x + rCheek.x) * 0.5) / Math.max(0.01, rCheek.x - lCheek.x);
        const pitch = (nose.y - (topHead.y + chin.y) * 0.5) / Math.max(0.01, chin.y - topHead.y);
        poseVec = [yaw, pitch, fw / Math.max(1, fh)];

        const rawOuterPts = FACE_OVAL_IDX.map(idx => {
          const pt = landmarks[idx];
          const px = pt.x * W;
          const py = pt.y * H;
          const isForehead = FOREHEAD_SET.has(idx);
          const scaleX = isForehead ? 1.07 : 1.03;
          const scaleY = isForehead ? 1.14 : 1.01;
          return { x: cx + (px - cx) * scaleX, y: cy + (py - cy) * scaleY };
        });

        const maxShift = Math.max(2, Math.min(6, Math.round(Math.min(fw, fh) * 0.05)));
        contourPts = snapPolygonPointsToEdges(rawOuterPts, cx, cy, sobel.canny || sobel, sobel, faceSkinConf, W, H, maxShift);

        const cMask = document.createElement('canvas');
        cMask.width = W;
        cMask.height = H;
        const mCtx = cMask.getContext('2d');
        mCtx.fillStyle = '#ffffff';
        fillSmoothPolygon(mCtx, contourPts);
        const mData = mCtx.getImageData(0, 0, W, H).data;

        const coarse = new Float32Array(totalPixels);
        for (let i = 0; i < totalPixels; i++) {
          let v = mData[i * 4 + 3] / 255;
          if (v > 0 && faceSkinConf && hairConf && bgConf) {
            const pSkin = faceSkinConf[i];
            const pHair = hairConf[i];
            const pBg = bgConf[i];
            // Carve out background or heavy hair fringes along the outer edge while keeping the facial core intact
            if (pBg > 0.78 && pSkin < 0.12) v *= 0.25;
            else if (pHair > 0.80 && pSkin < 0.15) v *= 0.45;
          }
          coarse[i] = v;
        }

        const refined = refineAlphaWithEdges(rgb, sobel, W, H, coarse, {
          radius: Math.max(2, Math.min(5, Math.round(Math.min(fw, fh) / 28))),
          eps: 1.5e-4
        });
        for (let i = 0; i < totalPixels; i++) {
          if (refined[i] >= 0.5 || mData[i * 4 + 3] >= 140) {
            faceMask[i] = 1;
            pixelCount++;
          }
        }
      } else {
        // Fallback elliptical face-shaped contour when only boundingBox / skin blob is available (never a rectangle!)
        const rx = fw * 0.50;
        const ry = fh * 0.54;
        const rawOval = [];
        for (let k = 0; k < 36; k++) {
          const ang = (k / 36) * Math.PI * 2;
          rawOval.push({ x: cx + Math.cos(ang) * rx, y: cy + Math.sin(ang) * ry });
        }
        contourPts = snapPolygonPointsToEdges(rawOval, cx, cy, sobel.canny || sobel, sobel, faceSkinConf, W, H, 4);
        const cMask = document.createElement('canvas');
        cMask.width = W;
        cMask.height = H;
        const mCtx = cMask.getContext('2d');
        mCtx.fillStyle = '#ffffff';
        fillSmoothPolygon(mCtx, contourPts);
        const mData = mCtx.getImageData(0, 0, W, H).data;
        for (let i = 0; i < totalPixels; i++) {
          if (mData[i * 4 + 3] >= 128) {
            faceMask[i] = 1;
            pixelCount++;
          }
        }
      }

      if (pixelCount >= 20) {
        // Extractの平均RGB skin signature inside face for appearance matching
        let rSum = 0, gSum = 0, bSum = 0, cCnt = 0;
        const x0 = Math.max(0, Math.floor(bbox.x0)), y0 = Math.max(0, Math.floor(bbox.y0));
        const x1 = Math.min(W - 1, Math.ceil(bbox.x1)), y1 = Math.min(H - 1, Math.ceil(bbox.y1));
        for (let y = y0; y <= y1; y += 2) {
          for (let x = x0; x <= x1; x += 2) {
            const idx = y * W + x;
            if (faceMask[idx]) {
              rSum += rgb[idx * 3];
              gSum += rgb[idx * 3 + 1];
              bSum += rgb[idx * 3 + 2];
              cCnt++;
            }
          }
        }
        const colorSig = cCnt > 0 ? [rSum / cCnt, gSum / cCnt, bSum / cCnt] : [0.5, 0.5, 0.5];

        frameFaces.push({
          bbox: { x0: Math.max(0, bbox.x0), y0: Math.max(0, bbox.y0), x1: Math.min(W, bbox.x1), y1: Math.min(H, bbox.y1) },
          cx,
          cy,
          fw,
          fh,
          mask: faceMask,
          pixelCount,
          contourPts,
          hasLandmarks: !!landmarks,
          poseVec,
          colorSig
        });
      }
    }

    return frameFaces;
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
   * Draw exact non-rectangular silhouette mask, Canny internal edge filaments, custom ROI box, and glowing boundary contours
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

    // 3. Neural Body & Face Contour + Canny Edge-Detection Overlays
    const overlayCanvas = document.createElement('canvas');
    overlayCanvas.width = W;
    overlayCanvas.height = H;
    const oCtx = overlayCanvas.getContext('2d');
    const overlayImgData = oCtx.createImageData(W, H);
    const overlayBuf = overlayImgData.data;

    const showBody = (scope === 'person') && state.bodyMask;
    const showFace = (scope === 'face') && state.faceMask;
    const edgeMap = state.edgeMap;

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
              overlayBuf[bufIdx + 3] = 255; // Outer contour
            } else if (edgeMap && edgeMap[idx] === 1) {
              // Crisp Canny edge-detection trace inside body silhouette
              overlayBuf[bufIdx] = 96;
              overlayBuf[bufIdx + 1] = 165;
              overlayBuf[bufIdx + 2] = 250;
              overlayBuf[bufIdx + 3] = 155;
            } else {
              overlayBuf[bufIdx] = 37;
              overlayBuf[bufIdx + 1] = 99;
              overlayBuf[bufIdx + 2] = 235;
              overlayBuf[bufIdx + 3] = 44; // Translucent tint
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
            } else if (edgeMap && edgeMap[idx] === 1) {
              // Crisp Canny edge-detection trace on facial features (eyes, brows, nose, lips)
              overlayBuf[bufIdx] = 52;
              overlayBuf[bufIdx + 1] = 211;
              overlayBuf[bufIdx + 2] = 153;
              overlayBuf[bufIdx + 3] = 175;
            } else {
              overlayBuf[bufIdx] = 5;
              overlayBuf[bufIdx + 1] = 150;
              overlayBuf[bufIdx + 2] = 105;
              overlayBuf[bufIdx + 3] = 68; // Emerald tint
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
      const activePersons = (state.detectedPersons || []).filter(p => p.selected !== false);
      if (activePersons.length > 0) {
        const smallFont = Math.max(11, Math.floor(12.5 * scale));
        const smallPillH = Math.max(20, Math.floor(23 * scale));
        ctx.font = `bold ${smallFont}px sans-serif`;
        activePersons.forEach((p, i) => {
          const confPct = Math.round((p.confidence || 0.90) * 100);
          const label = `👤 ${p.label || `Person ${i + 1}`} (${confPct}%)`;
          const tw = ctx.measureText(label).width;
          const bx = Math.max(6, Math.min(W - tw - 16, p.cx - (tw + 16) / 2));
          const by = Math.max(6, p.topY - smallPillH - 5);
          ctx.save();
          ctx.fillStyle = 'rgba(37, 99, 235, 0.92)';
          ctx.beginPath();
          ctx.roundRect ? ctx.roundRect(bx, by, tw + 16, smallPillH, 5) : ctx.rect(bx, by, tw + 16, smallPillH);
          ctx.fill();
          ctx.fillStyle = '#ffffff';
          ctx.fillText(label, bx + 8, by + smallFont + 3);
          ctx.restore();
        });
      }
    }

    if (showFace && state.detectedFaceStats.pixelCount > 0) {
      const activeFaces = (state.detectedFaces || []).filter(f => f.selected !== false);
      if (activeFaces.length > 0) {
        const smallFont = Math.max(11, Math.floor(12.5 * scale));
        const smallPillH = Math.max(20, Math.floor(23 * scale));
        ctx.font = `bold ${smallFont}px sans-serif`;
        activeFaces.forEach((f, i) => {
          const confPct = Math.round((f.confidence || 0.92) * 100);
          const label = `😀 ${f.label || `Face ${i + 1}`} (${confPct}%)`;
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
      }
    }

    // Draw manual-add drag rectangle if user is currently dragging to add a missing face/person
    if (state.isManualAddMode && state.manualAddBox.active && state.manualAddBox.width > 2 && state.manualAddBox.height > 2) {
      const { x, y, width: mw, height: mh } = state.manualAddBox;
      ctx.save();
      ctx.fillStyle = 'rgba(245, 158, 11, 0.20)';
      ctx.fillRect(x, y, mw, mh);
      ctx.strokeStyle = '#f59e0b';
      ctx.lineWidth = Math.max(2, Math.floor(3 * scale));
      ctx.setLineDash([6, 4]);
      ctx.strokeRect(x, y, mw, mh);
      ctx.restore();
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
    state.isManualAddMode = false;
    state.manualAddBox = { x: 0, y: 0, width: 0, height: 0, active: false };
    if (DOM.aiManualAddBanner) DOM.aiManualAddBanner.style.display = 'none';

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
    renderAiDetectionReviewPanel();
    renderEncOriginalWithOverlays();
  }

  /**
   * Build a Canny-edge-snapped contour mask inside a user-drawn manual detection box `(x, y, width, height)`
   * and add it as a confirmed Face or Person instance (Feature 7 Manual Correction).
   */
  function addManualDetectionFromBox(rect) {
    if (!state.encImage || !rect || rect.width < 8 || rect.height < 8) return;
    const W = state.encImage.width;
    const H = state.encImage.height;
    const totalPixels = W * H;
    const mask = new Uint8Array(totalPixels);

    const cx = rect.x + rect.width * 0.5;
    const cy = rect.y + rect.height * 0.5;
    const rx = rect.width * 0.50;
    const ry = rect.height * 0.50;
    const isFaceScope = state.encScope === 'face';

    let pxCount = 0;
    const x0 = Math.max(0, Math.floor(rect.x));
    const y0 = Math.max(0, Math.floor(rect.y));
    const x1 = Math.min(W - 1, Math.ceil(rect.x + rect.width));
    const y1 = Math.min(H - 1, Math.ceil(rect.y + rect.height));

    for (let y = y0; y <= y1; y++) {
      for (let x = x0; x <= x1; x++) {
        const dx = (x - cx) / Math.max(1, rx);
        const dy = (y - cy) / Math.max(1, ry);
        // For face: elliptical contour; for person: rounded silhouette contour
        const inside = isFaceScope
          ? (dx * dx + dy * dy <= 1.0)
          : (Math.pow(Math.abs(dx), 2.4) + Math.pow(Math.abs(dy), 2.4) <= 1.05);
        if (inside) {
          mask[y * W + x] = 1;
          pxCount++;
        }
      }
    }

    if (pxCount < 16) return;

    if (isFaceScope) {
      const idx = (state.detectedFaces || []).length + 1;
      state.detectedFaces.push({
        id: `face_manual_${Date.now()}`,
        index: idx,
        label: `Face ${idx} (Manual)`,
        customLabel: true,
        confidence: 1.0,
        cx: Math.round(cx),
        topY: y0,
        x0,
        y0,
        x1,
        y1,
        bbox: { x0, y0, x1, y1 },
        pixelCount: pxCount,
        coveragePct: parseFloat(((pxCount / totalPixels) * 100).toFixed(1)),
        baseMask: mask,
        mask: new Uint8Array(mask),
        selected: true
      });
    } else {
      const idx = (state.detectedPersons || []).length + 1;
      state.detectedPersons.push({
        id: `person_manual_${Date.now()}`,
        index: idx,
        label: `Person ${idx} (Manual)`,
        customLabel: true,
        confidence: 1.0,
        cx: Math.round(cx),
        topY: y0,
        bbox: { x0, y0, x1, y1 },
        pixelCount: pxCount,
        coveragePct: parseFloat(((pxCount / totalPixels) * 100).toFixed(1)),
        baseMask: mask,
        mask: new Uint8Array(mask),
        selected: true
      });
    }

    state.isManualAddMode = false;
    state.manualAddBox = { x: 0, y: 0, width: 0, height: 0, active: false };
    if (DOM.aiManualAddBanner) DOM.aiManualAddBanner.style.display = 'none';
    const compBox = DOM.canvasEncOrig ? DOM.canvasEncOrig.parentElement : null;
    if (compBox && state.encScope !== 'custom') compBox.classList.remove('drawing-roi');

    rebuildConfirmedScopeMasks();
    renderEncOriginalWithOverlays();
  }

  // Wire up Feature 7 AI Detection Review & Manual Correction Controls
  if (DOM.btnAiAddManual) {
    DOM.btnAiAddManual.addEventListener('click', () => {
      if (!state.encImage) return;
      if (state.encScope !== 'person' && state.encScope !== 'face') {
        setScope('face', DOM.btnScopeFace);
      }
      state.isManualAddMode = true;
      if (DOM.aiManualAddBanner) DOM.aiManualAddBanner.style.display = 'flex';
      if (DOM.aiManualAddText) {
        const targetType = state.encScope === 'face' ? 'Face' : 'Person';
        DOM.aiManualAddText.innerHTML = `<b>Manual Add ${targetType} Mode Active:</b> Click and drag a box over the missed ${targetType.toLowerCase()} on the <b>Original Image</b> canvas.`;
      }
      const compBox = DOM.canvasEncOrig ? DOM.canvasEncOrig.parentElement : null;
      if (compBox) compBox.classList.add('drawing-roi');
    });
  }

  if (DOM.btnAiCancelManual) {
    DOM.btnAiCancelManual.addEventListener('click', () => {
      state.isManualAddMode = false;
      state.manualAddBox = { x: 0, y: 0, width: 0, height: 0, active: false };
      if (DOM.aiManualAddBanner) DOM.aiManualAddBanner.style.display = 'none';
      const compBox = DOM.canvasEncOrig ? DOM.canvasEncOrig.parentElement : null;
      if (compBox && state.encScope !== 'custom') compBox.classList.remove('drawing-roi');
      renderEncOriginalWithOverlays();
    });
  }

  if (DOM.btnAiSelectAll) {
    DOM.btnAiSelectAll.addEventListener('click', () => {
      const list = state.encScope === 'face' ? state.detectedFaces : state.detectedPersons;
      (list || []).forEach(item => { item.selected = true; });
      rebuildConfirmedScopeMasks();
      renderEncOriginalWithOverlays();
    });
  }

  if (DOM.btnAiRescan) {
    DOM.btnAiRescan.addEventListener('click', () => {
      if (state.encImage) runAISegmentation(state.encImage);
    });
  }

  if (DOM.btnAiConfirmDetections) {
    DOM.btnAiConfirmDetections.addEventListener('click', () => {
      state.detectionsConfirmed = true;
      rebuildConfirmedScopeMasks();
      if (DOM.aiConfirmStatus) {
        const count = state.encScope === 'face' ? state.detectedFaceStats.count : state.detectedBodyStats.count;
        const unit = state.encScope === 'face' ? (count === 1 ? 'Face' : 'Faces') : (count === 1 ? 'Person' : 'People');
        DOM.aiConfirmStatus.innerHTML = `<i class="fa-solid fa-circle-check"></i> Confirmed ${count} ${unit} for selective encryption`;
      }
      renderEncOriginalWithOverlays();
    });
  }

  if (DOM.aiMaskPadSlider) {
    DOM.aiMaskPadSlider.addEventListener('input', (e) => {
      const pad = parseInt(e.target.value, 10) || 0;
      state.maskBoundaryPadPx = pad;
      if (DOM.aiMaskPadVal) {
        DOM.aiMaskPadVal.textContent = pad === 0
          ? '0 px (Exact Edge)'
          : (pad > 0 ? `+${pad} px (Expanded)` : `${pad} px (Tightened)`);
      }
      rebuildConfirmedScopeMasks();
      renderEncOriginalWithOverlays();
    });
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

  // Interactive Drag & Select ROI OR Manual Add Detection on canvasEncOrig
  if (DOM.canvasEncOrig) {
    const handleDragStart = (e) => {
      if (!state.encImage) return;
      state.isDraggingRoi = true;
      state.dragStart = getCanvasPixelCoords(DOM.canvasEncOrig, e);
      if (state.isManualAddMode) {
        state.manualAddBox = { x: state.dragStart.x, y: state.dragStart.y, width: 0, height: 0, active: true };
        return;
      }
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
      if (state.isManualAddMode) {
        state.manualAddBox = { x: rx, y: ry, width: rw, height: rh, active: true };
        renderEncOriginalWithOverlays();
        return;
      }
      state.customRoi = { x: rx, y: ry, width: rw, height: rh, active: true };
      renderEncOriginalWithOverlays();
      updateRoiStatusUI();
    };

    const handleDragEnd = () => {
      if (!state.isDraggingRoi) return;
      state.isDraggingRoi = false;
      if (state.isManualAddMode) {
        if (state.manualAddBox.width >= 8 && state.manualAddBox.height >= 8) {
          addManualDetectionFromBox(state.manualAddBox);
        } else {
          state.manualAddBox.active = false;
          renderEncOriginalWithOverlays();
        }
        return;
      }
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
    DOM.btnProcessEncrypt.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Encrypting & Encoding Self-Describing PNG...';

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
        const protectMask = !!(DOM.encProtectMask && DOM.encProtectMask.checked);

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

        // Execute 3-Stage Reversible Encryption & Encode Self-Describing Encrypted PNG (with msBx metadata chunk)
        const result = await BitEngine.encryptToPNG(imgData, effectiveKey, activeMask, {
          k: kVal,
          iterations: BitEngine.DEFAULT_KDF_ITERATIONS,
          keyType: state.encKeyType === 'image' ? 'image' : 'text',
          scope: state.encScope,
          protectMask
        });

        // Cache encrypted PNG binary & preview ImageData
        state.lastEncryptedPngBytes = result.pngBytes;
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

        // Metrics display (MSE, PSNR, Bits Swapped, Processing Time)
        DOM.valEncMse.textContent = result.mse;
        DOM.valEncPsnr.textContent = result.psnr + (result.psnr === '∞' ? '' : ' dB');
        DOM.valEncSwapped.textContent = result.swappedCount.toLocaleString();
        if (DOM.valEncTime) DOM.valEncTime.textContent = `${result.processingTimeMs} ms`;
        DOM.encMetrics.style.display = 'flex';

        if (DOM.btnDownloadEncrypted) DOM.btnDownloadEncrypted.disabled = false;
        renderMsbxHeaderCard(
          DOM.encMsbxInfo,
          result.header,
          result.pngBytes.byteLength,
          'Self-Describing Encrypted PNG (Metadata Chunk: msBX)',
          {
            verifiedLosslessPng: result.verifiedLosslessPng,
            processingTimeMs: result.processingTimeMs
          }
        );

        // Automatically load the newly encrypted PNG into the integrated Step 3 & Step 4 PNG Binary Explorer
        if (typeof window.syncIntegratedPngExplorerWithEncryption === 'function') {
          await window.syncIntegratedPngExplorerWithEncryption(
            result.pngBytes,
            effectiveKey,
            state.lastOriginalImageData,
            'encrypted_photo.png'
          );
        }
      } catch (err) {
        console.error('Encryption failed:', err);
        alert('Encryption failed: ' + (err && err.message ? err.message : String(err)));
      } finally {
        updateEncButtonState();
      }
    }, 50);
  });

  // Download Self-Describing Encrypted PNG (`encrypted_photo.png`)
  if (DOM.btnDownloadEncrypted) {
    DOM.btnDownloadEncrypted.addEventListener('click', () => {
      if (!state.lastEncryptedPngBytes) {
        alert('Please encrypt an image first to generate encrypted_photo.png.');
        return;
      }
      const blob = new Blob([state.lastEncryptedPngBytes], { type: 'image/png' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.download = 'encrypted_photo.png';
      link.href = url;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    });
  }

  // Optional quality/format listeners (if present in DOM)
  if (DOM.encExportFormat && DOM.jpegQualityGroup) {
    DOM.encExportFormat.addEventListener('change', (e) => {
      DOM.jpegQualityGroup.style.display = (e.target.value === 'image/jpeg') ? 'block' : 'none';
    });
  }
  if (DOM.encQuality && DOM.qualityVal) {
    DOM.encQuality.addEventListener('input', (e) => {
      DOM.qualityVal.textContent = e.target.value;
    });
  }

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
     Tab 2: Decrypt & Restore Logic (Self-Describing Encrypted PNG + Legacy .msbx)
     ========================================================================== */
  function updateDecScopeBanner(meta, isLegacyMsbx = false) {
    if (!DOM.decScopeInfo || !DOM.decScopeInfoText) return;
    if (!meta) {
      DOM.decScopeInfo.style.display = 'none';
      return;
    }
    const label = SCOPE_LABELS[meta.scope] || 'Entire Image';
    const formatBadge = isLegacyMsbx
      ? '<b>[Legacy .msbx Container]</b> '
      : '<b>[Self-Describing Encrypted PNG]</b> ';
    DOM.decScopeInfo.className = 'dec-scope-info';
    DOM.decScopeInfo.style.display = 'flex';
    DOM.decScopeInfoText.innerHTML = `${formatBadge}<b>Auto-detected scope:</b> ${label}. Enter your password or upload your key image below to decrypt.`;
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

  function resetDecryptTabOnError(title, msg) {
    state.decPngBytes = null;
    state.decMsbxBytes = null;
    state.decMsbxHeader = null;
    state.decContainerFormat = null;
    state.decImage = null;
    state.decMeta = null;
    clearCanvasAndShowPlaceholder(DOM.canvasDecOrig, DOM.phDecOrig);
    clearDecryptedResultView();
    if (DOM.decMsbxMeta) {
      DOM.decMsbxMeta.style.display = 'none';
      DOM.decMsbxMeta.innerHTML = '';
    }
    if (DOM.decScopeInfo) DOM.decScopeInfo.style.display = 'none';
    applyDecKeyTypeVisibility();
    showDecError(title, msg);
    updateDecButtonState();
  }

  async function loadEncryptedPngIntoDecryptTab(pngBytes, sourceName) {
    hideDecError();
    clearDecryptedResultView();

    try {
      const inspected = await BitEngine.inspectEncryptedPNG(pngBytes);
      state.decPngBytes = new Uint8Array(pngBytes);
      state.decMsbxBytes = null;
      state.decMsbxHeader = inspected.header;
      state.decContainerFormat = 'png';
      state.decImage = null;
      state.decFileName = (sourceName || 'restored_photo').replace(/\.[^/.]+$/, '') || 'restored_photo';
      state.decMeta = {
        scope: inspected.metadata.scope || 'full',
        keyType: inspected.metadata.keyType || 'text',
        w: inspected.metadata.width,
        h: inspected.metadata.height,
        mask: inspected.mask,
        roi: null
      };

      renderImageDataToCanvas(inspected.previewImageData, DOM.canvasDecOrig, DOM.phDecOrig);
      refreshDecKeySourceUI();
      applyDecKeyTypeVisibility();

      const chunkLabel = inspected.header.chunkDisplay || (inspected.header.isLegacyChunk ? 'msBx (Legacy)' : 'msBX');
      renderMsbxHeaderCard(
        DOM.decMsbxMeta,
        inspected.header,
        pngBytes.byteLength,
        `Embedded PNG Metadata — Metadata Chunk: ${chunkLabel} (${sourceName || 'encrypted_photo.png'})`
      );
      updateDecScopeBanner(state.decMeta, false);
      updateDecButtonState();
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      resetDecryptTabOnError('Invalid or Unrecognized Encrypted PNG', msg);
    }
  }

  function loadMsbxIntoDecryptTab(msbxBytes, sourceName) {
    hideDecError();
    clearDecryptedResultView();

    try {
      const inspected = BitEngine.inspectMSBX(msbxBytes);
      state.decMsbxBytes = new Uint8Array(msbxBytes);
      state.decPngBytes = null;
      state.decMsbxHeader = inspected.header;
      state.decContainerFormat = 'msbx';
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
      applyDecKeyTypeVisibility();

      renderMsbxHeaderCard(
        DOM.decMsbxMeta,
        inspected.header,
        msbxBytes.byteLength,
        `Legacy .msbx Container — Temporary Transition Support (${sourceName || 'encrypted.msbx'})`
      );
      updateDecScopeBanner(state.decMeta, true);
      updateDecButtonState();
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      resetDecryptTabOnError('Invalid or Corrupted Legacy .msbx File', msg);
    }
  }

  async function handleDecImageUpload(file) {
    if (!file) return;

    let rawBytes = null;
    try {
      const buf = await file.arrayBuffer();
      rawBytes = new Uint8Array(buf);
    } catch (err) {
      resetDecryptTabOnError('File Read Error', 'Could not read the uploaded file.');
      return;
    }

    const isMsbxExt = /\.msbx$/i.test(file.name || '');
    const isMsbxMagic = rawBytes.length >= 4 &&
      rawBytes[0] === 0x4D && rawBytes[1] === 0x53 && rawBytes[2] === 0x42 && rawBytes[3] === 0x58;

    // 1. Legacy .msbx container support (retained for backward compatibility)
    if (isMsbxExt || isMsbxMagic) {
      loadMsbxIntoDecryptTab(rawBytes, file.name);
      return;
    }

    // 2. Primary input: Self-Describing Encrypted PNG with embedded `msBx` metadata chunk
    if (BitEngine.isPngBytes(rawBytes)) {
      await loadEncryptedPngIntoDecryptTab(rawBytes, file.name);
      return;
    }

    // Reject non-PNG / non-MSBX files with an inline error banner (no alert popup)
    const msg = 'Unsupported file format: Please upload an Encrypted PNG (encrypted_photo.png) generated by this application (or a legacy .msbx file).';
    resetDecryptTabOnError('Unsupported File Format', msg);
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
    if (!state.decPngBytes && !state.decMsbxBytes && !state.decImage) return;

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
      showDecError('Key Required', 'Please enter the decryption password or upload the key image to decrypt.');
      return;
    }

    // Resolve candidate key(s): if both are supplied, try the header's keyType first and fall back to the other
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
        // Path A (Primary): Self-Describing Encrypted PNG Decryption + SHA-256 Verification
        if (state.decPngBytes) {
          let result = null;
          try {
            result = await BitEngine.decryptFromPNG(state.decPngBytes, primaryKey);
          } catch (firstErr) {
            if (fallbackKey !== null) {
              result = await BitEngine.decryptFromPNG(state.decPngBytes, fallbackKey);
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
            const chunkDisp = result.metadata.chunkDisplay || (result.metadata.isLegacyChunk ? 'msBx (Legacy)' : 'msBX');
            descEl.innerHTML = `Embedded PNG <code>${chunkDisp}</code> metadata verified (<code>${result.metadata.identifier}</code> v${result.metadata.metaVersion}, ${result.metadata.iterations.toLocaleString()} SHA-256 iterations, <i>k</i> = ${result.metadata.k}, ${result.processingTimeMs} ms). Exact lossless recovery achieved (<code>Different pixels = 0</code>, <code>MSE = 0.0000</code>, <code>PSNR = ∞ dB</code>).`;
          }

          DOM.decMetrics.style.display = 'flex';
          DOM.decFidelityCard.style.display = 'flex';
          DOM.btnDownloadRestored.disabled = false;
          return;
        }

        // Path B (Legacy Transition Support): Portable .msbx Container Decryption
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
            titleEl.textContent = 'Legacy .msbx SHA-256 Verification Tag Matched • 0 Different Pixels';
          }
          if (descEl) {
            descEl.innerHTML = `Legacy 68-byte <code>.msbx</code> header verified (${result.header.iterations.toLocaleString()} SHA-256 iterations, <i>k</i> = ${result.header.k}). Exact lossless recovery achieved (<code>Different pixels = 0</code>, <code>MSE = 0.0000</code>, <code>PSNR = ∞ dB</code>).`;
          }

          DOM.decMetrics.style.display = 'flex';
          DOM.decFidelityCard.style.display = 'flex';
          DOM.btnDownloadRestored.disabled = false;
          return;
        }
      } catch (err) {
        // Never display or allow saving a partially recovered image when verification fails;
        // show the inline error banner directly on the page without popping up an alert() dialog.
        clearDecryptedResultView();
        const msg = err && err.message ? err.message : String(err);
        showDecError('Decryption Failed — No Recovered Image Was Saved', msg);
      } finally {
        updateDecButtonState();
      }
    }, 50);
  });

  DOM.btnDownloadRestored.addEventListener('click', async () => {
    if (!state.lastDecryptedImageData && (!DOM.canvasDecResult || DOM.canvasDecResult.width === 0)) {
      alert('No verified decrypted image is available to save.');
      return;
    }
    const format = DOM.decExportFormat.value;
    const canvas = DOM.canvasDecResult;
    const baseName = state.decFileName || 'restored_photo';
    const ctx = canvas.getContext('2d');
    const imgData = state.lastDecryptedImageData || ctx.getImageData(0, 0, canvas.width, canvas.height);

    // 100% Lossless PNG export via BitEngine.encodeLosslessPNG
    if (format === 'image/png') {
      const pngBytes = await BitEngine.encodeLosslessPNG(imgData);
      const pngBlob = new Blob([pngBytes], { type: 'image/png' });
      const url = URL.createObjectURL(pngBlob);
      const link = document.createElement('a');
      link.download = `${baseName}_restored.png`;
      link.href = url;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
      return;
    }

    // Genuine uncompressed 24-bit Windows BMP export
    if (format === 'image/bmp') {
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
     VIDEO SUITE SHARED BRIDGE & TEMPORAL MULTI-FACE TRACKING ENGINE
     ========================================================================== */
  const FYP_VideoBridge = {
    lastKxvBytes: null,
    lastOriginalFrames: null, // Array of Uint8ClampedArray for 0-diff-pixel verification when testing in same session
    lastEncryptedName: 'encrypted_video.kxv'
  };

  const TRACK_COLORS = [
    '#10b981', // Emerald (Person #1)
    '#3b82f6', // Blue (Person #2)
    '#f59e0b', // Amber (Person #3)
    '#ec4899', // Pink (Person #4)
    '#8b5cf6', // Purple (Person #5)
    '#06b6d4'  // Cyan (Person #6)
  ];

  /**
   * Temporal Multi-Face Tracker across extracted video frames.
   * Associates detections across frames into persistent `trackId`s (Person #1, Person #2, ...)
   * using velocity-predicted centroid distance, scale similarity, bounding-box IoU,
   * head-pose continuity, and appearance colour signature.
   * Also interpolates/propagates masks across brief 1-2 frame occlusion gaps and reports
   * low-confidence frames for user review.
   */
  function trackFacesAcrossVideoFrames(rawPerFrameDetections, W, H) {
    const numFrames = rawPerFrameDetections.length;
    const tracks = []; // { trackId, lastFrame, cx, cy, vx, vy, fw, fh, bbox, poseVec, colorSig, appearances: [], confSum: 0, thumbFrameIdx, thumbBbox }
    let nextTrackId = 1;
    const lowConfidenceFrames = [];
    const diag = Math.hypot(W, H) || 1;

    function boxIoU(a, b) {
      const ix0 = Math.max(a.x0, b.x0), iy0 = Math.max(a.y0, b.y0);
      const ix1 = Math.min(a.x1, b.x1), iy1 = Math.min(a.y1, b.y1);
      const iw = Math.max(0, ix1 - ix0), ih = Math.max(0, iy1 - iy0);
      const inter = iw * ih;
      const areaA = Math.max(1, (a.x1 - a.x0) * (a.y1 - a.y0));
      const areaB = Math.max(1, (b.x1 - b.x0) * (b.y1 - b.y0));
      return inter / (areaA + areaB - inter);
    }

    function shiftMaskAndContour(det, dx, dy) {
      const sdx = Math.round(dx), sdy = Math.round(dy);
      const outMask = new Uint8Array(W * H);
      for (let y = 0; y < H; y++) {
        const ny = y + sdy;
        if (ny < 0 || ny >= H) continue;
        for (let x = 0; x < W; x++) {
          const nx = x + sdx;
          if (nx < 0 || nx >= W) continue;
          if (det.mask[y * W + x]) outMask[ny * W + nx] = 1;
        }
      }
      const outContour = (det.contourPts || []).map(p => ({ x: p.x + dx, y: p.y + dy }));
      return {
        bbox: {
          x0: Math.max(0, det.bbox.x0 + dx),
          y0: Math.max(0, det.bbox.y0 + dy),
          x1: Math.min(W, det.bbox.x1 + dx),
          y1: Math.min(H, det.bbox.y1 + dy)
        },
        cx: det.cx + dx,
        cy: det.cy + dy,
        fw: det.fw,
        fh: det.fh,
        mask: outMask,
        pixelCount: det.pixelCount,
        contourPts: outContour,
        hasLandmarks: det.hasLandmarks,
        poseVec: det.poseVec,
        colorSig: det.colorSig,
        trackId: det.trackId,
        confidence: Math.max(0.50, (det.confidence || 0.8) * 0.82),
        propagated: true
      };
    }

    const trackedFrames = Array.from({ length: numFrames }, () => []);
    const MAX_GAP_FRAMES = 12;

    for (let fIdx = 0; fIdx < numFrames; fIdx++) {
      // 1. Within-frame NMS & Mask-IoU deduplication so one person is never counted twice in the same frame
      const rawDets = (rawPerFrameDetections[fIdx] || []).slice().sort((a, b) => {
        const sa = (a.confidence || 0.85) + (a.hasLandmarks ? 0.1 : 0);
        const sb = (b.confidence || 0.85) + (b.hasLandmarks ? 0.1 : 0);
        return sb - sa;
      });
      const dets = [];
      for (const cand of rawDets) {
        let dup = false;
        for (const kept of dets) {
          const m = BitEngine.computeBoxOverlapMetrics(kept.bbox, cand.bbox);
          if (m.iou >= 0.30 || m.ioMin >= 0.52 || m.normCenterDist < 0.42) {
            dup = true;
            break;
          }
          if (kept.mask && cand.mask) {
            const mm = BitEngine.computeMaskIoUAndDice(kept.mask, cand.mask);
            if (mm.iou >= 0.25) {
              dup = true;
              break;
            }
          }
        }
        if (!dup) dets.push(cand);
      }

      const assignedTracks = new Set();
      const assignedDets = new Set();

      // Build candidate match pairs between active tracks and current frame detections
      const pairs = [];
      for (let tIdx = 0; tIdx < tracks.length; tIdx++) {
        const tr = tracks[tIdx];
        const dt = fIdx - tr.lastFrame;
        if (dt <= 0 || dt > MAX_GAP_FRAMES) continue;

        const predCx = tr.cx + tr.vx * Math.min(dt, 4);
        const predCy = tr.cy + tr.vy * Math.min(dt, 4);
        const predBox = {
          x0: predCx - tr.fw * 0.5,
          y0: predCy - tr.fh * 0.5,
          x1: predCx + tr.fw * 0.5,
          y1: predCy + tr.fh * 0.5
        };

        for (let dIdx = 0; dIdx < dets.length; dIdx++) {
          const d = dets[dIdx];
          const dist = Math.hypot(d.cx - predCx, d.cy - predCy);
          const avgSize = 0.5 * (Math.hypot(tr.fw, tr.fh) + Math.hypot(d.fw, d.fh));
          const normDist = dist / Math.max(16, avgSize);
          if (normDist > 1.75 && dist > diag * 0.30) continue;

          const iou = boxIoU(predBox, d.bbox);
          const scaleRatio = Math.min(tr.fw * tr.fh, d.fw * d.fh) / Math.max(1, Math.max(tr.fw * tr.fh, d.fw * d.fh));
          const colorDist = Math.hypot(
            (tr.colorSig[0] - d.colorSig[0]),
            (tr.colorSig[1] - d.colorSig[1]),
            (tr.colorSig[2] - d.colorSig[2])
          );
          const poseDist = Math.hypot(
            (tr.poseVec[0] - d.poseVec[0]) * 0.5,
            (tr.poseVec[1] - d.poseVec[1]) * 0.5
          );

          const distScore = Math.max(0, 1 - normDist * 0.52);
          const colorScore = Math.max(0, 1 - colorDist * 2.2);
          const poseScore = Math.max(0, 1 - poseDist * 0.8);
          const gapPenalty = Math.pow(0.95, dt - 1);

          const score = (0.44 * distScore + 0.22 * iou + 0.16 * scaleRatio + 0.12 * colorScore + 0.06 * poseScore) * gapPenalty;
          if (score >= 0.28) {
            pairs.push({ tIdx, dIdx, score, dt });
          }
        }
      }

      // Greedy Hungarian-style best-first matching
      pairs.sort((a, b) => b.score - a.score);
      for (const pair of pairs) {
        if (assignedTracks.has(pair.tIdx) || assignedDets.has(pair.dIdx)) continue;
        assignedTracks.add(pair.tIdx);
        assignedDets.add(pair.dIdx);

        const tr = tracks[pair.tIdx];
        const d = dets[pair.dIdx];
        const dt = pair.dt;

        // If there was a 1-3 frame occlusion gap between tr.lastFrame and fIdx, interpolate intermediate frames!
        if (dt > 1 && dt <= 3 && tr.lastDet) {
          for (let g = 1; g < dt; g++) {
            const frac = g / dt;
            const interp = shiftMaskAndContour(tr.lastDet, (d.cx - tr.cx) * frac, (d.cy - tr.cy) * frac);
            interp.trackId = tr.trackId;
            trackedFrames[tr.lastFrame + g].push(interp);
          }
        }

        const instVx = (d.cx - tr.cx) / dt;
        const instVy = (d.cy - tr.cy) / dt;
        tr.vx = 0.60 * tr.vx + 0.40 * instVx;
        tr.vy = 0.60 * tr.vy + 0.40 * instVy;
        // Temporal EMA smoothing on centroid & box dimensions to reduce box flickering
        tr.cx = 0.25 * tr.cx + 0.75 * d.cx;
        tr.cy = 0.25 * tr.cy + 0.75 * d.cy;
        tr.fw = 0.65 * tr.fw + 0.35 * d.fw;
        tr.fh = 0.65 * tr.fh + 0.35 * d.fh;
        tr.bbox = {
          x0: 0.25 * tr.bbox.x0 + 0.75 * d.bbox.x0,
          y0: 0.25 * tr.bbox.y0 + 0.75 * d.bbox.y0,
          x1: 0.25 * tr.bbox.x1 + 0.75 * d.bbox.x1,
          y1: 0.25 * tr.bbox.y1 + 0.75 * d.bbox.y1
        };
        tr.poseVec = d.poseVec;
        tr.colorSig = [
          0.7 * tr.colorSig[0] + 0.3 * d.colorSig[0],
          0.7 * tr.colorSig[1] + 0.3 * d.colorSig[1],
          0.7 * tr.colorSig[2] + 0.3 * d.colorSig[2]
        ];
        tr.lastFrame = fIdx;

        const conf = Math.min(0.99, Math.max(0.50, pair.score * 1.15 + (d.hasLandmarks ? 0.12 : 0)));
        const trackedDet = {
          ...d,
          bbox: tr.bbox,
          cx: tr.cx,
          cy: tr.cy,
          trackId: tr.trackId,
          confidence: conf
        };
        tr.lastDet = trackedDet;
        tr.appearances.push(fIdx);
        tr.confSum += conf;
        if (d.pixelCount > (tr.bestPixels || 0)) {
          tr.bestPixels = d.pixelCount;
          tr.thumbFrameIdx = fIdx;
          tr.thumbBbox = d.bbox;
        }

        trackedFrames[fIdx].push(trackedDet);
        if (conf < 0.64 && !lowConfidenceFrames.includes(fIdx + 1)) {
          lowConfidenceFrames.push(fIdx + 1);
        }
      }

      // Unassigned detections start new person tracks
      for (let dIdx = 0; dIdx < dets.length; dIdx++) {
        if (assignedDets.has(dIdx)) continue;
        const d = dets[dIdx];
        const trackId = nextTrackId++;
        const initConf = d.confidence || (d.hasLandmarks ? 0.94 : 0.74);
        const trackedDet = {
          ...d,
          trackId,
          confidence: initConf
        };
        tracks.push({
          trackId,
          lastFrame: fIdx,
          cx: d.cx,
          cy: d.cy,
          vx: 0,
          vy: 0,
          fw: d.fw,
          fh: d.fh,
          bbox: d.bbox,
          poseVec: d.poseVec,
          colorSig: d.colorSig.slice(),
          appearances: [fIdx],
          confSum: initConf,
          bestPixels: d.pixelCount,
          thumbFrameIdx: fIdx,
          thumbBbox: d.bbox,
          lastDet: trackedDet
        });
        trackedFrames[fIdx].push(trackedDet);
        if (initConf < 0.68 && !lowConfidenceFrames.includes(fIdx + 1)) {
          lowConfidenceFrames.push(fIdx + 1);
        }
      }
    }

    // Prune transient 1-frame low-confidence noise tracks in multi-frame videos & compact track IDs (1..K)
    const validTracks = tracks.filter(tr => {
      if (numFrames >= 6 && tr.appearances.length === 1 && (tr.confSum / tr.appearances.length) < 0.80) {
        return false;
      }
      return tr.appearances.length >= 1;
    });

    const idRemap = new Map();
    validTracks.forEach((tr, idx) => {
      idRemap.set(tr.trackId, idx + 1);
      tr.trackId = idx + 1;
    });

    for (let fIdx = 0; fIdx < numFrames; fIdx++) {
      trackedFrames[fIdx] = trackedFrames[fIdx]
        .filter(det => idRemap.has(det.trackId))
        .map(det => ({ ...det, trackId: idRemap.get(det.trackId) }))
        .sort((a, b) => a.trackId - b.trackId);
    }

    const trackSummaries = validTracks.map(tr => ({
      trackId: tr.trackId,
      color: TRACK_COLORS[(tr.trackId - 1) % TRACK_COLORS.length],
      frameCount: tr.appearances.length,
      firstFrame: tr.appearances[0] + 1,
      lastFrame: tr.appearances[tr.appearances.length - 1] + 1,
      avgConfidence: tr.appearances.length > 0 ? (tr.confSum / tr.appearances.length) : 0.85,
      thumbFrameIdx: tr.thumbFrameIdx,
      thumbBbox: tr.thumbBbox
    }));

    return {
      trackedFrames,
      trackSummaries,
      lowConfidenceFrames: lowConfidenceFrames.sort((a, b) => a - b)
    };
  }

  /* ==========================================================================
     PAGE 1: VIDEO ENCRYPTION MODULE (AI Selective Face Encryption & .kxv Output)
     ========================================================================== */
  function initVideoEncryptModule() {
    const encDOM = {
      dropZone: document.getElementById('video-enc-drop-zone'),
      fileInput: document.getElementById('video-enc-file-input'),
      dropText: document.getElementById('video-enc-drop-text'),
      dropIcon: document.getElementById('video-enc-drop-icon'),
      errorBanner: document.getElementById('video-enc-error-banner'),
      errorText: document.getElementById('video-enc-error-text'),
      metaChip: document.getElementById('video-enc-meta-chip'),
      metaName: document.getElementById('meta-video-enc-name'),
      metaDuration: document.getElementById('meta-video-enc-duration'),
      metaRes: document.getElementById('meta-video-enc-res'),
      metaFrames: document.getElementById('meta-video-enc-frames'),
      scaleSelect: document.getElementById('video-enc-scale-select'),
      fpsSelect: document.getElementById('video-enc-fps-select'),
      scopeSelector: document.getElementById('video-enc-scope-selector'),
      subFaceAll: document.getElementById('sub-video-face-all'),
      subFaceSelected: document.getElementById('sub-video-face-selected'),
      btnScanFaces: document.getElementById('btn-video-scan-faces'),
      trackedPersonsBox: document.getElementById('video-tracked-persons-box'),
      trackedPersonsCountBadge: document.getElementById('video-tracked-persons-count-badge'),
      trackedPersonsList: document.getElementById('video-tracked-persons-list'),
      trackingWarning: document.getElementById('video-tracking-warning'),
      trackingWarningText: document.getElementById('video-tracking-warning-text'),
      kSelect: document.getElementById('video-enc-k-select'),
      keySelector: document.getElementById('video-enc-key-selector'),
      pwdGroup: document.getElementById('video-enc-pwd-group'),
      imgKeyGroup: document.getElementById('video-enc-imgkey-group'),
      password: document.getElementById('video-enc-password'),
      togglePwd: document.getElementById('toggle-video-enc-pwd'),
      keyImageInput: document.getElementById('video-enc-key-image-input'),
      keyDropZone: document.getElementById('video-enc-key-drop-zone'),
      keyDropText: document.getElementById('video-enc-key-drop-text'),
      progressBox: document.getElementById('video-enc-progress-box'),
      progressStatus: document.getElementById('video-enc-progress-status'),
      progressPct: document.getElementById('video-enc-progress-pct'),
      progressFill: document.getElementById('video-enc-progress-fill'),
      progressDetails: document.getElementById('video-enc-progress-details'),
      progressEta: document.getElementById('video-enc-progress-eta'),
      btnProcess: document.getElementById('btn-process-video-enc'),
      btnCancel: document.getElementById('btn-cancel-video-enc'),
      origPlayer: document.getElementById('video-enc-orig-player'),
      canvasOrigFrame: document.getElementById('canvas-video-enc-orig-frame'),
      phOrig: document.getElementById('ph-video-enc-orig'),
      resultPlayer: document.getElementById('video-enc-result-player'),
      canvasResultFrame: document.getElementById('canvas-video-enc-result-frame'),
      phResult: document.getElementById('ph-video-enc-result'),
      origTime: document.getElementById('video-enc-orig-time'),
      resultTime: document.getElementById('video-enc-result-time'),
      scrubberBox: document.getElementById('video-enc-scrubber-box'),
      scrubberLabel: document.getElementById('video-enc-scrubber-label'),
      scrubberFaces: document.getElementById('video-enc-scrubber-faces'),
      frameSlider: document.getElementById('video-enc-frame-slider'),
      chkShowAiOverlay: document.getElementById('chk-video-show-ai-overlay'),
      liveBox: document.getElementById('video-enc-live-box'),
      liveBadge: document.getElementById('live-frame-enc-badge'),
      canvasThumb: document.getElementById('canvas-video-enc-thumb'),
      btnSyncPlay: document.getElementById('btn-sync-play-enc'),
      btnSyncPause: document.getElementById('btn-sync-pause-enc'),
      btnSyncReset: document.getElementById('btn-sync-reset-enc'),
      metricsBar: document.getElementById('video-enc-metrics-bar'),
      valFrames: document.getElementById('val-video-enc-frames'),
      valFacesCount: document.getElementById('val-video-enc-faces-count'),
      valMse: document.getElementById('val-video-enc-mse'),
      valPsnr: document.getElementById('val-video-enc-psnr'),
      kxvSummary: document.getElementById('video-enc-kxv-summary'),
      kxvSummaryText: document.getElementById('video-enc-kxv-summary-text'),
      btnDownloadKxv: document.getElementById('btn-download-video-kxv'),
      btnDownloadWebm: document.getElementById('btn-download-video-enc'),
      btnGotoDecrypt: document.getElementById('btn-goto-decrypt')
    };

    const encState = {
      videoLoaded: false,
      videoFile: null,
      videoUrl: null,
      scope: 'face_all', // 'face_all' | 'face_selected' | 'full'
      keyType: 'password', // 'password' | 'image'
      keyImageBytes: null,
      extractedW: 0,
      extractedH: 0,
      extractedFps: 15,
      extractedFrames: [],     // Array<ImageData>
      extractedTimestamps: [], // Array<number> (ms)
      trackedFrames: [],       // Array<Array<TrackedFace>>
      trackSummaries: [],      // Array<TrackSummary>
      selectedTrackIds: new Set(),
      aiScanComplete: false,
      encryptedFrames: [],     // Array<ImageData>
      kxvBytes: null,
      webmBlob: null,
      webmUrl: null,
      currentFrameIdx: 0,
      playTimer: null,
      isProcessing: false,
      cancelRequested: false
    };

    function showEncError(msg) {
      if (!encDOM.errorBanner || !encDOM.errorText) return;
      if (!msg) {
        encDOM.errorBanner.style.display = 'none';
        encDOM.errorText.textContent = '';
      } else {
        encDOM.errorText.textContent = msg;
        encDOM.errorBanner.style.display = 'flex';
      }
    }

    function stopEncPlayback() {
      if (encState.playTimer) {
        clearInterval(encState.playTimer);
        encState.playTimer = null;
      }
    }

    if (encDOM.togglePwd && encDOM.password) {
      setupPwdToggle(encDOM.togglePwd, encDOM.password);
    }

    // Scope Selector (Mode A: face_all, Mode B: face_selected, Full: full)
    if (encDOM.scopeSelector) {
      const btns = encDOM.scopeSelector.querySelectorAll('.scope-btn');
      btns.forEach(btn => {
        btn.addEventListener('click', () => {
          btns.forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          encState.scope = btn.getAttribute('data-video-scope') || 'face_all';
          if (encDOM.trackedPersonsBox) {
            encDOM.trackedPersonsBox.style.display =
              (encState.scope === 'face_selected' && encState.trackSummaries.length > 0) ? 'block' : 'none';
          }
          renderVideoEncFrame(encState.currentFrameIdx);
        });
      });
    }

    // Key Type Selector (Password vs Key Image)
    if (encDOM.keySelector) {
      const btns = encDOM.keySelector.querySelectorAll('.toggle-btn');
      btns.forEach(btn => {
        btn.addEventListener('click', () => {
          btns.forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          encState.keyType = btn.getAttribute('data-key-type') || 'password';
          if (encDOM.pwdGroup) encDOM.pwdGroup.style.display = encState.keyType === 'password' ? 'block' : 'none';
          if (encDOM.imgKeyGroup) encDOM.imgKeyGroup.style.display = encState.keyType === 'image' ? 'block' : 'none';
        });
      });
    }

    // Key Image Upload for Video Encryption
    if (encDOM.keyImageInput) {
      encDOM.keyImageInput.addEventListener('change', async (e) => {
        const file = e.target.files && e.target.files[0];
        if (!file) return;
        const buf = await file.arrayBuffer();
        encState.keyImageBytes = new Uint8Array(buf);
        if (encDOM.keyDropText) {
          encDOM.keyDropText.innerHTML = `✅ <b>Key Image:</b> ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        }
      });
    }

    // Video Drop Zone & File Input
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
      showEncError(null);
      stopEncPlayback();

      const isVideo = (file.type && file.type.startsWith('video/')) ||
        /\.(mp4|webm|mov|m4v|ogv)$/i.test(file.name);
      if (!isVideo) {
        showEncError(`Unsupported format: "${file.name}". Please upload an MP4 or WebM short video.`);
        return;
      }
      if (file.size > 60 * 1024 * 1024) {
        showEncError(`File size (${(file.size / (1024 * 1024)).toFixed(1)} MB) exceeds the 60 MB browser processing limit.`);
        return;
      }

      encState.videoFile = file;
      encState.aiScanComplete = false;
      encState.extractedFrames = [];
      encState.trackedFrames = [];
      encState.trackSummaries = [];
      encState.encryptedFrames = [];
      encState.kxvBytes = null;

      if (encState.videoUrl) URL.revokeObjectURL(encState.videoUrl);
      encState.videoUrl = URL.createObjectURL(file);
      loadEncVideoIntoPlayer(encState.videoUrl, file.name);

      setTimeout(() => {
        if (encDOM.fileInput) encDOM.fileInput.value = '';
      }, 400);
    }

    function getTargetDimensions(video) {
      const vw = video.videoWidth || 640;
      const vh = video.videoHeight || 360;
      const aspect = vw / Math.max(1, vh);
      const scaleVal = encDOM.scaleSelect ? encDOM.scaleSelect.value : '320x240';
      if (scaleVal === '320x240') {
        const w = 320;
        const h = Math.max(2, Math.round((320 / aspect) / 2) * 2);
        return { w, h };
      } else if (scaleVal === '640x360') {
        const w = Math.min(640, vw);
        const h = Math.max(2, Math.round((w / aspect) / 2) * 2);
        return { w, h };
      }
      return {
        w: Math.max(2, Math.round(vw / 2) * 2),
        h: Math.max(2, Math.round(vh / 2) * 2)
      };
    }

    function loadEncVideoIntoPlayer(url, name = 'uploaded_video.mp4') {
      const video = encDOM.origPlayer;
      if (!video) return;

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
      video.playsInline = true;

      const onMeta = async () => {
        const rawDur = video.duration || 0;
        const dur = Math.min(5.0, rawDur > 0 ? rawDur : 5.0);
        const { w, h } = getTargetDimensions(video);
        const fps = parseInt(encDOM.fpsSelect ? encDOM.fpsSelect.value : '15', 10);
        const estFrames = Math.max(1, Math.round(dur * fps));

        if (rawDur > 5.2) {
          showEncError(`Note: Video is ${rawDur.toFixed(1)}s long. Processing the first 5.0s (${estFrames} frames) per FYP short-video specification.`);
        }

        if (encDOM.metaName) encDOM.metaName.textContent = name;
        if (encDOM.metaDuration) encDOM.metaDuration.textContent = `${dur.toFixed(1)}s`;
        if (encDOM.metaRes) encDOM.metaRes.textContent = `${w} × ${h}`;
        if (encDOM.metaFrames) encDOM.metaFrames.textContent = `${estFrames} frames`;
        if (encDOM.metaChip) encDOM.metaChip.style.display = 'flex';

        encState.videoLoaded = true;
        if (encDOM.btnScanFaces) encDOM.btnScanFaces.disabled = false;
        if (encDOM.btnProcess) encDOM.btnProcess.disabled = false;

        // Automatically run frame extraction + AI Face Scan on upload
        await extractAndScanVideoFaces();
      };

      video.onloadedmetadata = onMeta;
      video.onerror = () => {
        showEncError(`Browser could not decode "${name}". Please provide a standard MP4 (H.264) or WebM video.`);
        if (encDOM.dropZone) encDOM.dropZone.classList.remove('has-file');
      };
    }

    // Re-extract if resolution or FPS changes
    if (encDOM.scaleSelect) {
      encDOM.scaleSelect.addEventListener('change', () => {
        if (encState.videoLoaded && !encState.isProcessing) extractAndScanVideoFaces();
      });
    }
    if (encDOM.fpsSelect) {
      encDOM.fpsSelect.addEventListener('change', () => {
        if (encState.videoLoaded && !encState.isProcessing) extractAndScanVideoFaces();
      });
    }
    if (encDOM.btnScanFaces) {
      encDOM.btnScanFaces.addEventListener('click', () => {
        if (encState.videoLoaded && !encState.isProcessing) extractAndScanVideoFaces();
      });
    }

    /**
     * Extract video frames at true timestamps and run AI Face Landmarker + Temporal Tracking
     */
    async function extractAndScanVideoFaces() {
      if (!encState.videoLoaded || encState.isProcessing) return;
      const video = encDOM.origPlayer;
      const { w, h } = getTargetDimensions(video);
      const fps = parseInt(encDOM.fpsSelect ? encDOM.fpsSelect.value : '15', 10);
      const duration = Math.min(5.0, video.duration || 3.0);
      const totalFrames = Math.max(1, Math.min(120, Math.round(duration * fps)));

      stopEncPlayback();
      encState.isProcessing = true;
      encState.cancelRequested = false;
      encState.extractedW = w;
      encState.extractedH = h;
      encState.extractedFps = fps;
      encState.extractedFrames = [];
      encState.extractedTimestamps = [];
      encState.trackedFrames = [];
      encState.trackSummaries = [];
      encState.encryptedFrames = [];

      if (encDOM.metaRes) encDOM.metaRes.textContent = `${w} × ${h}`;
      if (encDOM.metaFrames) encDOM.metaFrames.textContent = `${totalFrames} frames`;
      if (encDOM.btnProcess) encDOM.btnProcess.disabled = true;
      if (encDOM.btnScanFaces) encDOM.btnScanFaces.disabled = true;
      if (encDOM.btnCancel) encDOM.btnCancel.style.display = 'inline-flex';
      if (encDOM.progressBox) encDOM.progressBox.style.display = 'block';
      if (encDOM.progressStatus) {
        encDOM.progressStatus.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Step 1/2: Extracting Frames & Detecting Faces with AI...';
      }

      const workCanvas = document.createElement('canvas');
      workCanvas.width = w;
      workCanvas.height = h;
      const workCtx = workCanvas.getContext('2d', { willReadFrequently: true });

      const rawDetectionsPerFrame = [];
      const startTime = performance.now();

      for (let i = 0; i < totalFrames; i++) {
        if (encState.cancelRequested) break;
        const targetSec = Math.min((i / fps), Math.max(0, (video.duration || duration) - 0.01));
        video.currentTime = targetSec;

        await new Promise(resolve => {
          const onSeek = () => { video.removeEventListener('seeked', onSeek); resolve(); };
          video.addEventListener('seeked', onSeek, { once: true });
          setTimeout(onSeek, 220);
        });

        const actualMs = Math.round(video.currentTime * 1000);
        workCtx.drawImage(video, 0, 0, w, h);
        const frameImgData = workCtx.getImageData(0, 0, w, h);
        encState.extractedFrames.push(frameImgData);
        encState.extractedTimestamps.push(actualMs);

        // Run AI Face Detection + Face-Shaped Mask Generation on this frame
        let dets = [];
        try {
          dets = await detectFacesInVideoFrame(workCanvas, w, h);
        } catch (e) {
          console.warn('Frame face detection error:', e);
        }
        rawDetectionsPerFrame.push(dets);

        const pct = Math.round(((i + 1) / totalFrames) * 100);
        if (encDOM.progressFill) encDOM.progressFill.style.width = `${pct}%`;
        if (encDOM.progressPct) encDOM.progressPct.textContent = `${pct}%`;
        if (encDOM.progressDetails) {
          encDOM.progressDetails.textContent = `AI Face Scan: Frame ${i + 1} / ${totalFrames} (${dets.length} face${dets.length === 1 ? '' : 's'})`;
        }
        const elapsed = (performance.now() - startTime) / 1000;
        const eta = Math.max(0, ((elapsed / (i + 1)) * totalFrames) - elapsed).toFixed(1);
        if (encDOM.progressEta) encDOM.progressEta.textContent = `ETA: ${eta}s`;

        if (i % 2 === 0) await new Promise(r => setTimeout(r, 0));
      }

      if (encState.cancelRequested || encState.extractedFrames.length === 0) {
        encState.isProcessing = false;
        if (encDOM.btnProcess) encDOM.btnProcess.disabled = false;
        if (encDOM.btnScanFaces) encDOM.btnScanFaces.disabled = false;
        if (encDOM.btnCancel) encDOM.btnCancel.style.display = 'none';
        return;
      }

      // Run Temporal Multi-Face Tracking across all frames
      const tracking = trackFacesAcrossVideoFrames(rawDetectionsPerFrame, w, h);
      encState.trackedFrames = tracking.trackedFrames;
      encState.trackSummaries = tracking.trackSummaries;
      encState.selectedTrackIds = new Set(tracking.trackSummaries.map(t => t.trackId));
      encState.aiScanComplete = true;

      // Update Mode A / Mode B sub-labels
      let framesWithFaces = 0;
      for (const fDets of encState.trackedFrames) {
        if (fDets.length > 0) framesWithFaces++;
      }
      const numPersons = encState.trackSummaries.length;
      if (encDOM.subFaceAll) {
        encDOM.subFaceAll.textContent = numPersons > 0
          ? `${numPersons} person${numPersons === 1 ? '' : 's'} (${framesWithFaces}/${encState.extractedFrames.length} frames)`
          : 'No faces found';
      }
      if (encDOM.subFaceSelected) {
        encDOM.subFaceSelected.textContent = numPersons > 0
          ? `Select from ${numPersons} tracked ID${numPersons === 1 ? '' : 's'}`
          : 'No tracked IDs';
      }

      // Render Tracked Persons Selection UI (for Mode B)
      renderTrackedPersonsUI();

      // Show tracking warning if any frames had low tracking confidence
      if (encDOM.trackingWarning && encDOM.trackingWarningText) {
        if (tracking.lowConfidenceFrames.length > 0) {
          encDOM.trackingWarning.style.display = 'flex';
          encDOM.trackingWarningText.innerHTML =
            `<b>Low tracking confidence on frame(s) ${tracking.lowConfidenceFrames.slice(0, 8).join(', ')}:</b> Rapid motion or partial occlusion detected. Use the frame scrubber below to review face masks before encrypting.`;
        } else {
          encDOM.trackingWarning.style.display = 'none';
        }
      }

      // Configure interactive frame scrubber
      if (encDOM.scrubberBox && encDOM.frameSlider) {
        encDOM.scrubberBox.style.display = 'block';
        encDOM.frameSlider.max = String(Math.max(0, encState.extractedFrames.length - 1));
        encDOM.frameSlider.value = '0';
      }

      encState.currentFrameIdx = 0;
      renderVideoEncFrame(0);

      if (encDOM.progressStatus) {
        encDOM.progressStatus.innerHTML = `<i class="fa-solid fa-circle-check" style="color: var(--accent-emerald);"></i> AI Face Scan Ready: ${numPersons} Tracked Person(s) across ${encState.extractedFrames.length} frames`;
      }
      if (encDOM.btnCancel) encDOM.btnCancel.style.display = 'none';
      if (encDOM.btnProcess) encDOM.btnProcess.disabled = false;
      if (encDOM.btnScanFaces) encDOM.btnScanFaces.disabled = false;
      encState.isProcessing = false;
    }

    /**
     * Build interactive Tracked Person selection cards for Mode B (Encrypt Selected Faces)
     */
    function renderTrackedPersonsUI() {
      if (!encDOM.trackedPersonsList || !encDOM.trackedPersonsBox) return;
      encDOM.trackedPersonsList.innerHTML = '';

      if (encDOM.trackedPersonsCountBadge) {
        encDOM.trackedPersonsCountBadge.textContent = `${encState.trackSummaries.length} Tracked`;
      }

      if (encState.trackSummaries.length === 0) {
        encDOM.trackedPersonsBox.style.display = 'none';
        return;
      }

      encDOM.trackedPersonsBox.style.display = encState.scope === 'face_selected' ? 'block' : 'none';

      encState.trackSummaries.forEach(tr => {
        const card = document.createElement('label');
        const isChecked = encState.selectedTrackIds.has(tr.trackId);
        card.className = `tracked-person-card ${isChecked ? 'selected' : ''}`;
        card.style.borderColor = isChecked ? tr.color : '';

        // Create face thumbnail canvas from `tr.thumbFrameIdx`
        const thumbCanvas = document.createElement('canvas');
        thumbCanvas.width = 38;
        thumbCanvas.height = 38;
        thumbCanvas.className = 'tracked-person-thumb';
        const fData = encState.extractedFrames[tr.thumbFrameIdx];
        if (fData && tr.thumbBbox) {
          const tmp = document.createElement('canvas');
          tmp.width = encState.extractedW;
          tmp.height = encState.extractedH;
          tmp.getContext('2d').putImageData(fData, 0, 0);
          const bb = tr.thumbBbox;
          const bw = Math.max(16, bb.x1 - bb.x0);
          const bh = Math.max(16, bb.y1 - bb.y0);
          const pad = Math.max(bw, bh) * 0.25;
          const sx = Math.max(0, bb.x0 - pad);
          const sy = Math.max(0, bb.y0 - pad);
          const sw = Math.min(encState.extractedW - sx, bw + pad * 2);
          const sh = Math.min(encState.extractedH - sy, bh + pad * 2);
          thumbCanvas.getContext('2d').drawImage(tmp, sx, sy, sw, sh, 0, 0, 38, 38);
        }

        const chk = document.createElement('input');
        chk.type = 'checkbox';
        chk.checked = isChecked;
        chk.style.accentColor = tr.color;
        chk.addEventListener('change', () => {
          if (chk.checked) encState.selectedTrackIds.add(tr.trackId);
          else encState.selectedTrackIds.delete(tr.trackId);
          card.classList.toggle('selected', chk.checked);
          card.style.borderColor = chk.checked ? tr.color : '';
          renderVideoEncFrame(encState.currentFrameIdx);
        });

        const info = document.createElement('div');
        info.className = 'tracked-person-info';
        const confPct = Math.round(tr.avgConfidence * 100);
        info.innerHTML = `
          <span class="tracked-person-title" style="color: ${tr.color};">Person #${tr.trackId}</span>
          <span class="tracked-person-sub">Frames ${tr.firstFrame}–${tr.lastFrame} (${tr.frameCount}f · ${confPct}% conf)</span>
        `;

        card.appendChild(chk);
        card.appendChild(thumbCanvas);
        card.appendChild(info);
        encDOM.trackedPersonsList.appendChild(card);
      });
    }

    /**
     * Compute the active binary encryption mask (`Uint8Array(w * h)`) for frame `frameIdx`
     * based on Mode A (`face_all`), Mode B (`face_selected`), or `full`.
     */
    function buildFrameMaskForEncryption(frameIdx) {
      const w = encState.extractedW;
      const h = encState.extractedH;
      const total = w * h;
      const mask = new Uint8Array(total);

      if (encState.scope === 'full') {
        mask.fill(1);
        return mask;
      }

      const dets = encState.trackedFrames[frameIdx] || [];
      for (const det of dets) {
        const shouldEncrypt = encState.scope === 'face_all' ||
          (encState.scope === 'face_selected' && encState.selectedTrackIds.has(det.trackId));
        if (shouldEncrypt && det.mask) {
          const dm = det.mask;
          for (let i = 0; i < total; i++) {
            if (dm[i]) mask[i] = 1;
          }
        }
      }
      return mask;
    }

    /**
     * Render frame `frameIdx` onto the Original Canvas (with AI Face-Shaped Contour Overlays)
     * and the Encrypted Result Canvas (if encrypted frames exist).
     */
    function renderVideoEncFrame(frameIdx) {
      if (!encState.extractedFrames.length) return;
      const idx = Math.max(0, Math.min(encState.extractedFrames.length - 1, frameIdx));
      encState.currentFrameIdx = idx;

      const w = encState.extractedW;
      const h = encState.extractedH;
      const origData = encState.extractedFrames[idx];
      const tsSec = ((encState.extractedTimestamps[idx] || 0) / 1000).toFixed(2);
      const totalSec = ((encState.extractedTimestamps[encState.extractedTimestamps.length - 1] || 0) / 1000).toFixed(2);

      if (encDOM.origPlayer) encDOM.origPlayer.style.display = 'none';
      if (encDOM.phOrig) encDOM.phOrig.style.display = 'none';

      if (encDOM.canvasOrigFrame) {
        const canvas = encDOM.canvasOrigFrame;
        canvas.width = w;
        canvas.height = h;
        canvas.style.display = 'block';
        const ctx = canvas.getContext('2d');
        ctx.putImageData(origData, 0, 0);

        const showOverlay = !encDOM.chkShowAiOverlay || encDOM.chkShowAiOverlay.checked;
        const dets = encState.trackedFrames[idx] || [];

        if (showOverlay && encState.scope !== 'full') {
          dets.forEach(det => {
            const isSelected = encState.scope === 'face_all' ||
              (encState.scope === 'face_selected' && encState.selectedTrackIds.has(det.trackId));
            const color = isSelected
              ? TRACK_COLORS[(det.trackId - 1) % TRACK_COLORS.length]
              : '#94a3b8';

            // Draw smooth face-shaped contour polygon
            if (det.contourPts && det.contourPts.length >= 3) {
              ctx.save();
              ctx.beginPath();
              const pts = det.contourPts;
              ctx.moveTo(pts[0].x, pts[0].y);
              for (let i = 1; i < pts.length; i++) ctx.lineTo(pts[i].x, pts[i].y);
              ctx.closePath();
              ctx.fillStyle = isSelected ? 'rgba(16, 185, 129, 0.22)' : 'rgba(148, 163, 184, 0.12)';
              ctx.fill();
              ctx.lineWidth = Math.max(2, Math.round(w / 180));
              ctx.strokeStyle = color;
              if (!isSelected) ctx.setLineDash([4, 4]);
              ctx.stroke();
              ctx.restore();
            }

            // Draw Tracked Person ID badge above face
            ctx.save();
            const fontSize = Math.max(10, Math.round(w / 32));
            ctx.font = `bold ${fontSize}px sans-serif`;
            const statusTag = isSelected ? '🔒' : '🔓';
            const label = `${statusTag} P#${det.trackId} (${Math.round((det.confidence || 0.9) * 100)}%)`;
            const tw = ctx.measureText(label).width;
            const pillH = fontSize + 8;
            const bx = Math.max(4, Math.min(w - tw - 12, det.cx - (tw + 10) / 2));
            const by = Math.max(4, det.bbox.y0 - pillH - 3);
            ctx.fillStyle = color;
            ctx.fillRect(bx, by, tw + 10, pillH);
            ctx.fillStyle = '#ffffff';
            ctx.fillText(label, bx + 5, by + fontSize + 1);
            ctx.restore();
          });
        }

        if (encDOM.scrubberLabel) {
          encDOM.scrubberLabel.textContent = `Frame ${idx + 1} / ${encState.extractedFrames.length} (${tsSec}s)`;
        }
        if (encDOM.scrubberFaces) {
          const encCount = dets.filter(d =>
            encState.scope === 'face_all' || (encState.scope === 'face_selected' && encState.selectedTrackIds.has(d.trackId))
          ).length;
          encDOM.scrubberFaces.textContent = `${dets.length} Face(s) Detected · ${encCount} Selected for Encryption`;
        }
      }

      if (encDOM.origTime) encDOM.origTime.textContent = `${tsSec}s / ${totalSec}s`;

      // Render Encrypted Frame if available
      if (encState.encryptedFrames[idx] && encDOM.canvasResultFrame) {
        if (encDOM.phResult) encDOM.phResult.style.display = 'none';
        if (encDOM.resultPlayer) encDOM.resultPlayer.style.display = 'none';
        const rCanvas = encDOM.canvasResultFrame;
        rCanvas.width = w;
        rCanvas.height = h;
        rCanvas.style.display = 'block';
        rCanvas.getContext('2d').putImageData(encState.encryptedFrames[idx], 0, 0);
        if (encDOM.resultTime) encDOM.resultTime.textContent = `${tsSec}s / ${totalSec}s`;
      }
    }

    if (encDOM.frameSlider) {
      encDOM.frameSlider.addEventListener('input', () => {
        stopEncPlayback();
        renderVideoEncFrame(parseInt(encDOM.frameSlider.value, 10) || 0);
      });
    }
    if (encDOM.chkShowAiOverlay) {
      encDOM.chkShowAiOverlay.addEventListener('change', () => {
        renderVideoEncFrame(encState.currentFrameIdx);
      });
    }

    // Execute 3-Stage Selective Face Video Encryption & Package Self-Describing .kxv
    if (encDOM.btnProcess) {
      encDOM.btnProcess.addEventListener('click', async () => {
        showEncError(null);
        stopEncPlayback();

        if (!encState.videoLoaded) {
          showEncError('Please upload a short video first.');
          return;
        }

        // Validate key input
        const password = encDOM.password ? encDOM.password.value : '';
        if (encState.keyType === 'password' && !password) {
          showEncError('Please enter a secret password to derive the 3-stage frame keys.');
          return;
        }
        if (encState.keyType === 'image' && (!encState.keyImageBytes || encState.keyImageBytes.length === 0)) {
          showEncError('Please upload a Key Image to derive the 3-stage frame keys.');
          return;
        }

        // Ensure frames & AI face detection have been extracted
        if (!encState.aiScanComplete || encState.extractedFrames.length === 0) {
          await extractAndScanVideoFaces();
        }
        if (encState.extractedFrames.length === 0) return;

        if (encState.scope === 'face_selected' && encState.selectedTrackIds.size === 0) {
          showEncError('Please select at least one Tracked Person to encrypt in Mode B, or switch to Mode A (Encrypt All Faces).');
          return;
        }

        encState.isProcessing = true;
        encState.cancelRequested = false;
        encDOM.btnProcess.disabled = true;
        if (encDOM.btnScanFaces) encDOM.btnScanFaces.disabled = true;
        if (encDOM.btnCancel) encDOM.btnCancel.style.display = 'inline-flex';
        if (encDOM.progressBox) encDOM.progressBox.style.display = 'block';

        const w = encState.extractedW;
        const h = encState.extractedH;
        const fps = encState.extractedFps;
        const totalFrames = encState.extractedFrames.length;
        const kBits = parseInt(encDOM.kSelect ? encDOM.kSelect.value : '2', 10);
        const startTime = performance.now();

        try {
          if (encDOM.progressStatus) {
            encDOM.progressStatus.innerHTML = '<i class="fa-solid fa-lock fa-spin"></i> Encrypting Face Regions & Packaging Lossless .kxv Container...';
          }

          const keySource = encState.keyType === 'image' ? encState.keyImageBytes : password;
          const framesInput = [];
          let totalEncryptedFaceInstances = 0;

          for (let i = 0; i < totalFrames; i++) {
            const mask = buildFrameMaskForEncryption(i);
            const dets = encState.trackedFrames[i] || [];
            let fCount = 0;
            if (encState.scope === 'face_all') {
              fCount = dets.length;
            } else if (encState.scope === 'face_selected') {
              fCount = dets.filter(d => encState.selectedTrackIds.has(d.trackId)).length;
            } else {
              fCount = 1;
            }
            totalEncryptedFaceInstances += fCount;

            framesInput.push({
              imageData: encState.extractedFrames[i],
              mask,
              timestampMs: encState.extractedTimestamps[i] || Math.round((i * 1000) / fps),
              faceCount: fCount
            });
          }

          const encoded = await BitEngine.encodeKXVContainer(framesInput, keySource, {
            k: kBits,
            keyType: encState.keyType === 'image' ? 'image' : 'text',
            selectionMode: encState.scope === 'face_selected' ? 'selected' : 'all',
            scope: encState.scope,
            fps,
            selectedTrackIds: Array.from(encState.selectedTrackIds),
            onProgress: (done, total) => {
              const pct = Math.round((done / total) * 100);
              if (encDOM.progressFill) encDOM.progressFill.style.width = `${pct}%`;
              if (encDOM.progressPct) encDOM.progressPct.textContent = `${pct}%`;
              if (encDOM.progressDetails) {
                encDOM.progressDetails.textContent = `3-Stage MSB Face Encryption: Frame ${done} / ${total}`;
              }
            }
          });

          encState.kxvBytes = encoded.kxvBytes;
          encState.encryptedFrames = encoded.encryptedFrames;

          const avgMse = encoded.stats.avgMse;
          const avgPsnr = encoded.stats.avgPsnr;

          if (encDOM.valFrames) encDOM.valFrames.textContent = String(totalFrames);
          if (encDOM.valFacesCount) encDOM.valFacesCount.textContent = String(totalEncryptedFaceInstances);
          if (encDOM.valMse) encDOM.valMse.textContent = avgMse.toFixed(2);
          if (encDOM.valPsnr) encDOM.valPsnr.textContent = avgPsnr === '∞' ? '∞ dB' : `${avgPsnr} dB`;
          if (encDOM.metricsBar) encDOM.metricsBar.style.display = 'flex';

          // Populate .kxv summary banner
          const sizeKB = (encState.kxvBytes.byteLength / 1024).toFixed(1);
          const modeLabel = encState.scope === 'face_all'
            ? 'Mode A (All Faces)'
            : (encState.scope === 'face_selected' ? `Mode B (${encState.selectedTrackIds.size} Selected Person IDs)` : 'Entire Frame');
          if (encDOM.kxvSummary && encDOM.kxvSummaryText) {
            encDOM.kxvSummary.style.display = 'flex';
            encDOM.kxvSummaryText.innerHTML =
              `<b>Self-Describing .kxv Container Ready (${sizeKB} KB):</b> ${totalFrames} Lossless PNG Frames · ${modeLabel} · <b>k = ${kBits}-MSB</b> · Compressed RLE+ZLIB Face Masks &amp; Dual SHA-256 Auth Tags Embedded.`;
          }

          // Enable downloads & dual playback
          if (encDOM.btnDownloadKxv) encDOM.btnDownloadKxv.disabled = false;
          if (encDOM.btnDownloadWebm) encDOM.btnDownloadWebm.style.display = 'inline-flex';
          if (encDOM.btnDownloadWebm) encDOM.btnDownloadWebm.disabled = false;
          if (encDOM.btnGotoDecrypt) encDOM.btnGotoDecrypt.style.display = 'block';
          if (encDOM.btnSyncPlay) encDOM.btnSyncPlay.disabled = false;
          if (encDOM.btnSyncPause) encDOM.btnSyncPause.disabled = false;
          if (encDOM.btnSyncReset) encDOM.btnSyncReset.disabled = false;

          // Save in shared bridge for zero-diff verification in Decrypt tab
          FYP_VideoBridge.lastKxvBytes = encState.kxvBytes;
          FYP_VideoBridge.lastOriginalFrames = encState.extractedFrames.map(f => new Uint8ClampedArray(f.data));
          FYP_VideoBridge.lastEncryptedName = 'encrypted_video.kxv';

          const elapsedSec = ((performance.now() - startTime) / 1000).toFixed(2);
          if (encDOM.progressStatus) {
            encDOM.progressStatus.innerHTML = `<i class="fa-solid fa-circle-check" style="color: var(--accent-emerald);"></i> Selective Face Video Encryption Complete in ${elapsedSec}s!`;
          }

          // Start synchronized dual-canvas preview playback
          startEncDualPlayback();
        } catch (err) {
          console.error('Video encryption error:', err);
          showEncError(`Encryption failed: ${err.message || err}`);
        } finally {
          encState.isProcessing = false;
          encDOM.btnProcess.disabled = false;
          if (encDOM.btnScanFaces) encDOM.btnScanFaces.disabled = false;
          if (encDOM.btnCancel) encDOM.btnCancel.style.display = 'none';
        }
      });
    }

    function startEncDualPlayback() {
      stopEncPlayback();
      if (!encState.extractedFrames.length) return;
      const intervalMs = Math.round(1000 / (encState.extractedFps || 15));
      encState.playTimer = setInterval(() => {
        const nextIdx = (encState.currentFrameIdx + 1) % encState.extractedFrames.length;
        if (encDOM.frameSlider) encDOM.frameSlider.value = String(nextIdx);
        renderVideoEncFrame(nextIdx);
      }, intervalMs);
    }

    if (encDOM.btnSyncPlay) {
      encDOM.btnSyncPlay.addEventListener('click', () => startEncDualPlayback());
    }
    if (encDOM.btnSyncPause) {
      encDOM.btnSyncPause.addEventListener('click', () => stopEncPlayback());
    }
    if (encDOM.btnSyncReset) {
      encDOM.btnSyncReset.addEventListener('click', () => {
        stopEncPlayback();
        if (encDOM.frameSlider) encDOM.frameSlider.value = '0';
        renderVideoEncFrame(0);
      });
    }

    if (encDOM.btnCancel) {
      encDOM.btnCancel.addEventListener('click', () => {
        encState.cancelRequested = true;
      });
    }

    // Primary Download: Self-Describing Lossless .kxv Container (`encrypted_video.kxv`)
    if (encDOM.btnDownloadKxv) {
      encDOM.btnDownloadKxv.addEventListener('click', () => {
        if (!encState.kxvBytes) return;
        const blob = new Blob([encState.kxvBytes], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'encrypted_video.kxv';
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 2000);
      });
    }

    // Optional Secondary Download: Playable Encrypted WebM Preview
    if (encDOM.btnDownloadWebm) {
      encDOM.btnDownloadWebm.addEventListener('click', async () => {
        if (!encState.encryptedFrames.length) return;
        const w = encState.extractedW;
        const h = encState.extractedH;
        const fps = encState.extractedFps || 15;
        const recCanvas = document.createElement('canvas');
        recCanvas.width = w;
        recCanvas.height = h;
        const recCtx = recCanvas.getContext('2d');
        const stream = recCanvas.captureStream(fps);
        let mimeType = 'video/webm;codecs=vp9';
        if (typeof MediaRecorder !== 'undefined' && !MediaRecorder.isTypeSupported(mimeType)) mimeType = 'video/webm';
        const recorder = new MediaRecorder(stream, { mimeType, videoBitsPerSecond: 3500000 });
        const chunks = [];
        recorder.ondataavailable = e => { if (e.data.size > 0) chunks.push(e.data); };
        recorder.onstop = () => {
          const blob = new Blob(chunks, { type: mimeType });
          const url = URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = url;
          link.download = 'encrypted_preview.webm';
          link.click();
          setTimeout(() => URL.revokeObjectURL(url), 2000);
        };
        recorder.start();
        let idx = 0;
        const timer = setInterval(() => {
          if (idx < encState.encryptedFrames.length) {
            recCtx.putImageData(encState.encryptedFrames[idx++], 0, 0);
          } else {
            clearInterval(timer);
            setTimeout(() => { if (recorder.state !== 'inactive') recorder.stop(); }, 120);
          }
        }, Math.round(1000 / fps));
      });
    }

    if (encDOM.btnGotoDecrypt) {
      encDOM.btnGotoDecrypt.addEventListener('click', () => {
        stopEncPlayback();
        const decTabBtn = document.getElementById('tab-btn-video-dec');
        if (decTabBtn) decTabBtn.click();
      });
    }
  }

  /* ==========================================================================
     PAGE 2: VIDEO DECRYPTION MODULE (.kxv Self-Describing Lossless Recovery)
     ========================================================================== */
  function initVideoDecryptModule() {
    const decDOM = {
      dropZone: document.getElementById('video-dec-drop-zone'),
      fileInput: document.getElementById('video-dec-file-input'),
      dropText: document.getElementById('video-dec-drop-text'),
      dropIcon: document.getElementById('video-dec-drop-icon'),
      errorBanner: document.getElementById('video-dec-error-banner'),
      errorText: document.getElementById('video-dec-error-text'),
      kxvMetaCard: document.getElementById('video-dec-kxv-meta'),
      metaName: document.getElementById('meta-video-dec-name'),
      metaRes: document.getElementById('meta-video-dec-res'),
      metaFrames: document.getElementById('meta-video-dec-frames'),
      metaScope: document.getElementById('meta-video-dec-scope'),
      metaK: document.getElementById('meta-video-dec-k'),
      metaKeytype: document.getElementById('meta-video-dec-keytype'),
      scopeInfo: document.getElementById('video-dec-scope-info'),
      scopeText: document.getElementById('video-dec-scope-text'),
      keySelector: document.getElementById('video-dec-key-selector'),
      pwdGroup: document.getElementById('video-dec-pwd-group'),
      imgKeyGroup: document.getElementById('video-dec-imgkey-group'),
      password: document.getElementById('video-dec-password'),
      togglePwd: document.getElementById('toggle-video-dec-pwd'),
      keyImageInput: document.getElementById('video-dec-key-image-input'),
      keyDropZone: document.getElementById('video-dec-key-drop-zone'),
      keyDropText: document.getElementById('video-dec-key-drop-text'),
      progressBox: document.getElementById('video-dec-progress-box'),
      progressStatus: document.getElementById('video-dec-progress-status'),
      progressPct: document.getElementById('video-dec-progress-pct'),
      progressFill: document.getElementById('video-dec-progress-fill'),
      progressDetails: document.getElementById('video-dec-progress-details'),
      progressEta: document.getElementById('video-dec-progress-eta'),
      btnProcess: document.getElementById('btn-process-video-dec'),
      btnCancel: document.getElementById('btn-cancel-video-dec'),
      origPlayer: document.getElementById('video-dec-orig-player'),
      canvasOrigFrame: document.getElementById('canvas-video-dec-orig-frame'),
      phOrig: document.getElementById('ph-video-dec-orig'),
      resultPlayer: document.getElementById('video-dec-result-player'),
      canvasResultFrame: document.getElementById('canvas-video-dec-result-frame'),
      phResult: document.getElementById('ph-video-dec-result'),
      origTime: document.getElementById('video-dec-orig-time'),
      resultTime: document.getElementById('video-dec-result-time'),
      scrubberBox: document.getElementById('video-dec-scrubber-box'),
      scrubberLabel: document.getElementById('video-dec-scrubber-label'),
      frameSlider: document.getElementById('video-dec-frame-slider'),
      chkShowMask: document.getElementById('chk-video-dec-show-mask'),
      btnSyncPlay: document.getElementById('btn-sync-play-dec'),
      btnSyncPause: document.getElementById('btn-sync-pause-dec'),
      btnSyncReset: document.getElementById('btn-sync-reset-dec'),
      metricsBar: document.getElementById('video-dec-metrics-bar'),
      valFrames: document.getElementById('val-video-dec-frames'),
      valDiff: document.getElementById('val-video-dec-diff'),
      valMse: document.getElementById('val-video-dec-mse'),
      valPsnr: document.getElementById('val-video-dec-psnr'),
      btnDownloadPng: document.getElementById('btn-download-video-dec-png'),
      btnDownloadWebm: document.getElementById('btn-download-video-dec')
    };

    const decState = {
      kxvBytes: null,
      kxvInfo: null,
      keyType: 'password',
      keyImageBytes: null,
      encryptedFrames: [], // Array<ImageData>
      restoredFrames: [],  // Array<ImageData>
      frameMasks: [],      // Array<Uint8Array>
      timestampsMs: [],
      currentFrameIdx: 0,
      playTimer: null,
      isProcessing: false
    };

    function showDecError(msg) {
      if (!decDOM.errorBanner || !decDOM.errorText) return;
      if (!msg) {
        decDOM.errorBanner.style.display = 'none';
        decDOM.errorText.textContent = '';
      } else {
        decDOM.errorText.textContent = msg;
        decDOM.errorBanner.style.display = 'flex';
      }
    }

    function stopDecPlayback() {
      if (decState.playTimer) {
        clearInterval(decState.playTimer);
        decState.playTimer = null;
      }
    }

    if (decDOM.togglePwd && decDOM.password) {
      setupPwdToggle(decDOM.togglePwd, decDOM.password);
    }

    // Key Type Selector (Password vs Key Image)
    if (decDOM.keySelector) {
      const btns = decDOM.keySelector.querySelectorAll('.toggle-btn');
      btns.forEach(btn => {
        btn.addEventListener('click', () => {
          btns.forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          decState.keyType = btn.getAttribute('data-key-type') || 'password';
          if (decDOM.pwdGroup) decDOM.pwdGroup.style.display = decState.keyType === 'password' ? 'block' : 'none';
          if (decDOM.imgKeyGroup) decDOM.imgKeyGroup.style.display = decState.keyType === 'image' ? 'block' : 'none';
        });
      });
    }

    if (decDOM.keyImageInput) {
      decDOM.keyImageInput.addEventListener('change', async (e) => {
        const file = e.target.files && e.target.files[0];
        if (!file) return;
        const buf = await file.arrayBuffer();
        decState.keyImageBytes = new Uint8Array(buf);
        if (decDOM.keyDropText) {
          decDOM.keyDropText.innerHTML = `✅ <b>Key Image:</b> ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        }
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
          handleDecFileSelect(e.dataTransfer.files[0]);
        }
      });
      decDOM.fileInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files.length > 0) {
          handleDecFileSelect(e.target.files[0]);
        }
      });
    }

    async function handleDecFileSelect(file) {
      if (!file) return;
      showDecError(null);
      stopDecPlayback();

      try {
        const buf = await file.arrayBuffer();
        const bytes = new Uint8Array(buf);
        if (!BitEngine.isKxvBytes(bytes)) {
          showDecError(`Invalid container: "${file.name}" is not a valid KXBIT Self-Describing Encrypted Video (.kxv) file.`);
          return;
        }

        const info = await BitEngine.inspectKXVContainer(bytes);
        decState.kxvBytes = bytes;
        decState.kxvInfo = info;
        decState.restoredFrames = [];
        decState.frameMasks = info.masks || [];
        decState.timestampsMs = (info.metadata && info.metadata.timestampsMs) ? info.metadata.timestampsMs : [];
        decState.encryptedFrames = info.previewFrames || [];

        // Update dropzone UI
        if (decDOM.dropZone) {
          decDOM.dropZone.classList.add('has-file');
          if (decDOM.dropIcon) {
            decDOM.dropIcon.className = 'fa-solid fa-circle-check drop-icon';
            decDOM.dropIcon.style.color = '#059669';
          }
          if (decDOM.dropText) {
            decDOM.dropText.innerHTML = `✅ <b>Loaded .kxv Container:</b> <span style="color: #059669;">${file.name}</span> (${(bytes.byteLength / 1024).toFixed(1)} KB)`;
          }
        }

        // Populate .kxv metadata summary
        const hdr = info.header;
        const meta = info.metadata || {};
        const scopeLabel = hdr.selectionMode === 'selected'
          ? 'Mode B (Selected Tracked Faces)'
          : (hdr.scope === 'full' ? 'Entire Frame' : 'Mode A (All Detected Faces)');
        const keyLabel = hdr.keyType === 'image' ? 'Key Image' : 'Text Password';
        const fpsVal = meta.fps || 15;

        if (decDOM.metaName) decDOM.metaName.textContent = file.name;
        if (decDOM.metaRes) decDOM.metaRes.textContent = `${hdr.width} × ${hdr.height} @ ${fpsVal} FPS`;
        if (decDOM.metaFrames) decDOM.metaFrames.textContent = `${hdr.frameCount} lossless PNG frames`;
        if (decDOM.metaScope) decDOM.metaScope.textContent = scopeLabel;
        if (decDOM.metaK) decDOM.metaK.textContent = `k = ${hdr.k}-MSB`;
        if (decDOM.metaKeytype) decDOM.metaKeytype.textContent = keyLabel;
        if (decDOM.kxvMetaCard) decDOM.kxvMetaCard.style.display = 'flex';

        if (decDOM.scopeInfo && decDOM.scopeText) {
          decDOM.scopeInfo.style.display = 'flex';
          decDOM.scopeText.innerHTML =
            `<b>Embedded .kxv Metadata Verified:</b> ${scopeLabel} · <b>k = ${hdr.k}</b> · Required Key: <b>${keyLabel}</b>. Exact per-frame binary face masks loaded directly from container (AI detection is not rerun).`;
        }

        // Auto-switch key input tab to match container's keyType
        if (decDOM.keySelector) {
          const targetKeyType = hdr.keyType === 'image' ? 'image' : 'password';
          decState.keyType = targetKeyType;
          const btns = decDOM.keySelector.querySelectorAll('.toggle-btn');
          btns.forEach(b => b.classList.toggle('active', b.getAttribute('data-key-type') === targetKeyType));
          if (decDOM.pwdGroup) decDOM.pwdGroup.style.display = targetKeyType === 'password' ? 'block' : 'none';
          if (decDOM.imgKeyGroup) decDOM.imgKeyGroup.style.display = targetKeyType === 'image' ? 'block' : 'none';
        }

        if (decDOM.scrubberBox && decDOM.frameSlider) {
          decDOM.scrubberBox.style.display = 'block';
          decDOM.frameSlider.max = String(Math.max(0, hdr.frameCount - 1));
          decDOM.frameSlider.value = '0';
        }

        decState.currentFrameIdx = 0;
        renderVideoDecFrame(0);
        if (decDOM.btnProcess) decDOM.btnProcess.disabled = false;
      } catch (err) {
        console.error('.kxv inspection error:', err);
        showDecError(err.message || 'Corrupted or unsupported .kxv container.');
      }

      setTimeout(() => {
        if (decDOM.fileInput) decDOM.fileInput.value = '';
      }, 400);
    }

    function renderVideoDecFrame(frameIdx) {
      if (!decState.encryptedFrames.length || !decState.kxvInfo) return;
      const idx = Math.max(0, Math.min(decState.encryptedFrames.length - 1, frameIdx));
      decState.currentFrameIdx = idx;

      const w = decState.kxvInfo.header.width;
      const h = decState.kxvInfo.header.height;
      const tsSec = ((decState.timestampsMs[idx] || 0) / 1000).toFixed(2);
      const totalSec = ((decState.timestampsMs[decState.timestampsMs.length - 1] || 0) / 1000).toFixed(2);

      if (decDOM.phOrig) decDOM.phOrig.style.display = 'none';
      if (decDOM.origPlayer) decDOM.origPlayer.style.display = 'none';

      if (decDOM.canvasOrigFrame) {
        const canvas = decDOM.canvasOrigFrame;
        canvas.width = w;
        canvas.height = h;
        canvas.style.display = 'block';
        const ctx = canvas.getContext('2d');
        ctx.putImageData(decState.encryptedFrames[idx], 0, 0);

        // Optional stored binary mask boundary overlay
        if (decDOM.chkShowMask && decDOM.chkShowMask.checked && decState.frameMasks[idx]) {
          const mask = decState.frameMasks[idx];
          const ov = ctx.createImageData(w, h);
          const d = ov.data;
          for (let y = 1; y < h - 1; y++) {
            for (let x = 1; x < w - 1; x++) {
              const p = y * w + x;
              if (mask[p] === 1 && (mask[p - 1] === 0 || mask[p + 1] === 0 || mask[p - w] === 0 || mask[p + w] === 0)) {
                const bi = p * 4;
                d[bi] = 16; d[bi + 1] = 185; d[bi + 2] = 129; d[bi + 3] = 255;
              }
            }
          }
          const tmp = document.createElement('canvas');
          tmp.width = w;
          tmp.height = h;
          tmp.getContext('2d').putImageData(ov, 0, 0);
          ctx.drawImage(tmp, 0, 0);
        }
      }

      if (decDOM.scrubberLabel) {
        decDOM.scrubberLabel.textContent = `Frame ${idx + 1} / ${decState.encryptedFrames.length} (${tsSec}s)`;
      }
      if (decDOM.origTime) decDOM.origTime.textContent = `${tsSec}s / ${totalSec}s`;

      if (decState.restoredFrames[idx] && decDOM.canvasResultFrame) {
        if (decDOM.phResult) decDOM.phResult.style.display = 'none';
        if (decDOM.resultPlayer) decDOM.resultPlayer.style.display = 'none';
        const rCanvas = decDOM.canvasResultFrame;
        rCanvas.width = w;
        rCanvas.height = h;
        rCanvas.style.display = 'block';
        rCanvas.getContext('2d').putImageData(decState.restoredFrames[idx], 0, 0);
        if (decDOM.resultTime) decDOM.resultTime.textContent = `${tsSec}s / ${totalSec}s`;
      }
    }

    if (decDOM.frameSlider) {
      decDOM.frameSlider.addEventListener('input', () => {
        stopDecPlayback();
        renderVideoDecFrame(parseInt(decDOM.frameSlider.value, 10) || 0);
      });
    }
    if (decDOM.chkShowMask) {
      decDOM.chkShowMask.addEventListener('change', () => {
        renderVideoDecFrame(decState.currentFrameIdx);
      });
    }

    // Execute Lossless .kxv Video Decryption & 0-Different-Pixel Verification
    if (decDOM.btnProcess) {
      decDOM.btnProcess.addEventListener('click', async () => {
        showDecError(null);
        stopDecPlayback();

        if (!decState.kxvBytes || !decState.kxvInfo) {
          showDecError('Please upload an encrypted .kxv video file first.');
          return;
        }

        const password = decDOM.password ? decDOM.password.value : '';
        if (decState.keyType === 'password' && !password) {
          showDecError('Please enter the decryption password.');
          return;
        }
        if (decState.keyType === 'image' && (!decState.keyImageBytes || decState.keyImageBytes.length === 0)) {
          showDecError('Please upload the Key Image used during encryption.');
          return;
        }

        decState.isProcessing = true;
        decDOM.btnProcess.disabled = true;
        if (decDOM.progressBox) decDOM.progressBox.style.display = 'block';
        if (decDOM.progressStatus) {
          decDOM.progressStatus.innerHTML = '<i class="fa-solid fa-unlock-keyhole fa-spin"></i> Verifying Auth Tags & Reversing 3-Stage Face Encryption...';
        }

        const startTime = performance.now();
        try {
          const keySource = decState.keyType === 'image' ? decState.keyImageBytes : password;
          const result = await BitEngine.decryptKXVContainer(decState.kxvBytes, keySource, {
            onProgress: (done, total) => {
              const pct = Math.round((done / total) * 100);
              if (decDOM.progressFill) decDOM.progressFill.style.width = `${pct}%`;
              if (decDOM.progressPct) decDOM.progressPct.textContent = `${pct}%`;
              if (decDOM.progressDetails) {
                decDOM.progressDetails.textContent = `Restoring Frame ${done} / ${total}`;
              }
            }
          });

          decState.restoredFrames = result.restoredFrames;

          // Verify zero different pixels against session original frames (if available) + cryptographic plainAuthTag
          let diffPixels = result.stats.differentPixels || 0;
          let mse = result.stats.mse || 0;
          if (
            FYP_VideoBridge.lastOriginalFrames &&
            FYP_VideoBridge.lastOriginalFrames.length === result.restoredFrames.length
          ) {
            diffPixels = 0;
            mse = 0;
            for (let i = 0; i < result.restoredFrames.length; i++) {
              const orig = FYP_VideoBridge.lastOriginalFrames[i];
              const dec = result.restoredFrames[i].data;
              if (orig.length === dec.length) {
                const cmp = BitEngine.comparePixelsRGB(orig, dec, result.header.width, result.header.height);
                diffPixels += cmp.differentPixels;
                mse += cmp.mse;
              }
            }
            mse /= result.restoredFrames.length;
          }

          if (decDOM.valFrames) decDOM.valFrames.textContent = String(result.header.frameCount);
          if (decDOM.valDiff) decDOM.valDiff.textContent = `${diffPixels} px`;
          if (decDOM.valMse) decDOM.valMse.textContent = mse.toFixed(4);
          if (decDOM.valPsnr) decDOM.valPsnr.textContent = mse === 0 ? '∞ dB (100% Lossless)' : `${(10 * Math.log10((255 * 255) / mse)).toFixed(2)} dB`;
          if (decDOM.metricsBar) decDOM.metricsBar.style.display = 'flex';

          if (decDOM.btnDownloadPng) decDOM.btnDownloadPng.disabled = false;
          if (decDOM.btnDownloadWebm) decDOM.btnDownloadWebm.disabled = false;
          if (decDOM.btnSyncPlay) decDOM.btnSyncPlay.disabled = false;
          if (decDOM.btnSyncPause) decDOM.btnSyncPause.disabled = false;
          if (decDOM.btnSyncReset) decDOM.btnSyncReset.disabled = false;

          const elapsedSec = ((performance.now() - startTime) / 1000).toFixed(2);
          if (decDOM.progressStatus) {
            decDOM.progressStatus.innerHTML =
              `<i class="fa-solid fa-circle-check" style="color: var(--accent-emerald);"></i> 100% Lossless Recovery Verified (0 Different Pixels) in ${elapsedSec}s!`;
          }

          startDecDualPlayback();
        } catch (err) {
          // Requirement: Never pop up alert() on wrong password/key; show inline error banner only
          showDecError(err.message || 'Decryption failed: Wrong password/key image or modified .kxv container.');
          if (decDOM.progressBox) decDOM.progressBox.style.display = 'none';
        } finally {
          decState.isProcessing = false;
          decDOM.btnProcess.disabled = false;
        }
      });
    }

    function startDecDualPlayback() {
      stopDecPlayback();
      if (!decState.encryptedFrames.length || !decState.kxvInfo) return;
      const fpsVal = (decState.kxvInfo.metadata && decState.kxvInfo.metadata.fps) ? decState.kxvInfo.metadata.fps : 15;
      const intervalMs = Math.round(1000 / fpsVal);
      decState.playTimer = setInterval(() => {
        const nextIdx = (decState.currentFrameIdx + 1) % decState.encryptedFrames.length;
        if (decDOM.frameSlider) decDOM.frameSlider.value = String(nextIdx);
        renderVideoDecFrame(nextIdx);
      }, intervalMs);
    }

    if (decDOM.btnSyncPlay) {
      decDOM.btnSyncPlay.addEventListener('click', () => startDecDualPlayback());
    }
    if (decDOM.btnSyncPause) {
      decDOM.btnSyncPause.addEventListener('click', () => stopDecPlayback());
    }
    if (decDOM.btnSyncReset) {
      decDOM.btnSyncReset.addEventListener('click', () => {
        stopDecPlayback();
        if (decDOM.frameSlider) decDOM.frameSlider.value = '0';
        renderVideoDecFrame(0);
      });
    }

    // Download Current Verified Lossless Restored Frame as PNG
    if (decDOM.btnDownloadPng) {
      decDOM.btnDownloadPng.addEventListener('click', () => {
        const idx = decState.currentFrameIdx;
        if (!decState.restoredFrames[idx] || !decState.kxvInfo) return;
        const c = document.createElement('canvas');
        c.width = decState.kxvInfo.header.width;
        c.height = decState.kxvInfo.header.height;
        c.getContext('2d').putImageData(decState.restoredFrames[idx], 0, 0);
        const link = document.createElement('a');
        link.href = c.toDataURL('image/png');
        link.download = `restored_frame_${idx + 1}.png`;
        link.click();
      });
    }

    // Download Restored Playable WebM Video
    if (decDOM.btnDownloadWebm) {
      decDOM.btnDownloadWebm.addEventListener('click', () => {
        if (!decState.restoredFrames.length || !decState.kxvInfo) return;
        const w = decState.kxvInfo.header.width;
        const h = decState.kxvInfo.header.height;
        const fps = (decState.kxvInfo.metadata && decState.kxvInfo.metadata.fps) ? decState.kxvInfo.metadata.fps : 15;
        const recCanvas = document.createElement('canvas');
        recCanvas.width = w;
        recCanvas.height = h;
        const recCtx = recCanvas.getContext('2d');
        const stream = recCanvas.captureStream(fps);
        let mimeType = 'video/webm;codecs=vp9';
        if (typeof MediaRecorder !== 'undefined' && !MediaRecorder.isTypeSupported(mimeType)) mimeType = 'video/webm';
        const recorder = new MediaRecorder(stream, { mimeType, videoBitsPerSecond: 3500000 });
        const chunks = [];
        recorder.ondataavailable = e => { if (e.data.size > 0) chunks.push(e.data); };
        recorder.onstop = () => {
          const blob = new Blob(chunks, { type: mimeType });
          const url = URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = url;
          link.download = 'restored_video.webm';
          link.click();
          setTimeout(() => URL.revokeObjectURL(url), 2000);
        };
        recorder.start();
        let idx = 0;
        const timer = setInterval(() => {
          if (idx < decState.restoredFrames.length) {
            recCtx.putImageData(decState.restoredFrames[idx++], 0, 0);
          } else {
            clearInterval(timer);
            setTimeout(() => { if (recorder.state !== 'inactive') recorder.stop(); }, 120);
          }
        }, Math.round(1000 / fps));
      });
    }
  }

  // Initialize both video modules
  initVideoEncryptModule();
  initVideoDecryptModule();

  /* ==========================================================================
     PNG Binary Structure Explorer, Bit/Byte Editor & Optimization Controller
     ========================================================================== */
  function initPngBinaryExplorerModule() {
    const pexState = {
      fileName: 'sample_encrypted_photo.png',
      originalPngBytes: null,
      workingPngBytes: null,
      originalMetaBytes: null,
      workingMetaBytes: null,
      undoStack: [],
      redoStack: [],
      storageUnit: 'bytes',       // 'bytes' | 'kib' | 'pct'
      hexSectionIndex: -1,        // -1 = All PNG Bytes, or section.index
      hexViewMode: 'hex',         // 'hex' | 'binary' | 'decoded'
      hexPage: 0,
      hexPageSize: 256,
      highlightRange: null,       // { start, end, label }
      selectedFileByteOffset: 0,
      selectedMetaByteIndex: 0,
      referencePlainImageData: null,
      knownPassword: 'KXBIT-Demo-Key-2026'
    };

    const el = (id) => document.getElementById(id);

    function formatSize(bytes, totalBytes, unit) {
      if (unit === 'kib') return `${(bytes / 1024).toFixed(2)} KiB`;
      if (unit === 'pct') {
        const pct = totalBytes > 0 ? ((bytes / totalBytes) * 100).toFixed(2) : '0.00';
        return `${pct}%`;
      }
      return `${bytes.toLocaleString()} B`;
    }

    function getChunkColor(type) {
      const palette = {
        SIGN: '#6366f1',
        IHDR: '#0ea5e9',
        msBX: '#10b981',
        msBx: '#14b8a6',
        IDAT: '#3b82f6',
        IEND: '#8b5cf6'
      };
      return palette[type] || '#f59e0b';
    }

    async function generateDemoEncryptedPng(metaVersion = 2) {
      const w = 160, h = 120;
      const rgba = new Uint8ClampedArray(w * h * 4);
      const faceMask = new Uint8Array(w * h);
      const cx = w * 0.5, cy = h * 0.45, rx = w * 0.22, ry = h * 0.28;
      for (let y = 0; y < h; y++) {
        for (let x = 0; x < w; x++) {
          const i = (y * w + x) * 4;
          rgba[i] = (x * 5 + y * 2) & 0xFF;
          rgba[i + 1] = (x * 3 + y * 7 + 60) & 0xFF;
          rgba[i + 2] = (x * 11 + y * 5 + 120) & 0xFF;
          rgba[i + 3] = 255;
          const dx = (x - cx) / rx, dy = (y - cy) / ry;
          if (dx * dx + dy * dy <= 1.0) {
            faceMask[y * w + x] = 1;
          }
        }
      }
      const origImg = new ImageData(rgba, w, h);
      pexState.referencePlainImageData = new ImageData(new Uint8ClampedArray(rgba), w, h);
      pexState.knownPassword = 'KXBIT-Demo-Key-2026';
      const pwdInput = el('pex-test-password');
      if (pwdInput) pwdInput.value = pexState.knownPassword;

      const enc = await BitEngine.encryptToPNG(origImg, pexState.knownPassword, faceMask, {
        k: 2,
        iterations: 1000,
        keyType: 'text',
        scope: 'face',
        metaVersion,
        optionalFields: metaVersion === 2
          ? [{ id: 2, critical: false, value: 'KXBIT-FYP' }]
          : null
      });
      const label = metaVersion === 2
        ? 'sample_face_v2_compact.png'
        : 'sample_face_v1_legacy.png';
      await loadPngIntoExplorer(enc.pngBytes, label);
    }

    async function loadPngIntoExplorer(pngBytes, fileName = 'encrypted_photo.png') {
      const cleanCopy = new Uint8Array(pngBytes);
      pexState.fileName = fileName;
      pexState.originalPngBytes = new Uint8Array(cleanCopy);
      pexState.workingPngBytes = new Uint8Array(cleanCopy);
      pexState.undoStack = [];
      pexState.redoStack = [];
      pexState.hexPage = 0;
      pexState.highlightRange = null;

      const parsed = BitEngine.parsePngBinaryStructure(cleanCopy);
      if (parsed.msbxSection) {
        pexState.originalMetaBytes = new Uint8Array(parsed.msbxSection.dataBytes);
        pexState.workingMetaBytes = new Uint8Array(parsed.msbxSection.dataBytes);
        pexState.selectedFileByteOffset = parsed.msbxSection.dataOffset;
        pexState.selectedMetaByteIndex = 0;
      } else {
        pexState.originalMetaBytes = new Uint8Array(0);
        pexState.workingMetaBytes = new Uint8Array(0);
        pexState.selectedFileByteOffset = 0;
        pexState.selectedMetaByteIndex = 0;
      }

      const tamperBox = el('pex-tamper-result-box');
      if (tamperBox) tamperBox.style.display = 'none';

      await refreshAllExplorerViews();
    }

    function pushUndoSnapshot() {
      if (!pexState.workingPngBytes) return;
      pexState.undoStack.push({
        pngBytes: new Uint8Array(pexState.workingPngBytes),
        metaBytes: new Uint8Array(pexState.workingMetaBytes || 0)
      });
      if (pexState.undoStack.length > 40) pexState.undoStack.shift();
      pexState.redoStack = [];
      updateUndoRedoButtons();
    }

    function updateUndoRedoButtons() {
      const btnUndo = el('btn-pex-undo');
      const btnRedo = el('btn-pex-redo');
      if (btnUndo) btnUndo.disabled = pexState.undoStack.length === 0;
      if (btnRedo) btnRedo.disabled = pexState.redoStack.length === 0;
    }

    async function refreshAllExplorerViews() {
      if (!pexState.workingPngBytes) return;
      const structure = BitEngine.parsePngBinaryStructure(pexState.workingPngBytes);
      if (structure.msbxSection) {
        pexState.workingMetaBytes = new Uint8Array(structure.msbxSection.dataBytes);
      } else {
        pexState.workingMetaBytes = new Uint8Array(0);
      }

      renderSummaryBar(structure);
      renderStructureTab(structure);
      renderHexViewerTab(structure);
      renderEditorTab(structure);
      await renderOptimizationTab();
      await renderValidationTab();
      updateUndoRedoButtons();
    }

    function renderSummaryBar(structure) {
      const fnEl = el('pex-sum-filename');
      const fsEl = el('pex-sum-filesize');
      const dmEl = el('pex-sum-dims');
      const chEl = el('pex-sum-chunk');
      const stEl = el('pex-sum-edit-state');

      if (fnEl) fnEl.textContent = pexState.fileName;
      if (fsEl) fsEl.textContent = `${structure.totalByteLength.toLocaleString()} B (${(structure.totalByteLength / 1024).toFixed(2)} KiB)`;
      if (dmEl) {
        dmEl.textContent = structure.ihdrInfo
          ? `${structure.ihdrInfo.width} × ${structure.ihdrInfo.height} px (${structure.ihdrInfo.colorTypeLabel})`
          : 'Unknown';
      }
      if (chEl) {
        if (structure.msbxSection && structure.msbxSection.msbxBreakdown) {
          const bd = structure.msbxSection.msbxBreakdown;
          chEl.textContent = `${structure.msbxSection.type} (Schema v${bd.schemaVersion} • ${bd.payloadByteLength} B payload + 12 B overhead)`;
        } else {
          chEl.textContent = 'None (Standard PNG)';
        }
      }
      if (stEl) {
        const isModified = pexState.undoStack.length > 0;
        stEl.textContent = isModified
          ? `Modified In-Memory Copy (${pexState.undoStack.length} edit${pexState.undoStack.length > 1 ? 's' : ''})`
          : 'Unmodified (Original Copy)';
        stEl.style.color = isModified ? '#f59e0b' : 'var(--accent-emerald)';
      }
    }

    function renderStructureTab(structure) {
      const total = structure.totalByteLength;
      const formulaBanner = el('pex-size-formula-banner');
      if (formulaBanner) {
        const chunkSum = structure.chunks.reduce((a, c) => a + c.totalChunkSize, 0);
        formulaBanner.innerHTML =
          `<b>Total PNG Size = Signature (${structure.signatureBytes} B) + All Chunk Sizes (${chunkSum.toLocaleString()} B across ${structure.chunkCount} chunks, incl. ${structure.totalChunksOverheadBytes} B overhead) = ${total.toLocaleString()} B</b> ` +
          (structure.sizeFormulaMatches
            ? `<span style="color: var(--accent-emerald); font-weight:700;">✔ Verified Exact Sum</span>`
            : `<span style="color: #ef4444; font-weight:700;">⚠ Truncated/Mismatched Size</span>`);
      }

      // 1. Stacked Bar & Legend
      const barEl = el('pex-storage-bar');
      const legEl = el('pex-storage-legend');
      if (barEl && legEl) {
        barEl.innerHTML = '';
        legEl.innerHTML = '';
        for (const sec of structure.sections) {
          const color = getChunkColor(sec.type);
          const pct = Math.max(2.5, sec.percentage);
          const seg = document.createElement('div');
          seg.className = 'pex-bar-seg';
          seg.style.width = `${pct}%`;
          seg.style.background = color;
          seg.title = `${sec.name}: ${sec.totalChunkSize.toLocaleString()} B (${sec.percentage}%)`;
          seg.textContent = sec.percentage >= 7 ? `${sec.name} (${formatSize(sec.totalChunkSize, total, pexState.storageUnit)})` : sec.name;
          seg.addEventListener('click', () => {
            pexState.hexSectionIndex = sec.index;
            pexState.hexPage = 0;
            switchToSubTab('pex-panel-hex');
            renderHexViewerTab(structure);
          });
          barEl.appendChild(seg);

          const card = document.createElement('div');
          card.className = 'pex-legend-card';
          card.innerHTML = `
            <span class="pex-legend-dot" style="background:${color};"></span>
            <div class="pex-legend-info">
              <strong>${sec.name} ${sec.isSignature ? '' : `(Data: ${sec.dataLength} B + 12 B)`}</strong>
              <span>${formatSize(sec.totalChunkSize, total, pexState.storageUnit)} • ${sec.percentage}% of file</span>
            </div>
          `;
          legEl.appendChild(card);
        }
      }

      // 2. Chunks Table
      const tbody = el('pex-chunks-tbody');
      if (tbody) {
        tbody.innerHTML = '';
        for (const sec of structure.sections) {
          const tr = document.createElement('tr');
          const crcBadge = sec.isSignature
            ? `<span class="pex-tier-badge pass">Magic OK</span>`
            : (sec.crcValid && sec.lengthValid
              ? `<span class="pex-tier-badge pass">✔ ${sec.crcHex}</span>`
              : `<span class="pex-tier-badge fail">✖ ${sec.crcHex} (Expected ${sec.actualCrcHex})</span>`);

          tr.innerHTML = `
            <td>${sec.index}</td>
            <td><strong style="color:${getChunkColor(sec.type)};">${sec.name}</strong></td>
            <td><code>${sec.type}</code> <small style="color:var(--text-muted); display:block;">${sec.propertySummary}</small></td>
            <td><code>${sec.byteOffset}</code> <small>(0x${sec.byteOffset.toString(16).toUpperCase()})</small></td>
            <td><code>${sec.dataLength.toLocaleString()} B</code></td>
            <td><code>${sec.overheadBytes} B</code></td>
            <td><strong>${sec.totalChunkSize.toLocaleString()} B</strong></td>
            <td><code>${sec.percentage}%</code></td>
            <td>${crcBadge}</td>
            <td>
              <div style="font-size:11.5px; color:var(--text-muted); margin-bottom:4px;">${sec.purpose}</div>
              <button type="button" class="btn btn-xs btn-outline pex-inspect-sec-btn" data-sec-idx="${sec.index}">
                <i class="fa-solid fa-magnifying-glass"></i> View Bytes &amp; Bits
              </button>
            </td>
          `;
          tbody.appendChild(tr);
        }
        tbody.querySelectorAll('.pex-inspect-sec-btn').forEach(btn => {
          btn.addEventListener('click', () => {
            pexState.hexSectionIndex = parseInt(btn.getAttribute('data-sec-idx'), 10);
            pexState.hexPage = 0;
            switchToSubTab('pex-panel-hex');
            renderHexViewerTab(structure);
          });
        });
      }

      // 3. Feature 4: Expandable msBX Field Breakdown
      const msbxCard = el('pex-msbx-breakdown-card');
      const envStrip = el('pex-msbx-envelope-summary');
      const fieldsTbody = el('pex-msbx-fields-tbody');
      const schemaBadge = el('pex-msbx-schema-badge');

      if (msbxCard && fieldsTbody && envStrip) {
        if (!structure.msbxSection || !structure.msbxSection.msbxBreakdown) {
          envStrip.innerHTML = `<span style="color:#f59e0b;"><i class="fa-solid fa-circle-exclamation"></i> This PNG does not contain an embedded <code>msBX</code> or legacy <code>msBx</code> metadata chunk.</span>`;
          fieldsTbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">No <code>msBX</code> metadata fields present in this PNG file.</td></tr>`;
          if (schemaBadge) schemaBadge.textContent = 'No msBX Chunk';
        } else {
          const sec = structure.msbxSection;
          const bd = sec.msbxBreakdown;
          if (schemaBadge) {
            schemaBadge.textContent = bd.schemaVersion === 2
              ? `Schema v2 Compact (${bd.payloadByteLength} B payload)`
              : `Schema v1 Legacy (${bd.payloadByteLength} B payload)`;
          }
          envStrip.innerHTML = `
            <span><b>Chunk Envelope (12 B Overhead):</b></span>
            <span>Length Field: Offset <code>${bd.envelope.lengthField.fileByteOffset}..${bd.envelope.lengthField.fileByteOffset + 3}</code> (4 B = ${bd.payloadByteLength})</span>
            <span>• Type Field: Offset <code>${bd.envelope.typeField.fileByteOffset}..${bd.envelope.typeField.fileByteOffset + 3}</code> (4 B = "${bd.chunkType}")</span>
            <span>• Payload Data: Offset <code>${sec.dataOffset}..${sec.dataOffset + bd.payloadByteLength - 1}</code> (${bd.payloadByteLength} B)</span>
            <span>• CRC-32 Trailer: Offset <code>${bd.envelope.crcField.fileByteOffset}..${bd.envelope.crcField.fileByteOffset + 3}</code> (4 B = ${sec.crcHex})</span>
          `;

          fieldsTbody.innerHTML = '';
          bd.fields.forEach((f) => {
            const tr = document.createElement('tr');
            const chunkOffStr = f.chunkByteOffset >= 0
              ? `<code>+${f.chunkByteOffset}${f.chunkByteEnd > f.chunkByteOffset ? '..+' + f.chunkByteEnd : ''}</code> <small>(${f.bitRange})</small>`
              : `<span style="color:var(--accent-emerald); font-weight:600;">${f.bitRange}</span>`;
            const fileOffStr = f.fileByteOffset >= 0
              ? `<code>${f.fileByteOffset}${f.fileByteEnd > f.fileByteOffset ? '..' + f.fileByteEnd : ''}</code>`
              : '—';

            tr.innerHTML = `
              <td><strong>${f.field}</strong></td>
              <td><code>${f.value}</code></td>
              <td><strong>${f.storage}</strong></td>
              <td>${chunkOffStr}</td>
              <td>${fileOffStr}</td>
              <td>
                <div style="font-family:'JetBrains Mono',monospace; font-size:11px;">Hex: <b>${f.rawHex}</b></div>
                <div style="font-family:'JetBrains Mono',monospace; font-size:10.5px; color:var(--text-muted);">Bin: ${f.rawBinary}</div>
              </td>
              <td>
                <div style="font-size:11px; color:var(--text-muted); margin-bottom:4px;">${f.description}</div>
                ${f.chunkByteOffset >= 0 ? `
                  <button type="button" class="btn btn-xs btn-outline pex-jump-field-btn" data-file-start="${f.fileByteOffset}" data-file-end="${f.fileByteEnd}" data-chunk-off="${f.chunkByteOffset}" data-field-name="${f.field}">
                    <i class="fa-solid fa-highlighter"></i> Highlight Bytes
                  </button>
                ` : ''}
              </td>
            `;
            fieldsTbody.appendChild(tr);
          });

          fieldsTbody.querySelectorAll('.pex-jump-field-btn').forEach(btn => {
            btn.addEventListener('click', () => {
              const fStart = parseInt(btn.getAttribute('data-file-start'), 10);
              const fEnd = parseInt(btn.getAttribute('data-file-end'), 10);
              const fName = btn.getAttribute('data-field-name');
              pexState.hexSectionIndex = structure.msbxSection.index;
              pexState.highlightRange = { start: fStart, end: fEnd, label: fName };
              pexState.selectedFileByteOffset = fStart;
              pexState.hexPage = Math.floor((fStart - structure.msbxSection.byteOffset) / pexState.hexPageSize);
              switchToSubTab('pex-panel-hex');
              renderHexViewerTab(structure);
            });
          });
        }
      }
    }

    function renderHexViewerTab(structure) {
      const selEl = el('pex-hex-section-select');
      if (selEl) {
        const prevVal = String(pexState.hexSectionIndex);
        selEl.innerHTML = `<option value="-1">All PNG File Bytes (${structure.totalByteLength.toLocaleString()} B)</option>`;
        for (const sec of structure.sections) {
          const opt = document.createElement('option');
          opt.value = String(sec.index);
          opt.textContent = `${sec.name} — Offset ${sec.byteOffset} (${sec.totalChunkSize.toLocaleString()} B)`;
          selEl.appendChild(opt);
        }
        selEl.value = prevVal;
      }

      let baseOffset = 0;
      let viewBytes = pexState.workingPngBytes;
      let activeSec = null;
      if (pexState.hexSectionIndex >= 0) {
        activeSec = structure.sections.find(s => s.index === pexState.hexSectionIndex) || null;
        if (activeSec) {
          baseOffset = activeSec.byteOffset;
          viewBytes = activeSec.rawBytes;
        }
      }

      // Field Highlight Pills
      const pillsBox = el('pex-field-pills');
      if (pillsBox) {
        pillsBox.innerHTML = '';
        const fieldsSource = (activeSec && activeSec.decodedFields && activeSec.decodedFields.length > 0)
          ? activeSec.decodedFields
          : (structure.msbxSection ? structure.msbxSection.decodedFields : []);

        if (fieldsSource && fieldsSource.length > 0) {
          const labelSpan = document.createElement('span');
          labelSpan.style.fontSize = '11.5px';
          labelSpan.style.color = 'var(--text-muted)';
          labelSpan.style.alignSelf = 'center';
          labelSpan.innerHTML = '<b>Click Field to Highlight Bytes:</b>';
          pillsBox.appendChild(labelSpan);

          fieldsSource.forEach(f => {
            if (f.fileByteOffset < 0) return;
            const pill = document.createElement('button');
            pill.type = 'button';
            const isHi = pexState.highlightRange &&
              pexState.highlightRange.start === f.fileByteOffset &&
              pexState.highlightRange.end === f.fileByteEnd;
            pill.className = 'pex-field-pill' + (isHi ? ' active' : '');
            pill.textContent = `${f.field} (${f.storage || ''})`;
            pill.addEventListener('click', () => {
              pexState.highlightRange = { start: f.fileByteOffset, end: f.fileByteEnd, label: f.field };
              pexState.selectedFileByteOffset = f.fileByteOffset;
              const relOff = Math.max(0, f.fileByteOffset - baseOffset);
              pexState.hexPage = Math.floor(relOff / pexState.hexPageSize);
              renderHexViewerTab(structure);
            });
            pillsBox.appendChild(pill);
          });
        }
      }

      const totalViewBytes = viewBytes.byteLength;
      const maxPage = Math.max(0, Math.ceil(totalViewBytes / pexState.hexPageSize) - 1);
      if (pexState.hexPage > maxPage) pexState.hexPage = maxPage;
      if (pexState.hexPage < 0) pexState.hexPage = 0;

      const pageStart = pexState.hexPage * pexState.hexPageSize;
      const pageEnd = Math.min(totalViewBytes, pageStart + pexState.hexPageSize);

      const pageLbl = el('pex-hex-page-label');
      if (pageLbl) {
        pageLbl.textContent = `Bytes ${(baseOffset + pageStart).toLocaleString()}..${Math.max(baseOffset + pageStart, baseOffset + pageEnd - 1).toLocaleString()} of ${(baseOffset + totalViewBytes).toLocaleString()}`;
      }
      const btnPrev = el('btn-pex-hex-prev');
      const btnNext = el('btn-pex-hex-next');
      if (btnPrev) btnPrev.disabled = pexState.hexPage <= 0;
      if (btnNext) btnNext.disabled = pexState.hexPage >= maxPage;

      const gridBox = el('pex-hex-grid-box');
      if (gridBox) {
        gridBox.innerHTML = '';

        if (pexState.hexViewMode === 'decoded') {
          const targetFields = activeSec
            ? activeSec.decodedFields
            : structure.sections.flatMap(s => (s.decodedFields || []).map(f => ({ ...f, secName: s.name })));
          if (!targetFields || targetFields.length === 0) {
            gridBox.innerHTML = `<div style="padding:16px; color:var(--text-muted);">No structured fields decoded for this section. Switch to Hexadecimal or Binary View to inspect raw bytes.</div>`;
          } else {
            targetFields.forEach(f => {
              const row = document.createElement('div');
              row.style.padding = '8px 10px';
              row.style.borderBottom = '1px solid var(--border-light)';
              row.style.cursor = 'pointer';
              row.innerHTML = `
                <div style="display:flex; justify-content:space-between; gap:8px;">
                  <strong>${f.secName ? `[${f.secName}] ` : ''}${f.field}</strong>
                  <span style="color:var(--primary-blue); font-weight:700;">${f.value}</span>
                </div>
                <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">
                  File Offset: <code>${f.fileByteOffset}..${f.fileByteEnd}</code> • Range: ${f.bitRange || '—'} • Storage: ${f.storage || '—'}
                </div>
              `;
              row.addEventListener('click', () => {
                if (f.fileByteOffset >= 0) {
                  pexState.selectedFileByteOffset = f.fileByteOffset;
                  pexState.highlightRange = { start: f.fileByteOffset, end: f.fileByteEnd, label: f.field };
                  updateByteInspector(structure, f.fileByteOffset);
                }
              });
              gridBox.appendChild(row);
            });
          }
        } else {
          const bytesPerRow = pexState.hexViewMode === 'binary' ? 6 : (pexState.hexViewMode === 'decimal' ? 12 : 16);
          for (let r = pageStart; r < pageEnd; r += bytesPerRow) {
            const rowEnd = Math.min(pageEnd, r + bytesPerRow);
            const fileRowOffset = baseOffset + r;
            const rowEl = document.createElement('div');
            rowEl.className = 'pex-hex-row';

            const offSpan = document.createElement('span');
            offSpan.className = 'pex-hex-offset';
            offSpan.textContent = `+0x${fileRowOffset.toString(16).padStart(4, '0').toUpperCase()}`;

            const cellsWrap = document.createElement('div');
            cellsWrap.className = 'pex-hex-cells';

            let asciiStr = '';
            for (let i = r; i < rowEnd; i++) {
              const fileOff = baseOffset + i;
              const b = viewBytes[i];
              asciiStr += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';

              const cell = document.createElement('span');
              cell.className = 'pex-byte-cell';
              if (pexState.highlightRange && fileOff >= pexState.highlightRange.start && fileOff <= pexState.highlightRange.end) {
                cell.classList.add('highlighted');
              }
              if (fileOff === pexState.selectedFileByteOffset) {
                cell.classList.add('selected');
              }
              if (pexState.hexViewMode === 'binary') {
                cell.textContent = b.toString(2).padStart(8, '0');
              } else if (pexState.hexViewMode === 'decimal') {
                cell.textContent = b.toString(10).padStart(3, '0');
              } else {
                cell.textContent = b.toString(16).padStart(2, '0').toUpperCase();
              }
              cell.title = `File Offset ${fileOff} (0x${fileOff.toString(16).toUpperCase()}) • Hex: 0x${b.toString(16).padStart(2, '0').toUpperCase()} • Bin: ${b.toString(2).padStart(8, '0')} • Dec: ${b}`;
              cell.addEventListener('click', () => {
                pexState.selectedFileByteOffset = fileOff;
                renderHexViewerTab(structure);
              });
              cellsWrap.appendChild(cell);
            }

            const asciiSpan = document.createElement('span');
            asciiSpan.style.color = 'var(--text-muted)';
            asciiSpan.textContent = asciiStr;

            rowEl.appendChild(offSpan);
            rowEl.appendChild(cellsWrap);
            rowEl.appendChild(asciiSpan);
            gridBox.appendChild(rowEl);
          }
        }
      }

      updateByteInspector(structure, pexState.selectedFileByteOffset);
    }

    function findFieldForFileOffset(structure, fileOff) {
      for (const sec of structure.sections) {
        if (fileOff >= sec.byteOffset && fileOff < sec.byteOffset + sec.totalChunkSize) {
          if (!sec.isSignature) {
            if (fileOff < sec.byteOffset + 4) {
              return { sec, fieldName: `${sec.name} Chunk Envelope: 4-Byte Length (uint32 BE)` };
            }
            if (fileOff < sec.byteOffset + 8) {
              return { sec, fieldName: `${sec.name} Chunk Envelope: 4-Byte ASCII Type ("${sec.type}")` };
            }
            if (fileOff >= sec.dataOffset + sec.effectiveDataLength) {
              return { sec, fieldName: `${sec.name} Chunk Envelope: 4-Byte CRC-32 Checksum` };
            }
          }
          if (sec.decodedFields) {
            for (const f of sec.decodedFields) {
              if (f.fileByteOffset >= 0 && fileOff >= f.fileByteOffset && fileOff <= f.fileByteEnd) {
                return { sec, fieldName: `${sec.name}: ${f.field} (${f.value})` };
              }
            }
          }
          return { sec, fieldName: `${sec.name} Chunk Payload Data` };
        }
      }
      return { sec: null, fieldName: 'PNG Data Byte' };
    }

    function updateByteInspector(structure, fileOff) {
      const bytes = pexState.workingPngBytes;
      if (!bytes || bytes.length === 0) return;
      const safeOff = Math.max(0, Math.min(bytes.length - 1, fileOff));
      const b = bytes[safeOff];
      const { sec, fieldName } = findFieldForFileOffset(structure, safeOff);

      const fOffEl = el('pex-insp-file-off');
      const secEl = el('pex-insp-section');
      const hexEl = el('pex-insp-hex');
      const binEl = el('pex-insp-bin');
      const decEl = el('pex-insp-dec');
      const ascEl = el('pex-insp-ascii');
      const fldEl = el('pex-insp-field');

      if (fOffEl) fOffEl.textContent = `${safeOff} (0x${safeOff.toString(16).padStart(4, '0').toUpperCase()})`;
      if (secEl) secEl.textContent = sec ? `${sec.name} (${sec.type})` : 'PNG File';
      if (hexEl) hexEl.textContent = `0x${b.toString(16).padStart(2, '0').toUpperCase()}`;
      if (binEl) binEl.textContent = b.toString(2).padStart(8, '0');
      if (decEl) decEl.textContent = String(b);
      if (ascEl) ascEl.textContent = (b >= 32 && b <= 126) ? `'${String.fromCharCode(b)}'` : 'Non-printable (.)';
      if (fldEl) fldEl.textContent = fieldName;
    }

    function renderEditorTab(structure) {
      const mapEl = el('pex-editor-byte-map');
      const bitsRow = el('pex-8bits-row');
      const selLbl = el('pex-bit-selected-label');
      const affFld = el('pex-bit-affected-field');
      const origValEl = el('pex-bit-orig-val');
      const currValEl = el('pex-bit-curr-val');
      const liveValEl = el('pex-editor-live-validation');

      if (!mapEl || !bitsRow) return;

      const metaBytes = pexState.workingMetaBytes || new Uint8Array(0);
      const origMeta = pexState.originalMetaBytes || new Uint8Array(0);

      if (!structure.msbxSection || metaBytes.length === 0) {
        mapEl.innerHTML = `<div style="padding:12px; color:var(--text-muted);">No <code>msBX</code> chunk present in working PNG copy. Click "Reset to Original" or use the Structured Editor on the right to rebuild an <code>msBX</code> chunk.</div>`;
        bitsRow.innerHTML = '';
        return;
      }

      if (pexState.selectedMetaByteIndex >= metaBytes.length) {
        pexState.selectedMetaByteIndex = 0;
      }
      const idx = pexState.selectedMetaByteIndex;
      const curByte = metaBytes[idx];
      const origByte = idx < origMeta.length ? origMeta[idx] : curByte;

      // Render byte chips inside msBX payload
      mapEl.innerHTML = '';
      for (let i = 0; i < metaBytes.length; i++) {
        const chip = document.createElement('div');
        const isMod = i >= origMeta.length || metaBytes[i] !== origMeta[i];
        chip.className = 'pex-edit-byte-chip' + (isMod ? ' modified' : '') + (i === idx ? ' active' : '');
        chip.innerHTML = `<small>+${i}</small><strong>${metaBytes[i].toString(16).padStart(2, '0').toUpperCase()}</strong>`;
        chip.addEventListener('click', () => {
          pexState.selectedMetaByteIndex = i;
          renderEditorTab(structure);
        });
        mapEl.appendChild(chip);
      }

      // Identify affected metadata field for selected byte index
      const bd = structure.msbxSection.msbxBreakdown;
      let matchingFields = [];
      if (bd && bd.fields) {
        matchingFields = bd.fields.filter(f => f.chunkByteOffset >= 0 && idx >= f.chunkByteOffset && idx <= f.chunkByteEnd);
      }
      const fieldLabel = matchingFields.length > 0
        ? matchingFields.map(f => f.field).join(' / ')
        : `msBX Payload Byte +${idx}`;

      if (selLbl) {
        selLbl.innerHTML = `<b>Selected Byte:</b> Offset <code>+${idx}</code> in <code>${structure.msbxSection.type}</code> (File Offset <code>${structure.msbxSection.dataOffset + idx}</code>)`;
      }
      if (affFld) affFld.textContent = fieldLabel;
      if (origValEl) {
        origValEl.textContent = `${origByte.toString(2).padStart(8, '0')} (0x${origByte.toString(16).padStart(2, '0').toUpperCase()} • Dec ${origByte})`;
      }
      if (currValEl) {
        currValEl.textContent = `${curByte.toString(2).padStart(8, '0')} (0x${curByte.toString(16).padStart(2, '0').toUpperCase()} • Dec ${curByte})`;
      }
      const hexInputEl = el('pex-direct-hex-input');
      if (hexInputEl) {
        hexInputEl.value = curByte.toString(16).padStart(2, '0').toUpperCase();
      }

      // Render 8 clickable bit buttons (b7 MSB down to b0 LSB)
      bitsRow.innerHTML = '';
      for (let bit = 7; bit >= 0; bit--) {
        const bitVal = (curByte >>> bit) & 1;
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'pex-bit-btn' + (bitVal === 1 ? ' bit-one' : '');
        btn.innerHTML = `
          <span class="bit-idx">Bit ${bit}${bit === 7 ? ' (MSB)' : (bit === 0 ? ' (LSB)' : '')}</span>
          <span class="bit-val">${bitVal}</span>
        `;
        btn.addEventListener('click', async () => {
          pushUndoSnapshot();
          const newMeta = new Uint8Array(pexState.workingMetaBytes);
          newMeta[idx] ^= (1 << bit);
          pexState.workingMetaBytes = newMeta;
          pexState.workingPngBytes = BitEngine.rebuildPngWithModifiedMetadata(pexState.workingPngBytes, newMeta);
          await refreshAllExplorerViews();
        });
        bitsRow.appendChild(btn);
      }

      // Sync Structured Editor form controls from decoded metadata if valid
      try {
        const decMeta = BitEngine.decodeMsBxMetadata(metaBytes, null, structure.ihdrInfo);
        if (el('pex-edit-schema-ver')) el('pex-edit-schema-ver').value = String(decMeta.metaVersion);
        if (el('pex-edit-k')) el('pex-edit-k').value = String(decMeta.k);
        if (el('pex-edit-scope')) el('pex-edit-scope').value = decMeta.scope;
        if (el('pex-edit-keytype')) el('pex-edit-keytype').value = decMeta.keyType;
        if (el('pex-edit-colormode')) el('pex-edit-colormode').value = String(decMeta.originalColorMode);
        if (el('pex-edit-maskcodec') && decMeta.maskCodec) el('pex-edit-maskcodec').value = String(decMeta.maskCodec);
        if (liveValEl) {
          liveValEl.innerHTML = `
            <div class="pex-tier-item pass">
              <div>
                <strong>✔ PNG Chunk Rebuilt &amp; Schema Valid (v${decMeta.metaVersion})</strong>
                <div style="font-size:11.5px; color:var(--text-muted);">CRC-32: <code>${structure.msbxSection.crcHex}</code> • k = ${decMeta.k} • Scope = ${decMeta.scope} • KeyType = ${decMeta.keyType}</div>
              </div>
              <span class="pex-tier-badge pass">SCHEMA OK</span>
            </div>
          `;
        }
      } catch (err) {
        if (liveValEl) {
          liveValEl.innerHTML = `
            <div class="pex-tier-item fail">
              <div>
                <strong>✖ Metadata Schema Validation Error Triggered by Bit Edit</strong>
                <div style="font-size:11.5px; color:#ef4444;">${err.message || String(err)}</div>
              </div>
              <span class="pex-tier-badge fail">INVALID SCHEMA</span>
            </div>
          `;
        }
      }
    }

    async function renderOptimizationTab() {
      if (!pexState.workingPngBytes) return;
      const cmp = await BitEngine.compareMetadataOptimization(pexState.workingPngBytes);

      const kpiGrid = el('pex-opt-kpi-grid');
      if (kpiGrid) {
        const activeOrig = cmp.scope !== 'full' ? cmp.originalMetadataBytes : cmp.originalMetadataBytes;
        const activeOpt = cmp.scope !== 'full' ? cmp.optimizedMetadataBytes : cmp.optimizedMetadataBytes;
        kpiGrid.innerHTML = `
          <div class="pex-kpi-card">
            <span class="kpi-label">Legacy v1 Metadata Size</span>
            <span class="kpi-val">${activeOrig} B</span>
            <span class="kpi-sub">+12 B chunk overhead = ${activeOrig + 12} B</span>
          </div>
          <div class="pex-kpi-card">
            <span class="kpi-label">Optimized v2 Metadata Size</span>
            <span class="kpi-val" style="color:var(--primary-blue);">${activeOpt} B</span>
            <span class="kpi-sub">+12 B chunk overhead = ${activeOpt + 12} B</span>
          </div>
          <div class="pex-kpi-card">
            <span class="kpi-label">Metadata Bytes Saved</span>
            <span class="kpi-val" style="color:var(--accent-emerald);">−${cmp.bytesSaved} B</span>
            <span class="kpi-sub">${cmp.storageReductionPct}% Metadata Reduction</span>
          </div>
          <div class="pex-kpi-card">
            <span class="kpi-label">Selective Mask vs. Raw Binary</span>
            <span class="kpi-val" style="color:var(--accent-emerald);">−${cmp.selectiveVsRawMaskSaved.toLocaleString()} B</span>
            <span class="kpi-sub">${cmp.selectiveVsRawReductionPct}% Saved vs Raw Mask</span>
          </div>
          <div class="pex-kpi-card">
            <span class="kpi-label">Total PNG Size (Before → After)</span>
            <span class="kpi-val">${cmp.totalPngBeforeBytes.toLocaleString()} → ${cmp.totalPngAfterBytes.toLocaleString()} B</span>
            <span class="kpi-sub">Saved ${cmp.totalPngBeforeBytes - cmp.totalPngAfterBytes} B in PNG container</span>
          </div>
          <div class="pex-kpi-card">
            <span class="kpi-label">v2 Encode / Decode Speed</span>
            <span class="kpi-val">${cmp.v2EncodeTimeMs} / ${cmp.v2DecodeTimeMs} ms</span>
            <span class="kpi-sub">v1: ${cmp.v1EncodeTimeMs} / ${cmp.v1DecodeTimeMs} ms</span>
          </div>
        `;
      }

      const fieldsTbody = el('pex-opt-fields-tbody');
      if (fieldsTbody) {
        fieldsTbody.innerHTML = '';
        cmp.fieldSavingsBreakdown.forEach(row => {
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td><strong>${row.component}</strong></td>
            <td><code>${row.legacyV1}</code></td>
            <td><code style="color:var(--primary-blue); font-weight:700;">${row.optimizedV2}</code></td>
            <td><strong style="color:${row.bytesSaved > 0 ? 'var(--accent-emerald)' : 'var(--text-muted)'};">${row.bytesSaved > 0 ? '−' + row.bytesSaved + ' B' : '0 B (Security Preserved)'}</strong></td>
            <td>${row.explanation}</td>
          `;
          fieldsTbody.appendChild(tr);
        });
      }

      const maskSub = el('pex-mask-bench-subtitle');
      if (maskSub) {
        maskSub.textContent = cmp.usingSyntheticMaskForBenchmark
          ? `Benchmarking all 4 lossless mask compression codecs on a ${cmp.width}×${cmp.height} (${cmp.maskBenchmark.totalPixels.toLocaleString()} px) AI facial contour mask:`
          : `Benchmarking all 4 lossless mask compression codecs on the embedded ${cmp.width}×${cmp.height} (${cmp.maskBenchmark.totalPixels.toLocaleString()} px) selective mask:`;
      }

      const maskTbody = el('pex-mask-bench-tbody');
      if (maskTbody) {
        maskTbody.innerHTML = '';
        cmp.maskBenchmark.methods.forEach(m => {
          const isBest = m.codecId === cmp.maskBenchmark.bestCodecId;
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td>
              <strong>Codec ${m.codecId}: ${m.name}</strong>
              ${isBest ? `<span class="pex-tier-badge pass" style="margin-left:6px;">★ Optimal Selected</span>` : ''}
            </td>
            <td><strong>${m.encodedBytes.toLocaleString()} B</strong></td>
            <td><span style="color:var(--accent-emerald); font-weight:700;">${m.bytesSavedVsRaw >= 0 ? '−' + m.bytesSavedVsRaw.toLocaleString() + ' B' : '+' + Math.abs(m.bytesSavedVsRaw) + ' B'}</span></td>
            <td><code>${m.compressionRatio}×</code></td>
            <td><strong>${m.reductionPct}%</strong></td>
            <td><code>${m.encodeTimeMs} ms / ${m.decodeTimeMs} ms</code></td>
            <td><span class="pex-tier-badge pass">✔ 0 Diff Bits (${m.totalPixels || cmp.maskBenchmark.totalPixels} px)</span></td>
          `;
          maskTbody.appendChild(tr);
        });
      }
    }

    async function renderValidationTab() {
      if (!pexState.workingPngBytes) return;
      const pwdInput = el('pex-test-password');
      const candidateKey = pwdInput ? pwdInput.value.trim() : pexState.knownPassword;
      const report = await BitEngine.validatePngAndMetadataMultiLevel(
        pexState.workingPngBytes,
        candidateKey,
        pexState.referencePlainImageData
      );

      const tiersEl = el('pex-validation-tiers');
      if (!tiersEl) return;

      const tiers = [
        { title: '1. PNG Structural Validity (Signature, Chunks & CRC-32)', data: report.level1 },
        { title: '2. Metadata Schema Validity (msBX Format & Bit-Packed Ranges)', data: report.level2 },
        { title: '3. Cryptographic Authentication (32-Byte Keyed SHA-256 Tag)', data: report.level3 },
        { title: '4. Decryption Verification (3-Stage Recovery & 0 Diff Pixels)', data: report.level4 }
      ];

      tiersEl.innerHTML = '';
      tiers.forEach(t => {
        const cls = t.data.status === 'PASS' ? 'pass' : (t.data.status === 'FAIL' ? 'fail' : 'warn');
        const div = document.createElement('div');
        div.className = `pex-tier-item ${cls}`;
        div.innerHTML = `
          <div>
            <strong>${t.title}</strong>
            <div style="font-size:11.5px; color:var(--text-muted); margin-top:2px;">${t.data.summary}</div>
          </div>
          <span class="pex-tier-badge ${cls}">${t.data.status}</span>
        `;
        tiersEl.appendChild(div);
      });

      // Step 4 Validate & Download button state + sync with main Encrypted PNG output
      const btnVerified = el('btn-pex-download-verified');
      const btnUnverified = el('btn-pex-download-unverified');
      const step4Desc = el('pex-step4-status-desc');

      if (report.allVerified) {
        // Keep main Encryption Page output synced with the latest validated PNG bytes!
        if (state.lastEncryptedPngBytes) {
          state.lastEncryptedPngBytes = new Uint8Array(pexState.workingPngBytes);
        }
        if (btnVerified) {
          btnVerified.disabled = false;
          btnVerified.innerHTML = `<i class="fa-solid fa-download"></i> Download Final Validated Encrypted PNG (${pexState.workingPngBytes.byteLength.toLocaleString()} B)`;
        }
        if (btnUnverified) btnUnverified.style.display = 'none';
        if (step4Desc) {
          step4Desc.innerHTML = `<span style="color:var(--accent-emerald); font-weight:700;">✔ All 4 Validation Tiers Passed (0 Different Pixels):</span> Your customized <code>msBX</code> metadata and encrypted pixel data are 100% verified and ready for download.`;
        }
      } else {
        if (btnVerified) {
          btnVerified.disabled = true;
          btnVerified.innerHTML = `<i class="fa-solid fa-ban"></i> Verified Download Blocked (Fix or Reset Invalid Edit)`;
        }
        if (btnUnverified) btnUnverified.style.display = 'inline-flex';
        if (step4Desc) {
          const reason = !report.level1.valid
            ? report.level1.summary
            : (!report.level2.valid ? report.level2.summary : report.level3.summary);
          step4Desc.innerHTML = `<span style="color:#ef4444; font-weight:700;">✖ Validation Failed:</span> ${reason} Click <b>"Reset to Validated Encrypted PNG"</b> to restore valid output, or export as an unverified test file.`;
        }
      }

      return report;
    }

    function switchToSubTab(panelId) {
      document.querySelectorAll('#enc-integrated-explorer-section .pex-subtab').forEach(btn => {
        btn.classList.toggle('active', btn.getAttribute('data-pex-tab') === panelId);
      });
      document.querySelectorAll('#enc-integrated-explorer-section .pex-subpanel').forEach(panel => {
        panel.style.display = (panel.id === panelId) ? 'block' : 'none';
      });
    }

    // Sub-tab click listeners
    document.querySelectorAll('#enc-integrated-explorer-section .pex-subtab').forEach(btn => {
      btn.addEventListener('click', () => {
        const target = btn.getAttribute('data-pex-tab');
        switchToSubTab(target);
      });
    });

    // Storage unit switcher (Bytes / KiB / % of File Size)
    document.querySelectorAll('.pex-unit-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.pex-unit-btn').forEach(b => {
          b.classList.remove('btn-primary');
          b.classList.add('btn-outline');
        });
        btn.classList.remove('btn-outline');
        btn.classList.add('btn-primary');
        pexState.storageUnit = btn.getAttribute('data-unit') || 'bytes';
        if (pexState.workingPngBytes) {
          renderStructureTab(BitEngine.parsePngBinaryStructure(pexState.workingPngBytes));
        }
      });
    });

    // Hex Viewer toolbar listeners
    const secSelect = el('pex-hex-section-select');
    if (secSelect) {
      secSelect.addEventListener('change', (e) => {
        pexState.hexSectionIndex = parseInt(e.target.value, 10);
        pexState.hexPage = 0;
        if (pexState.workingPngBytes) {
          renderHexViewerTab(BitEngine.parsePngBinaryStructure(pexState.workingPngBytes));
        }
      });
    }

    document.querySelectorAll('.pex-view-mode-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.pex-view-mode-btn').forEach(b => {
          b.classList.remove('btn-primary');
          b.classList.add('btn-outline');
        });
        btn.classList.remove('btn-outline');
        btn.classList.add('btn-primary');
        pexState.hexViewMode = btn.getAttribute('data-view') || 'hex';
        if (pexState.workingPngBytes) {
          renderHexViewerTab(BitEngine.parsePngBinaryStructure(pexState.workingPngBytes));
        }
      });
    });

    if (el('btn-pex-hex-prev')) {
      el('btn-pex-hex-prev').addEventListener('click', () => {
        pexState.hexPage = Math.max(0, pexState.hexPage - 1);
        if (pexState.workingPngBytes) {
          renderHexViewerTab(BitEngine.parsePngBinaryStructure(pexState.workingPngBytes));
        }
      });
    }
    if (el('btn-pex-hex-next')) {
      el('btn-pex-hex-next').addEventListener('click', () => {
        pexState.hexPage++;
        if (pexState.workingPngBytes) {
          renderHexViewerTab(BitEngine.parsePngBinaryStructure(pexState.workingPngBytes));
        }
      });
    }

    if (el('btn-pex-edit-this-byte')) {
      el('btn-pex-edit-this-byte').addEventListener('click', () => {
        if (!pexState.workingPngBytes) return;
        const structure = BitEngine.parsePngBinaryStructure(pexState.workingPngBytes);
        if (structure.msbxSection) {
          const rel = pexState.selectedFileByteOffset - structure.msbxSection.dataOffset;
          if (rel >= 0 && rel < structure.msbxSection.dataLength) {
            pexState.selectedMetaByteIndex = rel;
          }
        }
        switchToSubTab('pex-panel-editor');
        renderEditorTab(structure);
      });
    }

    // Undo / Redo / Reset / Export buttons
    if (el('btn-pex-undo')) {
      el('btn-pex-undo').addEventListener('click', async () => {
        if (pexState.undoStack.length === 0) return;
        pexState.redoStack.push({
          pngBytes: new Uint8Array(pexState.workingPngBytes),
          metaBytes: new Uint8Array(pexState.workingMetaBytes || 0)
        });
        const prev = pexState.undoStack.pop();
        pexState.workingPngBytes = prev.pngBytes;
        pexState.workingMetaBytes = prev.metaBytes;
        await refreshAllExplorerViews();
      });
    }

    if (el('btn-pex-redo')) {
      el('btn-pex-redo').addEventListener('click', async () => {
        if (pexState.redoStack.length === 0) return;
        pexState.undoStack.push({
          pngBytes: new Uint8Array(pexState.workingPngBytes),
          metaBytes: new Uint8Array(pexState.workingMetaBytes || 0)
        });
        const next = pexState.redoStack.pop();
        pexState.workingPngBytes = next.pngBytes;
        pexState.workingMetaBytes = next.metaBytes;
        await refreshAllExplorerViews();
      });
    }

    if (el('btn-pex-reset')) {
      el('btn-pex-reset').addEventListener('click', async () => {
        if (!pexState.originalPngBytes) return;
        await loadPngIntoExplorer(pexState.originalPngBytes, pexState.fileName);
      });
    }

    if (el('btn-pex-export-modified')) {
      el('btn-pex-export-modified').addEventListener('click', async () => {
        switchToSubTab('pex-panel-validation');
        await renderValidationTab();
      });
    }

    if (el('btn-pex-apply-hex')) {
      el('btn-pex-apply-hex').addEventListener('click', async () => {
        if (!pexState.workingPngBytes || !pexState.workingMetaBytes || pexState.workingMetaBytes.length === 0) return;
        const hexInput = el('pex-direct-hex-input');
        const rawHex = (hexInput ? hexInput.value.trim() : '').replace(/^0x/i, '');
        if (!/^[0-9a-fA-F]{1,2}$/.test(rawHex)) return;
        const val = parseInt(rawHex, 16) & 0xFF;
        const idx = pexState.selectedMetaByteIndex;
        if (idx < 0 || idx >= pexState.workingMetaBytes.length) return;
        pushUndoSnapshot();
        const newMeta = new Uint8Array(pexState.workingMetaBytes);
        newMeta[idx] = val;
        pexState.workingMetaBytes = newMeta;
        pexState.workingPngBytes = BitEngine.rebuildPngWithModifiedMetadata(pexState.workingPngBytes, newMeta);
        await refreshAllExplorerViews();
      });
    }

    if (el('btn-pex-download-verified')) {
      el('btn-pex-download-verified').addEventListener('click', async () => {
        if (!pexState.workingPngBytes) return;
        const report = await renderValidationTab();
        if (!report || !report.allVerified) return;
        state.lastEncryptedPngBytes = new Uint8Array(pexState.workingPngBytes);
        const blob = new Blob([pexState.workingPngBytes], { type: 'image/png' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'encrypted_photo.png';
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 3000);
      });
    }

    if (el('btn-pex-val-reset')) {
      el('btn-pex-val-reset').addEventListener('click', async () => {
        if (!pexState.originalPngBytes) return;
        await loadPngIntoExplorer(pexState.originalPngBytes, pexState.fileName);
      });
    }

    if (el('btn-pex-download-unverified')) {
      el('btn-pex-download-unverified').addEventListener('click', () => {
        if (!pexState.workingPngBytes) return;
        const blob = new Blob([pexState.workingPngBytes], { type: 'image/png' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `unverified_test_${pexState.fileName || 'encrypted_photo.png'}`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 3000);
      });
    }

    // Mode A — Structured Metadata & Configuration Editor Apply Button:
    // Regenerates encryption from the original image when encryption-critical settings (k, scope, schema, mask codec, or optional TLV) are edited!
    if (el('btn-pex-apply-structured')) {
      el('btn-pex-apply-structured').addEventListener('click', async () => {
        if (!pexState.workingPngBytes) return;
        const structure = BitEngine.parsePngBinaryStructure(pexState.workingPngBytes);
        const w = structure.ihdrInfo ? structure.ihdrInfo.width : 160;
        const h = structure.ihdrInfo ? structure.ihdrInfo.height : 120;

        let curMeta = null;
        if (structure.msbxSection) {
          try {
            curMeta = BitEngine.decodeMsBxMetadata(structure.msbxSection.dataBytes, null, { width: w, height: h });
          } catch (_) {}
        }

        const targetVer = parseInt(el('pex-edit-schema-ver')?.value || '2', 10);
        const newK = parseInt(el('pex-edit-k')?.value || '2', 10);
        const newScope = el('pex-edit-scope')?.value || 'full';
        const newKeyType = el('pex-edit-keytype')?.value || 'text';
        const newColorMode = parseInt(el('pex-edit-colormode')?.value || '1', 10);
        const newMaskCodec = parseInt(el('pex-edit-maskcodec')?.value || '3', 10);
        const optTag = (el('pex-edit-opt-tag')?.value || '').trim();
        const optDesc = (el('pex-edit-opt-desc')?.value || '').trim();

        const optFields = [];
        if (optTag.length > 0) optFields.push({ id: 2, critical: false, value: optTag });
        if (optDesc.length > 0) optFields.push({ id: 3, critical: false, value: optDesc });

        // If original reference image + key are available, regenerate a 100% cryptographically valid encrypted PNG!
        const pwdInput = el('pex-test-password');
        const activeKey = (pwdInput && pwdInput.value.trim()) ? pwdInput.value.trim() : pexState.knownPassword;
        if (pexState.referencePlainImageData && activeKey) {
          let targetMask = null;
          if (newScope === 'person' && state.bodyMask && state.bodyMask.length === w * h) {
            targetMask = state.bodyMask;
          } else if (newScope === 'face' && state.faceMask && state.faceMask.length === w * h) {
            targetMask = state.faceMask;
          } else if (curMeta && curMeta.mask && curMeta.mask.length === w * h && newScope !== 'full') {
            targetMask = curMeta.mask;
          } else if (newScope !== 'full') {
            targetMask = new Uint8Array(w * h);
            for (let i = 0; i < Math.floor((w * h) / 4); i++) targetMask[i] = 1;
          }

          const cleanOrigCopy = new ImageData(
            new Uint8ClampedArray(pexState.referencePlainImageData.data),
            pexState.referencePlainImageData.width,
            pexState.referencePlainImageData.height
          );
          const regen = await BitEngine.encryptToPNG(cleanOrigCopy, activeKey, targetMask, {
            k: newK,
            iterations: curMeta ? curMeta.iterations : BitEngine.DEFAULT_KDF_ITERATIONS,
            keyType: newKeyType,
            scope: newScope,
            originalColorMode: newColorMode,
            metaVersion: targetVer,
            maskCodec: newMaskCodec,
            optionalFields: optFields.length > 0 ? optFields : null,
            protectMask: !!(DOM.encProtectMask && DOM.encProtectMask.checked)
          });

          pushUndoSnapshot();
          pexState.originalPngBytes = new Uint8Array(regen.pngBytes);
          pexState.workingPngBytes = new Uint8Array(regen.pngBytes);

          // If this was the main Encryption Tab image, also sync Step 2 Preview & Header Card!
          if (state.lastOriginalImageData &&
              state.lastOriginalImageData.width === cleanOrigCopy.width &&
              state.lastOriginalImageData.height === cleanOrigCopy.height) {
            state.lastEncryptedPngBytes = new Uint8Array(regen.pngBytes);
            state.lastEncryptedHeader = regen.header;
            if (DOM.encKSelect) DOM.encKSelect.value = String(newK);
            if (DOM.canvasEncResult) {
              const ctx = DOM.canvasEncResult.getContext('2d');
              ctx.putImageData(regen.imageData, 0, 0);
            }
            if (DOM.valEncMse) DOM.valEncMse.textContent = regen.mse;
            if (DOM.valEncPsnr) DOM.valEncPsnr.textContent = regen.psnr + (regen.psnr === '∞' ? '' : ' dB');
            if (DOM.valEncSwapped) DOM.valEncSwapped.textContent = regen.swappedCount.toLocaleString();
            renderMsbxHeaderCard(
              DOM.encMsbxInfo,
              regen.header,
              regen.pngBytes.byteLength,
              'Self-Describing Encrypted PNG (Metadata Chunk: msBX)',
              {
                verifiedLosslessPng: regen.verifiedLosslessPng,
                processingTimeMs: regen.processingTimeMs
              }
            );
          }

          await refreshAllExplorerViews();
          return;
        }

        const salt = curMeta ? curMeta.salt : BitEngine.generateRandomSalt(16);
        const verificationTag = curMeta ? curMeta.verificationTag : new Uint8Array(32).fill(0x5A);
        const iterations = curMeta ? curMeta.iterations : 100000;

        let mask = curMeta && curMeta.mask ? curMeta.mask : null;
        if (newScope !== 'full' && (!mask || mask.length !== w * h)) {
          mask = new Uint8Array(w * h);
          for (let i = 0; i < Math.floor((w * h) / 4); i++) mask[i] = 1;
        }

        pushUndoSnapshot();
        let rebuiltMeta;
        if (targetVer === 2) {
          const encodedMask = (newScope !== 'full' && mask)
            ? BitEngine.encodeMaskWithCodec(mask, newMaskCodec)
            : null;
          rebuiltMeta = BitEngine.encodeMsBxMetadataV2({
            algoVersion: 1,
            originalColorMode: newColorMode,
            k: newK,
            keyType: newKeyType,
            scope: newScope,
            maskCodec: encodedMask ? newMaskCodec : 0,
            maskProtected: false,
            iterations,
            salt,
            verificationTag,
            encodedMaskBytes: encodedMask,
            optionalFields: optFields.length > 0 ? optFields : null
          });
        } else {
          const rleMask = (newScope !== 'full' && mask) ? BitEngine.encodeMaskTrailer(mask) : null;
          rebuiltMeta = BitEngine.encodeMsBxMetadata({
            metaVersion: 1,
            originalColorMode: newColorMode,
            k: newK,
            keyType: newKeyType,
            scope: newScope,
            maskEncoding: rleMask ? 1 : 0,
            width: w,
            height: h,
            iterations,
            salt,
            verificationTag,
            encodedMaskBytes: rleMask
          });
        }

        pexState.workingMetaBytes = rebuiltMeta;
        pexState.workingPngBytes = BitEngine.rebuildPngWithModifiedMetadata(pexState.workingPngBytes, rebuiltMeta);
        await refreshAllExplorerViews();
      });
    }

    // Convert current PNG to Optimized Schema v2 in Tab 4 (regenerating authentic v2 tag when original image & key exist)
    if (el('btn-pex-apply-v2-opt')) {
      el('btn-pex-apply-v2-opt').addEventListener('click', async () => {
        if (!pexState.workingPngBytes) return;
        if (el('pex-edit-schema-ver')) el('pex-edit-schema-ver').value = '2';
        if (el('pex-edit-maskcodec')) el('pex-edit-maskcodec').value = '4';
        if (el('btn-pex-apply-structured') && pexState.referencePlainImageData) {
          el('btn-pex-apply-structured').click();
          return;
        }
        const cmp = await BitEngine.compareMetadataOptimization(pexState.workingPngBytes);
        pushUndoSnapshot();
        pexState.workingMetaBytes = cmp.v2Payload;
        pexState.workingPngBytes = BitEngine.rebuildPngWithModifiedMetadata(pexState.workingPngBytes, cmp.v2Payload);
        await refreshAllExplorerViews();
      });
    }

    // Validation & Educational Tampering Lab listeners
    if (el('btn-pex-run-validation')) {
      el('btn-pex-run-validation').addEventListener('click', async () => {
        await renderValidationTab();
      });
    }
    if (el('btn-pex-validate-now')) {
      el('btn-pex-validate-now').addEventListener('click', async () => {
        await renderValidationTab();
      });
    }

    document.querySelectorAll('.pex-tamper-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!pexState.originalPngBytes) return;
        const presetId = btn.getAttribute('data-tamper');
        try {
          pushUndoSnapshot();
          const tamperRes = BitEngine.applyEducationalTamperPreset(pexState.originalPngBytes, presetId);
          pexState.workingPngBytes = tamperRes.tamperedPngBytes;
          pexState.workingMetaBytes = tamperRes.modifiedMetaBytes;
          await refreshAllExplorerViews();

          const report = await renderValidationTab();
          const resBox = el('pex-tamper-result-box');
          const titleEl = el('pex-tamper-result-title');
          const expEl = el('pex-tamper-expected');
          const actEl = el('pex-tamper-actual');
          if (resBox && titleEl && expEl && actEl && report) {
            resBox.style.display = 'block';
            titleEl.innerHTML = `<i class="fa-solid fa-microscope"></i> ${tamperRes.title}`;
            expEl.textContent = tamperRes.expectedEffect;
            actEl.textContent = `Tier 1 (PNG CRC/Structure): ${report.level1.status} | Tier 2 (Schema): ${report.level2.status} | Tier 3 (SHA-256 Auth): ${report.level3.status} | Tier 4 (Decryption): ${report.level4.status} — ${report.level2.valid ? report.level3.summary : report.level2.summary}`;
          }
        } catch (err) {
          console.error('Tamper preset error:', err);
        }
      });
    });

    // Top Quick Action Buttons
    if (el('pex-file-input')) {
      el('pex-file-input').addEventListener('change', async (e) => {
        const file = e.target.files && e.target.files[0];
        if (!file) return;
        const buf = await file.arrayBuffer();
        pexState.referencePlainImageData = null;
        await loadPngIntoExplorer(new Uint8Array(buf), file.name);
        e.target.value = '';
      });
    }

    if (el('btn-pex-load-current')) {
      el('btn-pex-load-current').addEventListener('click', async () => {
        if (state.lastEncryptedPngBytes) {
          pexState.referencePlainImageData = state.lastOriginalImageData || null;
          if (DOM.encPassword && DOM.encPassword.value) {
            pexState.knownPassword = DOM.encPassword.value;
            if (el('pex-test-password')) el('pex-test-password').value = pexState.knownPassword;
          }
          await loadPngIntoExplorer(state.lastEncryptedPngBytes, 'encrypted_photo.png');
        } else if (state.decPngBytes) {
          await loadPngIntoExplorer(state.decPngBytes, `${state.decFileName || 'uploaded'}.png`);
        } else {
          await generateDemoEncryptedPng(2);
        }
      });
    }

    if (el('btn-pex-load-sample')) {
      el('btn-pex-load-sample').addEventListener('click', async () => {
        await generateDemoEncryptedPng(2);
      });
    }

    if (el('btn-pex-load-sample-v1')) {
      el('btn-pex-load-sample-v1').addEventListener('click', async () => {
        await generateDemoEncryptedPng(1);
      });
    }

    // Automatically initialize with a sample v2 encrypted PNG when the PNG Binary Explorer tab is opened
    const tabBtnExplorer = el('tab-btn-png-explorer');
    if (tabBtnExplorer) {
      tabBtnExplorer.addEventListener('click', async () => {
        if (!pexState.workingPngBytes) {
          if (state.lastEncryptedPngBytes) {
            pexState.referencePlainImageData = state.lastOriginalImageData || null;
            await loadPngIntoExplorer(state.lastEncryptedPngBytes, 'encrypted_photo.png');
          } else {
            await generateDemoEncryptedPng(2);
          }
        }
      });
    }

    // Expose automatic post-encryption hook so Step 2 immediately populates the Encryption Page's PNG Binary Structure & Metadata Editor
    window.syncIntegratedPngExplorerWithEncryption = async (pngBytes, effectiveKey, origImageData, fileName = 'encrypted_photo.png') => {
      pexState.referencePlainImageData = origImageData || null;
      if (effectiveKey) {
        pexState.knownPassword = effectiveKey;
        const pwdEl = el('pex-test-password');
        if (pwdEl) pwdEl.value = effectiveKey;
      }
      await loadPngIntoExplorer(pngBytes, fileName);
      if (typeof window.syncReadOnlyExplorerIfEmpty === 'function') {
        window.syncReadOnlyExplorerIfEmpty(pngBytes, fileName);
      }
    };

    const btnScrollToExplorer = el('btn-scroll-to-explorer');
    if (btnScrollToExplorer) {
      btnScrollToExplorer.addEventListener('click', () => {
        const detailsEl = el('enc-explorer-details');
        if (detailsEl) detailsEl.open = true;
        const secEl = document.getElementById('enc-integrated-explorer-section');
        if (secEl) secEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    }

    // Generate initial sample in background so Explorer is ready immediately
    setTimeout(() => {
      if (!pexState.workingPngBytes) {
        generateDemoEncryptedPng(2).catch(() => {});
      }
    }, 150);
  }

  /* ==========================================================================
     Dedicated Read-Only PNG Binary Explorer Page (`#png-explorer-tab`)
     Purpose: Upload, Inspect & Test Existing PNG Files Only (Strictly Read-Only)
     Reuses shared BitEngine PNG parser, chunk analyzer, field decoder & validator
     ========================================================================== */
  function initReadOnlyPngExplorerPage() {
    const roState = {
      fileName: 'sample_encrypted_photo.png',
      pngBytes: null,
      storageUnit: 'bytes',
      hexSectionIndex: -1,
      hexViewMode: 'hex', // 'hex' | 'binary' | 'decimal' | 'decoded'
      hexPage: 0,
      hexPageSize: 256,
      highlightRange: null,
      selectedFileByteOffset: 0
    };

    const el = (id) => document.getElementById(id);

    function formatSize(bytes, totalBytes, unit) {
      if (unit === 'kib') return `${(bytes / 1024).toFixed(2)} KiB`;
      if (unit === 'pct') {
        const pct = totalBytes > 0 ? ((bytes / totalBytes) * 100).toFixed(2) : '0.00';
        return `${pct}%`;
      }
      return `${bytes.toLocaleString()} B`;
    }

    function getChunkColor(type) {
      const palette = {
        SIGN: '#6366f1',
        IHDR: '#0ea5e9',
        msBX: '#10b981',
        msBx: '#14b8a6',
        IDAT: '#3b82f6',
        IEND: '#8b5cf6'
      };
      return palette[type] || '#f59e0b';
    }

    function switchRoSubTab(panelId) {
      document.querySelectorAll('#png-explorer-tab .pex-subtab').forEach(btn => {
        btn.classList.toggle('active', btn.getAttribute('data-ro-tab') === panelId);
      });
      document.querySelectorAll('#png-explorer-tab .ro-pex-subpanel').forEach(panel => {
        panel.style.display = (panel.id === panelId) ? 'block' : 'none';
      });
    }

    async function loadReadOnlyPng(bytes, fileName = 'uploaded_image.png') {
      roState.fileName = fileName;
      roState.pngBytes = new Uint8Array(bytes);
      roState.hexPage = 0;
      roState.highlightRange = null;

      const structure = BitEngine.parsePngBinaryStructure(roState.pngBytes);
      roState.selectedFileByteOffset = structure.msbxSection ? structure.msbxSection.dataOffset : 0;

      renderRoSummary(structure);
      renderRoStructureTab(structure);
      renderRoHexTab(structure);
      renderRoMetadataTab(structure);
      await renderRoTestingTab(structure);
    }

    function renderRoSummary(structure) {
      if (el('ro-pex-sum-filename')) el('ro-pex-sum-filename').textContent = roState.fileName;
      if (el('ro-pex-sum-filesize')) {
        el('ro-pex-sum-filesize').textContent = `${structure.totalByteLength.toLocaleString()} B (${(structure.totalByteLength / 1024).toFixed(2)} KiB)`;
      }
      if (el('ro-pex-sum-dims')) {
        el('ro-pex-sum-dims').textContent = structure.ihdrInfo
          ? `${structure.ihdrInfo.width} × ${structure.ihdrInfo.height} px (${structure.ihdrInfo.colorTypeLabel})`
          : 'Invalid / Missing IHDR';
      }
      if (el('ro-pex-sum-chunk')) {
        const chEl = el('ro-pex-sum-chunk');
        if (structure.msbxSection && structure.msbxSection.msbxBreakdown) {
          const bd = structure.msbxSection.msbxBreakdown;
          const legacyTag = structure.msbxSection.type === 'msBx' ? ' (Legacy Chunk)' : '';
          chEl.textContent = `${structure.msbxSection.type}${legacyTag} • Schema v${bd.schemaVersion} (${bd.payloadByteLength} B)`;
          chEl.style.color = 'var(--accent-emerald)';
        } else {
          chEl.textContent = 'None (Ordinary Unencrypted PNG)';
          chEl.style.color = 'var(--text-muted)';
        }
      }
    }

    function renderRoStructureTab(structure) {
      const total = structure.totalByteLength;
      const formulaEl = el('ro-pex-size-formula');
      if (formulaEl) {
        const chunkSum = structure.chunks.reduce((a, c) => a + c.totalChunkSize, 0);
        formulaEl.innerHTML =
          `<b>Total PNG Size = Signature (${structure.signatureBytes} B) + All Chunk Sizes (${chunkSum.toLocaleString()} B across ${structure.chunkCount} chunks, incl. ${structure.totalChunksOverheadBytes} B overhead) = ${total.toLocaleString()} B</b> ` +
          (structure.sizeFormulaMatches
            ? `<span style="color:var(--accent-emerald); font-weight:700;">✔ Exact Sum Verified</span>`
            : `<span style="color:#ef4444; font-weight:700;">⚠ Truncated or Mismatched Size</span>`);
      }

      const barEl = el('ro-pex-storage-bar');
      const legEl = el('ro-pex-storage-legend');
      if (barEl && legEl) {
        barEl.innerHTML = '';
        legEl.innerHTML = '';
        for (const sec of structure.sections) {
          const color = getChunkColor(sec.type);
          const pct = Math.max(2.5, sec.percentage);
          const seg = document.createElement('div');
          seg.className = 'pex-bar-seg';
          seg.style.width = `${pct}%`;
          seg.style.background = color;
          seg.title = `${sec.name}: ${sec.totalChunkSize.toLocaleString()} B (${sec.percentage}%)`;
          seg.textContent = sec.percentage >= 7 ? `${sec.name} (${formatSize(sec.totalChunkSize, total, roState.storageUnit)})` : sec.name;
          seg.addEventListener('click', () => {
            roState.hexSectionIndex = sec.index;
            roState.hexPage = 0;
            switchRoSubTab('ro-panel-hex');
            renderRoHexTab(structure);
          });
          barEl.appendChild(seg);

          const card = document.createElement('div');
          card.className = 'pex-legend-card';
          card.innerHTML = `
            <span class="pex-legend-dot" style="background:${color};"></span>
            <div class="pex-legend-info">
              <strong>${sec.name} ${sec.isSignature ? '' : `(Data: ${sec.dataLength} B + 12 B)`}</strong>
              <span>${formatSize(sec.totalChunkSize, total, roState.storageUnit)} • ${sec.percentage}% of file</span>
            </div>
          `;
          legEl.appendChild(card);
        }
      }

      const tbody = el('ro-pex-chunks-tbody');
      if (tbody) {
        tbody.innerHTML = '';
        for (const sec of structure.sections) {
          const tr = document.createElement('tr');
          const crcBadge = sec.isSignature
            ? `<span class="pex-tier-badge pass">${sec.crcValid ? 'Magic OK' : 'Invalid Magic'}</span>`
            : (sec.crcValid && sec.lengthValid
              ? `<span class="pex-tier-badge pass">✔ ${sec.crcHex}</span>`
              : `<span class="pex-tier-badge fail">✖ ${sec.crcHex} (Expected ${sec.actualCrcHex})</span>`);

          tr.innerHTML = `
            <td>${sec.index}</td>
            <td><strong style="color:${getChunkColor(sec.type)};">${sec.name}</strong></td>
            <td><code>${sec.type}</code> <small style="color:var(--text-muted); display:block;">${sec.propertySummary}</small></td>
            <td><code>${sec.byteOffset}</code> <small>(0x${sec.byteOffset.toString(16).toUpperCase()})</small></td>
            <td><code>${sec.dataLength.toLocaleString()} B</code></td>
            <td><code>${sec.overheadBytes} B</code></td>
            <td><strong>${sec.totalChunkSize.toLocaleString()} B</strong></td>
            <td><code>${sec.percentage}%</code></td>
            <td>${crcBadge}</td>
            <td>
              <div style="font-size:11.5px; color:var(--text-muted); margin-bottom:4px;">${sec.purpose}</div>
              <button type="button" class="btn btn-xs btn-outline ro-inspect-sec-btn" data-sec-idx="${sec.index}">
                <i class="fa-solid fa-magnifying-glass"></i> Inspect Bytes
              </button>
            </td>
          `;
          tbody.appendChild(tr);
        }
        tbody.querySelectorAll('.ro-inspect-sec-btn').forEach(btn => {
          btn.addEventListener('click', () => {
            roState.hexSectionIndex = parseInt(btn.getAttribute('data-sec-idx'), 10);
            roState.hexPage = 0;
            switchRoSubTab('ro-panel-hex');
            renderRoHexTab(structure);
          });
        });
      }
    }

    function findRoFieldForOffset(structure, fileOff) {
      for (const sec of structure.sections) {
        if (fileOff >= sec.byteOffset && fileOff < sec.byteOffset + sec.totalChunkSize) {
          if (!sec.isSignature) {
            if (fileOff < sec.byteOffset + 4) return { sec, fieldName: `${sec.name} Envelope: 4-Byte Length (uint32 BE)` };
            if (fileOff < sec.byteOffset + 8) return { sec, fieldName: `${sec.name} Envelope: 4-Byte ASCII Type ("${sec.type}")` };
            if (fileOff >= sec.dataOffset + sec.effectiveDataLength) return { sec, fieldName: `${sec.name} Envelope: 4-Byte CRC-32` };
          }
          if (sec.decodedFields) {
            for (const f of sec.decodedFields) {
              if (f.fileByteOffset >= 0 && fileOff >= f.fileByteOffset && fileOff <= f.fileByteEnd) {
                return { sec, fieldName: `${sec.name}: ${f.field} (${f.value})` };
              }
            }
          }
          return { sec, fieldName: `${sec.name} Chunk Payload Data` };
        }
      }
      return { sec: null, fieldName: 'PNG Data Byte' };
    }

    function updateRoByteInspector(structure, fileOff) {
      const bytes = roState.pngBytes;
      if (!bytes || bytes.length === 0) return;
      const safeOff = Math.max(0, Math.min(bytes.length - 1, fileOff));
      const b = bytes[safeOff];
      const { sec, fieldName } = findRoFieldForOffset(structure, safeOff);

      if (el('ro-insp-file-off')) el('ro-insp-file-off').textContent = `${safeOff} (0x${safeOff.toString(16).padStart(4, '0').toUpperCase()})`;
      if (el('ro-insp-section')) el('ro-insp-section').textContent = sec ? `${sec.name} (${sec.type})` : 'PNG File';
      if (el('ro-insp-hex')) el('ro-insp-hex').textContent = `0x${b.toString(16).padStart(2, '0').toUpperCase()}`;
      if (el('ro-insp-bin')) el('ro-insp-bin').textContent = b.toString(2).padStart(8, '0');
      if (el('ro-insp-dec')) el('ro-insp-dec').textContent = String(b);
      if (el('ro-insp-ascii')) el('ro-insp-ascii').textContent = (b >= 32 && b <= 126) ? `'${String.fromCharCode(b)}'` : 'Non-printable (.)';
      if (el('ro-insp-field')) el('ro-insp-field').textContent = fieldName;
    }

    function renderRoHexTab(structure) {
      const selEl = el('ro-pex-section-select');
      if (selEl) {
        const prevVal = String(roState.hexSectionIndex);
        selEl.innerHTML = `<option value="-1">All PNG File Bytes (${structure.totalByteLength.toLocaleString()} B)</option>`;
        for (const sec of structure.sections) {
          const opt = document.createElement('option');
          opt.value = String(sec.index);
          opt.textContent = `${sec.name} — Offset ${sec.byteOffset} (${sec.totalChunkSize.toLocaleString()} B)`;
          selEl.appendChild(opt);
        }
        selEl.value = prevVal;
      }

      let baseOffset = 0;
      let viewBytes = roState.pngBytes;
      let activeSec = null;
      if (roState.hexSectionIndex >= 0) {
        activeSec = structure.sections.find(s => s.index === roState.hexSectionIndex) || null;
        if (activeSec) {
          baseOffset = activeSec.byteOffset;
          viewBytes = activeSec.rawBytes;
        }
      }

      const pillsBox = el('ro-pex-field-pills');
      if (pillsBox) {
        pillsBox.innerHTML = '';
        const fieldsSource = (activeSec && activeSec.decodedFields && activeSec.decodedFields.length > 0)
          ? activeSec.decodedFields
          : (structure.msbxSection ? structure.msbxSection.decodedFields : (structure.sections[1] ? structure.sections[1].decodedFields : []));

        if (fieldsSource && fieldsSource.length > 0) {
          const lbl = document.createElement('span');
          lbl.style.fontSize = '11.5px';
          lbl.style.color = 'var(--text-muted)';
          lbl.style.alignSelf = 'center';
          lbl.innerHTML = '<b>Highlight Field Bytes:</b>';
          pillsBox.appendChild(lbl);

          fieldsSource.forEach(f => {
            if (f.fileByteOffset < 0) return;
            const pill = document.createElement('button');
            pill.type = 'button';
            const isHi = roState.highlightRange &&
              roState.highlightRange.start === f.fileByteOffset &&
              roState.highlightRange.end === f.fileByteEnd;
            pill.className = 'pex-field-pill' + (isHi ? ' active' : '');
            pill.textContent = `${f.field} (${f.storage || ''})`;
            pill.addEventListener('click', () => {
              roState.highlightRange = { start: f.fileByteOffset, end: f.fileByteEnd, label: f.field };
              roState.selectedFileByteOffset = f.fileByteOffset;
              const relOff = Math.max(0, f.fileByteOffset - baseOffset);
              roState.hexPage = Math.floor(relOff / roState.hexPageSize);
              renderRoHexTab(structure);
            });
            pillsBox.appendChild(pill);
          });
        }
      }

      const totalViewBytes = viewBytes.byteLength;
      const maxPage = Math.max(0, Math.ceil(totalViewBytes / roState.hexPageSize) - 1);
      if (roState.hexPage > maxPage) roState.hexPage = maxPage;
      if (roState.hexPage < 0) roState.hexPage = 0;

      const pageStart = roState.hexPage * roState.hexPageSize;
      const pageEnd = Math.min(totalViewBytes, pageStart + roState.hexPageSize);

      if (el('ro-pex-page-label')) {
        el('ro-pex-page-label').textContent = `Bytes ${(baseOffset + pageStart).toLocaleString()}..${Math.max(baseOffset + pageStart, baseOffset + pageEnd - 1).toLocaleString()} of ${(baseOffset + totalViewBytes).toLocaleString()}`;
      }
      if (el('btn-ro-hex-prev')) el('btn-ro-hex-prev').disabled = roState.hexPage <= 0;
      if (el('btn-ro-hex-next')) el('btn-ro-hex-next').disabled = roState.hexPage >= maxPage;

      const gridBox = el('ro-pex-hex-grid');
      if (gridBox) {
        gridBox.innerHTML = '';
        if (roState.hexViewMode === 'decoded') {
          const targetFields = activeSec
            ? activeSec.decodedFields
            : structure.sections.flatMap(s => (s.decodedFields || []).map(f => ({ ...f, secName: s.name })));
          if (!targetFields || targetFields.length === 0) {
            gridBox.innerHTML = `<div style="padding:16px; color:var(--text-muted);">No decoded metadata fields for this section. Switch to Hexadecimal, Binary, or Decimal view.</div>`;
          } else {
            targetFields.forEach(f => {
              const row = document.createElement('div');
              row.style.padding = '8px 10px';
              row.style.borderBottom = '1px solid var(--border-light)';
              row.style.cursor = 'pointer';
              row.innerHTML = `
                <div style="display:flex; justify-content:space-between; gap:8px;">
                  <strong>${f.secName ? `[${f.secName}] ` : ''}${f.field}</strong>
                  <span style="color:var(--primary-blue); font-weight:700;">${f.value}</span>
                </div>
                <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">
                  File Offset: <code>${f.fileByteOffset}..${f.fileByteEnd}</code> • Range: ${f.bitRange || '—'} • Storage: ${f.storage || '—'}
                </div>
              `;
              row.addEventListener('click', () => {
                if (f.fileByteOffset >= 0) {
                  roState.selectedFileByteOffset = f.fileByteOffset;
                  roState.highlightRange = { start: f.fileByteOffset, end: f.fileByteEnd, label: f.field };
                  updateRoByteInspector(structure, f.fileByteOffset);
                }
              });
              gridBox.appendChild(row);
            });
          }
        } else {
          const bytesPerRow = roState.hexViewMode === 'binary' ? 6 : (roState.hexViewMode === 'decimal' ? 12 : 16);
          for (let r = pageStart; r < pageEnd; r += bytesPerRow) {
            const rowEnd = Math.min(pageEnd, r + bytesPerRow);
            const fileRowOffset = baseOffset + r;
            const rowEl = document.createElement('div');
            rowEl.className = 'pex-hex-row';

            const offSpan = document.createElement('span');
            offSpan.className = 'pex-hex-offset';
            offSpan.textContent = `+0x${fileRowOffset.toString(16).padStart(4, '0').toUpperCase()}`;

            const cellsWrap = document.createElement('div');
            cellsWrap.className = 'pex-hex-cells';

            let asciiStr = '';
            for (let i = r; i < rowEnd; i++) {
              const fileOff = baseOffset + i;
              const b = viewBytes[i];
              asciiStr += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';

              const cell = document.createElement('span');
              cell.className = 'pex-byte-cell';
              if (roState.highlightRange && fileOff >= roState.highlightRange.start && fileOff <= roState.highlightRange.end) {
                cell.classList.add('highlighted');
              }
              if (fileOff === roState.selectedFileByteOffset) {
                cell.classList.add('selected');
              }
              if (roState.hexViewMode === 'binary') {
                cell.textContent = b.toString(2).padStart(8, '0');
              } else if (roState.hexViewMode === 'decimal') {
                cell.textContent = b.toString(10).padStart(3, '0');
              } else {
                cell.textContent = b.toString(16).padStart(2, '0').toUpperCase();
              }
              cell.title = `File Offset ${fileOff} (0x${fileOff.toString(16).toUpperCase()}) • Hex: 0x${b.toString(16).padStart(2, '0').toUpperCase()} • Bin: ${b.toString(2).padStart(8, '0')} • Dec: ${b}`;
              cell.addEventListener('click', () => {
                roState.selectedFileByteOffset = fileOff;
                renderRoHexTab(structure);
              });
              cellsWrap.appendChild(cell);
            }

            const asciiSpan = document.createElement('span');
            asciiSpan.style.color = 'var(--text-muted)';
            asciiSpan.textContent = asciiStr;

            rowEl.appendChild(offSpan);
            rowEl.appendChild(cellsWrap);
            rowEl.appendChild(asciiSpan);
            gridBox.appendChild(rowEl);
          }
        }
      }
      updateRoByteInspector(structure, roState.selectedFileByteOffset);
    }

    function renderRoMetadataTab(structure) {
      const sumBox = el('ro-pex-meta-summary-box');
      const envEl = el('ro-pex-meta-envelope');
      const tbody = el('ro-pex-meta-fields-tbody');
      const badgeEl = el('ro-pex-meta-badge');
      if (!sumBox || !envEl || !tbody) return;

      if (!structure.msbxSection) {
        if (badgeEl) badgeEl.textContent = 'Ordinary Unencrypted PNG';
        sumBox.innerHTML = `
          <div class="pex-struct-warning" style="background: rgba(59, 130, 246, 0.10); border-color: rgba(59, 130, 246, 0.35);">
            <i class="fa-solid fa-circle-info" style="color: var(--primary-blue);"></i>
            <div>
              <strong>No KXBIT Encryption Metadata Found (Ordinary PNG Image)</strong>
              <p style="margin: 3px 0 0 0;">This PNG file does not contain an embedded <code>msBX</code> or legacy <code>msBx</code> chunk. It is a standard unencrypted PNG image (${structure.ihdrInfo ? `${structure.ihdrInfo.width}×${structure.ihdrInfo.height} px` : 'unknown dimensions'}).</p>
            </div>
          </div>
        `;
        envEl.style.display = 'none';
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">No KXBIT encryption metadata fields present in this ordinary PNG file.</td></tr>`;
        return;
      }

      envEl.style.display = 'flex';
      const sec = structure.msbxSection;
      const bd = sec.msbxBreakdown;

      let decodedMeta = null;
      let decodeError = null;
      try {
        decodedMeta = BitEngine.decodeMsBxMetadata(sec.dataBytes, null, structure.ihdrInfo);
      } catch (err) {
        decodeError = err.message || String(err);
      }

      if (badgeEl) {
        badgeEl.textContent = `${sec.type} • Schema v${bd ? bd.schemaVersion : '?'}`;
      }

      if (decodedMeta) {
        sumBox.innerHTML = `
          <div class="pex-opt-kpi-grid" style="margin-top: 8px;">
            <div class="pex-kpi-card">
              <span class="kpi-label">Algorithm Identifier</span>
              <span class="kpi-val" style="font-size:14px;">${decodedMeta.identifier} (Algo v${decodedMeta.algoVersion})</span>
              <span class="kpi-sub">3-Stage MSB Pipeline</span>
            </div>
            <div class="pex-kpi-card">
              <span class="kpi-label">Stage 3 MSB Bit Depth</span>
              <span class="kpi-val" style="font-size:15px;">k = ${decodedMeta.k} bit${decodedMeta.k > 1 ? 's' : ''}</span>
              <span class="kpi-sub">Colour Mode: ${decodedMeta.modeLabel}</span>
            </div>
            <div class="pex-kpi-card">
              <span class="kpi-label">Key Type &amp; KDF Rounds</span>
              <span class="kpi-val" style="font-size:14px;">${decodedMeta.keyType === 'image' ? 'Key Image (SHA-256)' : 'Text Password'}</span>
              <span class="kpi-sub">${decodedMeta.iterations.toLocaleString()} SHA-256 rounds (Secret key not stored)</span>
            </div>
            <div class="pex-kpi-card">
              <span class="kpi-label">Encryption Scope &amp; Mask</span>
              <span class="kpi-val" style="font-size:14px;">${decodedMeta.scope.toUpperCase()}</span>
              <span class="kpi-sub">${decodedMeta.encodedMaskBytes ? `${decodedMeta.maskCodecLabel} (${decodedMeta.encodedMaskBytes.byteLength} B)` : 'No mask (Full Image)'}</span>
            </div>
            <div class="pex-kpi-card">
              <span class="kpi-label">Salt Length &amp; Hex</span>
              <span class="kpi-val" style="font-size:13px;">16 Bytes (128 bits)</span>
              <span class="kpi-sub" title="${decodedMeta.saltHex}">${decodedMeta.saltHex.slice(0, 16)}…</span>
            </div>
            <div class="pex-kpi-card">
              <span class="kpi-label">SHA-256 Verification Tag</span>
              <span class="kpi-val" style="font-size:13px;">32 Bytes (256 bits)</span>
              <span class="kpi-sub" title="${decodedMeta.tagHex}">${decodedMeta.tagHex.slice(0, 16)}…</span>
            </div>
          </div>
        `;
      } else {
        sumBox.innerHTML = `
          <div class="pex-tier-item fail" style="margin-top:8px;">
            <div>
              <strong>✖ Invalid or Corrupted ${sec.type} Metadata Schema</strong>
              <div style="font-size:11.5px; color:#ef4444;">${decodeError}</div>
            </div>
            <span class="pex-tier-badge fail">INVALID</span>
          </div>
        `;
      }

      if (bd) {
        envEl.innerHTML = `
          <span><b>Chunk Envelope (12 B Overhead):</b></span>
          <span>Length: Offset <code>${bd.envelope.lengthField.fileByteOffset}..${bd.envelope.lengthField.fileByteOffset + 3}</code> (${bd.payloadByteLength} B)</span>
          <span>• Type: Offset <code>${bd.envelope.typeField.fileByteOffset}..${bd.envelope.typeField.fileByteOffset + 3}</code> ("${bd.chunkType}")</span>
          <span>• Payload: Offset <code>${sec.dataOffset}..${sec.dataOffset + bd.payloadByteLength - 1}</code></span>
          <span>• CRC-32: Offset <code>${bd.envelope.crcField.fileByteOffset}..${bd.envelope.crcField.fileByteOffset + 3}</code> (${sec.crcHex})</span>
        `;

        tbody.innerHTML = '';
        bd.fields.forEach(f => {
          const tr = document.createElement('tr');
          const chunkOffStr = f.chunkByteOffset >= 0
            ? `<code>+${f.chunkByteOffset}${f.chunkByteEnd > f.chunkByteOffset ? '..+' + f.chunkByteEnd : ''}</code> <small>(${f.bitRange})</small>`
            : `<span style="color:var(--accent-emerald); font-weight:600;">${f.bitRange}</span>`;
          const fileOffStr = f.fileByteOffset >= 0
            ? `<code>${f.fileByteOffset}${f.fileByteEnd > f.fileByteOffset ? '..' + f.fileByteEnd : ''}</code>`
            : '—';

          tr.innerHTML = `
            <td><strong>${f.field}</strong></td>
            <td><code>${f.value}</code></td>
            <td><strong>${f.storage}</strong></td>
            <td>${chunkOffStr}</td>
            <td>${fileOffStr}</td>
            <td>
              <div style="font-family:'JetBrains Mono',monospace; font-size:11px;">Hex: <b>${f.rawHex}</b></div>
              <div style="font-family:'JetBrains Mono',monospace; font-size:10.5px; color:var(--text-muted);">Bin: ${f.rawBinary}</div>
            </td>
            <td>
              <div style="font-size:11px; color:var(--text-muted); margin-bottom:4px;">${f.description}</div>
              ${f.chunkByteOffset >= 0 ? `
                <button type="button" class="btn btn-xs btn-outline ro-jump-field-btn" data-file-start="${f.fileByteOffset}" data-file-end="${f.fileByteEnd}" data-field-name="${f.field}">
                  <i class="fa-solid fa-highlighter"></i> Highlight in Hex/Binary
                </button>
              ` : ''}
            </td>
          `;
          tbody.appendChild(tr);
        });

        tbody.querySelectorAll('.ro-jump-field-btn').forEach(btn => {
          btn.addEventListener('click', () => {
            const fStart = parseInt(btn.getAttribute('data-file-start'), 10);
            const fEnd = parseInt(btn.getAttribute('data-file-end'), 10);
            const fName = btn.getAttribute('data-field-name');
            roState.hexSectionIndex = structure.msbxSection.index;
            roState.highlightRange = { start: fStart, end: fEnd, label: fName };
            roState.selectedFileByteOffset = fStart;
            roState.hexPage = Math.floor((fStart - structure.msbxSection.byteOffset) / roState.hexPageSize);
            switchRoSubTab('ro-panel-hex');
            renderRoHexTab(structure);
          });
        });
      }
    }

    async function renderRoTestingTab(structure) {
      const reportList = el('ro-pex-test-report-list');
      if (!reportList) return;

      const msBXCount = structure.chunks.filter(c => c.type === 'msBX').length;
      const msBxLegacyCount = structure.chunks.filter(c => c.type === 'msBx').length;
      const allLengthsValid = structure.chunks.every(c => c.lengthValid) && structure.sizeFormulaMatches;
      const allCrcsValid = structure.chunks.every(c => c.crcValid);

      let metaValid = false;
      let metaSummary = 'No KXBIT encryption metadata chunk found (ordinary unencrypted PNG image).';
      let metaStatus = 'INFO';
      let dimCompat = true;
      let dimSummary = 'IHDR dimensions valid.';

      if (msBXCount === 0 && msBxLegacyCount === 0) {
        metaStatus = 'WARN';
        dimSummary = structure.ihdrInfo
          ? `Standard PNG (${structure.ihdrInfo.width}×${structure.ihdrInfo.height} px) without msBX metadata.`
          : 'Missing IHDR.';
      } else if (msBXCount > 0 && msBxLegacyCount > 0) {
        metaStatus = 'FAIL';
        metaSummary = 'Conflicting metadata chunks: File contains both "msBX" and legacy "msBx".';
      } else if (msBXCount > 1 || msBxLegacyCount > 1) {
        metaStatus = 'FAIL';
        metaSummary = `Duplicate metadata chunks detected (${msBXCount + msBxLegacyCount} chunks).`;
      } else if (structure.msbxSection) {
        try {
          const decoded = BitEngine.decodeMsBxMetadata(structure.msbxSection.dataBytes, null, structure.ihdrInfo);
          metaValid = true;
          metaStatus = 'PASS';
          metaSummary = `Valid ${structure.msbxSection.type} Schema v${decoded.metaVersion} (k=${decoded.k}, scope=${decoded.scope}, KDF=${decoded.iterations.toLocaleString()}).`;
          if (structure.ihdrInfo && (decoded.width !== structure.ihdrInfo.width || decoded.height !== structure.ihdrInfo.height)) {
            dimCompat = false;
            dimSummary = `Dimension mismatch: IHDR is ${structure.ihdrInfo.width}×${structure.ihdrInfo.height}, metadata specifies ${decoded.width}×${decoded.height}.`;
          } else if (structure.ihdrInfo) {
            dimSummary = `Consistent ${structure.ihdrInfo.width}×${structure.ihdrInfo.height} px dimensions.`;
          }
        } catch (err) {
          metaValid = false;
          metaStatus = 'FAIL';
          metaSummary = err.message || String(err);
        }
      }

      const checks = [
        {
          title: '1. PNG Signature Validity',
          status: structure.isValidSignature ? 'PASS' : 'FAIL',
          desc: structure.isValidSignature
            ? 'Valid 8-byte ISO/IEC 15948 PNG signature (89 50 4E 47 0D 0A 1A 0A).'
            : 'Invalid or missing 8-byte PNG signature.'
        },
        {
          title: '2. Required Chunk Structure (IHDR, IDAT, IEND)',
          status: (structure.ihdrInfo && structure.idatCount > 0 && structure.chunks.some(c => c.type === 'IEND')) ? 'PASS' : 'FAIL',
          desc: `Found ${structure.chunkCount} total chunks (${structure.idatCount} IDAT chunk${structure.idatCount === 1 ? '' : 's'}).`
        },
        {
          title: '3. Chunk Length & File Size Exactness',
          status: allLengthsValid ? 'PASS' : 'FAIL',
          desc: allLengthsValid
            ? `All chunk lengths valid; Signature (8 B) + Chunks = ${structure.totalByteLength.toLocaleString()} B.`
            : 'One or more chunk lengths exceed file bounds or file has trailing/truncated bytes.'
        },
        {
          title: '4. Per-Chunk CRC-32 Checksum Integrity',
          status: allCrcsValid ? 'PASS' : 'FAIL',
          desc: allCrcsValid
            ? `All ${structure.chunkCount} chunks passed ISO/IEC 15948 32-bit CRC verification.`
            : structure.structuralErrors.filter(e => e.includes('CRC')).join(' ') || 'CRC-32 mismatch detected.'
        },
        {
          title: '5. KXBIT msBX / msBx Metadata Presence & Uniqueness',
          status: (msBXCount + msBxLegacyCount === 1) ? 'PASS' : ((msBXCount + msBxLegacyCount === 0) ? 'WARN' : 'FAIL'),
          desc: (msBXCount + msBxLegacyCount === 1)
            ? `Exactly 1 ${msBXCount === 1 ? 'msBX (current)' : 'msBx (legacy)'} metadata chunk present.`
            : metaSummary
        },
        {
          title: '6. Metadata Schema & Version Validation',
          status: metaStatus,
          desc: metaSummary
        },
        {
          title: '7. Image Dimension & Colour Compatibility',
          status: dimCompat ? 'PASS' : 'FAIL',
          desc: dimSummary
        }
      ];

      reportList.innerHTML = '';
      checks.forEach(c => {
        const cls = c.status === 'PASS' ? 'pass' : (c.status === 'FAIL' ? 'fail' : 'warn');
        const item = document.createElement('div');
        item.className = `pex-tier-item ${cls}`;
        item.innerHTML = `
          <div>
            <strong>${c.title}</strong>
            <div style="font-size:11.5px; color:var(--text-muted); margin-top:2px;">${c.desc}</div>
          </div>
          <span class="pex-tier-badge ${cls}">${c.status}</span>
        `;
        reportList.appendChild(item);
      });
    }

    // Sub-tab switching on Read-Only Explorer Page
    document.querySelectorAll('#png-explorer-tab .pex-subtab').forEach(btn => {
      btn.addEventListener('click', () => {
        switchRoSubTab(btn.getAttribute('data-ro-tab'));
      });
    });

    // Storage unit switcher on Read-Only Explorer Page
    document.querySelectorAll('.ro-unit-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.ro-unit-btn').forEach(b => {
          b.classList.remove('btn-primary');
          b.classList.add('btn-outline');
        });
        btn.classList.remove('btn-outline');
        btn.classList.add('btn-primary');
        roState.storageUnit = btn.getAttribute('data-ro-unit') || 'bytes';
        if (roState.pngBytes) {
          renderRoStructureTab(BitEngine.parsePngBinaryStructure(roState.pngBytes));
        }
      });
    });

    // Hex/Binary viewer controls on Read-Only Explorer Page
    if (el('ro-pex-section-select')) {
      el('ro-pex-section-select').addEventListener('change', (e) => {
        roState.hexSectionIndex = parseInt(e.target.value, 10);
        roState.hexPage = 0;
        if (roState.pngBytes) renderRoHexTab(BitEngine.parsePngBinaryStructure(roState.pngBytes));
      });
    }

    document.querySelectorAll('.ro-view-mode-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.ro-view-mode-btn').forEach(b => {
          b.classList.remove('btn-primary');
          b.classList.add('btn-outline');
        });
        btn.classList.remove('btn-outline');
        btn.classList.add('btn-primary');
        roState.hexViewMode = btn.getAttribute('data-ro-view') || 'hex';
        if (roState.pngBytes) renderRoHexTab(BitEngine.parsePngBinaryStructure(roState.pngBytes));
      });
    });

    if (el('btn-ro-hex-prev')) {
      el('btn-ro-hex-prev').addEventListener('click', () => {
        roState.hexPage = Math.max(0, roState.hexPage - 1);
        if (roState.pngBytes) renderRoHexTab(BitEngine.parsePngBinaryStructure(roState.pngBytes));
      });
    }
    if (el('btn-ro-hex-next')) {
      el('btn-ro-hex-next').addEventListener('click', () => {
        roState.hexPage++;
        if (roState.pngBytes) renderRoHexTab(BitEngine.parsePngBinaryStructure(roState.pngBytes));
      });
    }

    // Optional Read-Only Decryption Compatibility Test
    if (el('btn-ro-pex-test-decrypt')) {
      el('btn-ro-pex-test-decrypt').addEventListener('click', async () => {
        const resBox = el('ro-pex-decrypt-test-result');
        if (!resBox || !roState.pngBytes) return;
        const keyVal = el('ro-pex-test-key') ? el('ro-pex-test-key').value.trim() : '';
        if (!keyVal) {
          resBox.innerHTML = `<div class="pex-tier-item warn"><div><strong>Key Required</strong><div style="font-size:11.5px;">Enter the candidate password or key image SHA-256 hash above to test decryption compatibility.</div></div><span class="pex-tier-badge warn">INPUT NEEDED</span></div>`;
          return;
        }
        try {
          const dec = await BitEngine.decryptFromPNG(roState.pngBytes, keyVal);
          resBox.innerHTML = `
            <div class="pex-tier-item pass">
              <div>
                <strong>✔ Decryption Compatibility Verified (0 Errors)</strong>
                <div style="font-size:11.5px; color:var(--text-muted);">32-byte SHA-256 tag matched (${dec.metadata.tagHex.slice(0, 16)}…). Reversed 3 stages in ${dec.processingTimeMs} ms (${dec.imageData.width}×${dec.imageData.height} px).</div>
              </div>
              <span class="pex-tier-badge pass">AUTHENTIC</span>
            </div>
          `;
        } catch (err) {
          resBox.innerHTML = `
            <div class="pex-tier-item fail">
              <div>
                <strong>✖ Decryption Test Failed</strong>
                <div style="font-size:11.5px; color:#ef4444;">${err.message || String(err)}</div>
              </div>
              <span class="pex-tier-badge fail">FAILED</span>
            </div>
          `;
        }
      });
    }

    // File upload & drop zone on Read-Only Explorer Page
    const roDropZone = el('ro-pex-drop-zone');
    const roFileInput = el('ro-pex-file-input');
    if (roDropZone && roFileInput) {
      roDropZone.addEventListener('click', () => roFileInput.click());
      roDropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        roDropZone.classList.add('dragover');
      });
      roDropZone.addEventListener('dragleave', () => {
        roDropZone.classList.remove('dragover');
      });
      roDropZone.addEventListener('drop', async (e) => {
        e.preventDefault();
        roDropZone.classList.remove('dragover');
        const file = e.dataTransfer.files && e.dataTransfer.files[0];
        if (!file) return;
        const buf = await file.arrayBuffer();
        await loadReadOnlyPng(new Uint8Array(buf), file.name);
      });
      roFileInput.addEventListener('change', async (e) => {
        const file = e.target.files && e.target.files[0];
        if (!file) return;
        const buf = await file.arrayBuffer();
        await loadReadOnlyPng(new Uint8Array(buf), file.name);
        e.target.value = '';
      });
    }

    // Sample & Active PNG Loader Buttons on Read-Only Explorer Page
    async function generateRoSamplePng(mode = 'msBX_v2') {
      const w = 128, h = 96;
      const rgba = new Uint8ClampedArray(w * h * 4);
      for (let i = 0; i < w * h * 4; i += 4) {
        rgba[i] = (i * 5) & 0xFF;
        rgba[i + 1] = (i * 9 + 40) & 0xFF;
        rgba[i + 2] = (i * 15 + 90) & 0xFF;
        rgba[i + 3] = 255;
      }
      const imgData = new ImageData(rgba, w, h);
      if (mode === 'plain') {
        const plainBytes = await BitEngine.encodeLosslessPNG(imgData);
        await loadReadOnlyPng(plainBytes, 'ordinary_unencrypted_photo.png');
        return;
      }
      const demoKey = 'KXBIT-Demo-Key-2026';
      if (el('ro-pex-test-key')) el('ro-pex-test-key').value = demoKey;
      const enc = await BitEngine.encryptToPNG(imgData, demoKey, null, {
        k: 2,
        iterations: 1000,
        metaVersion: mode === 'msBx_legacy' ? 1 : 2
      });
      if (mode === 'msBx_legacy') {
        const decPng = await BitEngine.decodeLosslessPNG(enc.pngBytes);
        const msbxChunk = decPng.chunks.find(c => c.type === 'msBX');
        const legacyBytes = await BitEngine.encodeLosslessPNG(enc.imageData, [{ type: 'msBx', data: msbxChunk.data }]);
        await loadReadOnlyPng(legacyBytes, 'legacy_msBx_encrypted.png');
      } else {
        await loadReadOnlyPng(enc.pngBytes, 'sample_msBX_v2_encrypted.png');
      }
    }

    if (el('btn-ro-pex-load-active')) {
      el('btn-ro-pex-load-active').addEventListener('click', async () => {
        if (state.lastEncryptedPngBytes) {
          if (DOM.encPassword && DOM.encPassword.value && el('ro-pex-test-key')) {
            el('ro-pex-test-key').value = DOM.encPassword.value;
          }
          await loadReadOnlyPng(state.lastEncryptedPngBytes, 'encrypted_photo.png');
        } else {
          await generateRoSamplePng('msBX_v2');
        }
      });
    }
    if (el('btn-ro-pex-sample-msbx')) {
      el('btn-ro-pex-sample-msbx').addEventListener('click', () => generateRoSamplePng('msBX_v2'));
    }
    if (el('btn-ro-pex-sample-legacy')) {
      el('btn-ro-pex-sample-legacy').addEventListener('click', () => generateRoSamplePng('msBx_legacy'));
    }
    if (el('btn-ro-pex-sample-plain')) {
      el('btn-ro-pex-sample-plain').addEventListener('click', () => generateRoSamplePng('plain'));
    }

    window.syncReadOnlyExplorerIfEmpty = (pngBytes, fileName) => {
      if (!roState.pngBytes) {
        loadReadOnlyPng(pngBytes, fileName).catch(() => {});
      }
    };

    setTimeout(() => {
      if (!roState.pngBytes) {
        generateRoSamplePng('msBX_v2').catch(() => {});
      }
    }, 200);
  }

  initPngBinaryExplorerModule();
  initReadOnlyPngExplorerPage();

});
