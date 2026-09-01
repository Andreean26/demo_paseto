'use strict';

const nameForm = document.querySelector('#nameForm');
const nameInput = document.querySelector('#nameInput');
const tokenBox = document.querySelector('#tokenBox');
const modeLabel = document.querySelector('#modeLabel');
const roleLabel = document.querySelector('#roleLabel');
const resultPanel = document.querySelector('#resultPanel');
const resultText = document.querySelector('#resultText');
const accessButton = document.querySelector('#accessButton');
const copyButton = document.querySelector('#copyButton');
const forgeButton = document.querySelector('#forgeButton');
const tamperButton = document.querySelector('#tamperButton');
const tokenHint = document.querySelector('#tokenHint');
const decodeButton = document.querySelector('#decodeButton');
const decoderSummary = document.querySelector('#decoderSummary');
const decoderDetails = document.querySelector('#decoderDetails');
const decoderHeaderLabel = document.querySelector('#decoderHeaderLabel');
const decoderPayloadLabel = document.querySelector('#decoderPayloadLabel');
const decoderSignatureLabel = document.querySelector('#decoderSignatureLabel');
const decoderHeader = document.querySelector('#decoderHeader');
const decoderPayload = document.querySelector('#decoderPayload');
const decoderSignature = document.querySelector('#decoderSignature');
const pasetoFormatContainer = document.querySelector('#pasetoFormatContainer');
const formatCards = document.querySelectorAll('.format-card');
const pasetoFormatInputs = document.querySelectorAll('input[name="pasetoFormat"]');

let currentName = '';
let currentMode = null;
let tokenRequestId = 0;
let decoderActive = false;

function setResult(text, kind) {
  resultText.textContent = text;
  resultPanel.classList.remove('success', 'error');
  if (kind) {
    resultPanel.classList.add(kind);
  }
}

function getSelectedPasetoFormat() {
  const checked = document.querySelector('input[name="pasetoFormat"]:checked');
  return checked ? checked.value : 'v4.public';
}

function updatePasetoFormatCards() {
  const currentVal = getSelectedPasetoFormat();
  formatCards.forEach((card) => {
    const radio = card.querySelector('input[type="radio"]');
    if (radio && radio.value === currentVal) {
      card.classList.add('active');
    } else {
      card.classList.remove('active');
    }
  });
}

function setModeText(mode) {
  const secure = mode === 'paseto';
  modeLabel.textContent = secure ? 'PASETO Secure' : 'JWT Vulnerable';
  tamperButton.hidden = !secure;
  forgeButton.hidden = secure;
  if (pasetoFormatContainer) {
    pasetoFormatContainer.hidden = !secure;
  }

  if (secure) {
    const format = getSelectedPasetoFormat();
    if (format === 'v4.local') {
      tokenHint.textContent =
        'Token PASETO memakai library standar (v4.local / AEAD XChaCha20-Poly1305) dan payload-nya terenkripsi penuh. Coba rusak satu karakter, lalu akses brankas.';
    } else if (format === 'v3.local') {
      tokenHint.textContent =
        'Token PASETO memakai library standar (v3.local / AEAD AES-256-CTR) dan payload-nya terenkripsi penuh. Coba rusak satu karakter, lalu akses brankas.';
    } else if (format === 'v3.public') {
      tokenHint.textContent =
        'Token PASETO memakai library standar (v3.public / NIST ECDSA). Payload terbaca, ditandatangani digital signature. Coba rusak satu karakter, lalu akses brankas.';
    } else {
      tokenHint.textContent =
        'Token PASETO memakai library standar (v4.public / Ed25519). Payload terbaca, ditandatangani digital signature. Coba rusak satu karakter, lalu akses brankas.';
    }
  } else {
    tokenHint.textContent =
      'Token JWT dibuat dengan library standar jsonwebtoken. Coba Forge JWT ADMIN, lalu akses brankas.';
  }
}

function getParticipantName() {
  currentName = nameInput.value.trim();
  if (!currentName) {
    currentName = 'Peserta Demo';
    nameInput.value = currentName;
  }
  return currentName;
}

function toBase64UrlJson(value) {
  const json = JSON.stringify(value);
  const utf8 = encodeURIComponent(json).replace(/%([0-9A-F]{2})/g, (_, code) =>
    String.fromCharCode(Number.parseInt(code, 16))
  );
  return btoa(utf8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function setDecoderSummary(text, kind) {
  decoderSummary.textContent = text;
  decoderSummary.classList.remove('secure', 'warning', 'error');
  if (kind) {
    decoderSummary.classList.add(kind);
  }
}

function showDecoderDetails({ headerLabel, header, payloadLabel, payload, signatureLabel, signature }) {
  decoderHeaderLabel.textContent = headerLabel;
  decoderPayloadLabel.textContent = payloadLabel;
  decoderSignatureLabel.textContent = signatureLabel;
  decoderHeader.textContent = header;
  decoderPayload.textContent = payload;
  decoderSignature.textContent = signature;
  decoderDetails.hidden = false;
}

function decodeBase64UrlBytes(value) {
  if (!value || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('Segmen token bukan base64url yang valid.');
  }

  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  let binary;
  try {
    binary = atob(padded);
  } catch {
    throw new Error('Segmen token tidak dapat dibaca.');
  }
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function decodeBase64UrlJson(value, partName) {
  const text = new TextDecoder().decode(decodeBase64UrlBytes(value));
  try {
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('not-object');
    }
    return parsed;
  } catch {
    throw new Error(`${partName} token harus berupa objek JSON yang valid.`);
  }
}

// ===== JWT: struktur header dan payload dapat dibaca langsung di browser =====
function inspectJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3 || !parts[0] || !parts[1]) {
    throw new Error('JWT harus memiliki tiga segmen: header, payload, dan signature.');
  }

  const header = decodeBase64UrlJson(parts[0], 'Header');
  const payload = decodeBase64UrlJson(parts[1], 'Payload');
  const algorithm = String(header.alg || 'tidak diketahui');
  const role = String(payload.role || 'tidak diketahui');
  const forged = algorithm.toLowerCase() === 'none' && role.toUpperCase() === 'ADMIN';

  showDecoderDetails({
    headerLabel: 'Header JWT',
    header: JSON.stringify(header, null, 2),
    payloadLabel: 'Payload JWT',
    payload: JSON.stringify(payload, null, 2),
    signatureLabel: 'Signature JWT',
    signature: parts[2] || '(kosong — token ini tidak memiliki signature)'
  });

  if (forged) {
    setDecoderSummary(
      'Hasil forge terlihat: algoritma menjadi none, role menjadi ADMIN, dan signature kosong.',
      'warning'
    );
    return;
  }

  setDecoderSummary(
    `Isi token saat ini: algoritma ${algorithm} dan role ${role}. JWT dapat dibaca tanpa mengetahui secret.`,
    null
  );
}

// ===== PASETO: parser terenkripsi (local) dan tanda tangan publik (public) =====
function isPasetoToken(token) {
  return /^v[1-4]\.(local|public)\./i.test(token);
}

function inspectSecureToken(token) {
  const match = token.match(/^(v[1-4])\.(local|public)\.([A-Za-z0-9_-]+)(?:\.([A-Za-z0-9_-]+))?$/i);
  if (!match) {
    throw new Error('Format token PASETO tidak valid.');
  }
  const version = match[1].toLowerCase();
  const purpose = match[2].toLowerCase();
  const body = match[3];
  const packed = decodeBase64UrlBytes(body);

  if (purpose === 'local') {
    const cipherName =
      version === 'v4'
        ? 'XChaCha20-Poly1305 + BLAKE2b'
        : 'AES-256-CTR + HMAC-SHA384';
    showDecoderDetails({
      headerLabel: 'Header PASETO',
      header: `${version}.${purpose}`,
      payloadLabel: 'Payload Terenkripsi (AEAD)',
      payload: JSON.stringify(
        {
          version,
          purpose: `local (Symmetric AEAD ${cipherName})`,
          status: 'opaque / terenkripsi (tidak dapat dibaca tanpa symmetric key)',
          encodedLength: body.length,
          binaryBytes: packed.length
        },
        null,
        2
      ),
      signatureLabel: 'Autentikasi & Integritas',
      signature: `Nonce, Ciphertext, dan AEAD Authentication Tag (${version === 'v4' ? 'BLAKE2b 32-byte' : 'HMAC-SHA384 48-byte'}) dikemas bersama. Perubahan 1 bit akan langsung membatalkan token.`
    });
    setDecoderSummary(
      `Berbeda dari JWT, payload PASETO ${version}.local terenkripsi sepenuhnya (${cipherName}). Penyerang tidak bisa membaca ataupun memodifikasi data.`,
      'secure'
    );
  } else {
    // PUBLIC PURPOSE (Asymmetric Signature)
    // Signature length:
    // v4 / v2: 64 bytes (Ed25519)
    // v3: 96 bytes (ECDSA P-384 IEEE P1363)
    // v1: 256 bytes (RSA 2048)
    let sigLen = 64;
    let cryptoAlg = 'Ed25519 (EdDSA)';
    if (version === 'v3') {
      sigLen = 96;
      cryptoAlg = 'ECDSA (P-384 / SHA-384)';
    } else if (version === 'v1') {
      sigLen = 256;
      cryptoAlg = 'RSA-PSS / SHA-384';
    }

    if (packed.length <= sigLen) {
      throw new Error(`Token PASETO public terlalu pendek (${packed.length} bytes, minimum ${sigLen + 1} bytes).`);
    }

    const payloadBytes = packed.subarray(0, packed.length - sigLen);
    const signatureBytes = packed.subarray(packed.length - sigLen);
    const payloadText = new TextDecoder().decode(payloadBytes);

    let parsedPayload;
    try {
      parsedPayload = JSON.parse(payloadText);
    } catch {
      parsedPayload = payloadText;
    }

    const sigHex = Array.from(signatureBytes, (b) => b.toString(16).padStart(2, '0')).join('');
    const formattedSig =
      sigHex.length > 64
        ? `${sigHex.slice(0, 32)}...\n...${sigHex.slice(-32)}`
        : sigHex;

    showDecoderDetails({
      headerLabel: 'Header PASETO',
      header: `${version}.${purpose}`,
      payloadLabel: 'Payload PASETO Public',
      payload: typeof parsedPayload === 'object' ? JSON.stringify(parsedPayload, null, 2) : parsedPayload,
      signatureLabel: `Signature Kriptografi (${cryptoAlg} - ${sigLen} bytes)`,
      signature: `${formattedSig}\n\nDitandatangani secara asimetris dengan kunci privat Ed25519/ECDSA.`
    });

    const roleName = typeof parsedPayload === 'object' && parsedPayload.role ? parsedPayload.role : 'USER';
    setDecoderSummary(
      `PASETO Public ditandatangani dengan kunci privat kriptografi modern (${cryptoAlg}). Payload (${roleName}) terbaca publik namun terlindungi tanda tangan digital.`,
      'secure'
    );
  }
}

function decodeToken() {
  decoderActive = true;
  const token = tokenBox.value.trim();
  if (!token) {
    decoderDetails.hidden = true;
    setDecoderSummary('Token masih kosong. Ambil token terlebih dahulu.', 'error');
    return;
  }

  try {
    if (isPasetoToken(token)) {
      inspectSecureToken(token);
    } else {
      inspectJwt(token);
    }
  } catch (error) {
    decoderDetails.hidden = true;
    setDecoderSummary(error.message || 'Token tidak dapat di-decode.', 'error');
  }
}

function refreshDecoder() {
  if (decoderActive) {
    decodeToken();
  }
}

async function loadState() {
  const response = await fetch('/api/state');
  const payload = await response.json();
  currentMode = payload.mode;
  setModeText(currentMode);
  updatePasetoFormatCards();
}

async function requestToken(name) {
  const requestId = ++tokenRequestId;
  const pasetoFormat = getSelectedPasetoFormat();
  const response = await fetch('/api/auth/generate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name, pasetoFormat })
  });
  const payload = await response.json();
  if (requestId !== tokenRequestId) {
    return null;
  }
  if (!payload.ok) {
    setResult(payload.error || 'Token gagal dibuat.', 'error');
    return null;
  }

  currentMode = payload.mode;
  tokenBox.value = payload.token;
  roleLabel.textContent = payload.role;
  setModeText(currentMode);
  refreshDecoder();
  return payload;
}

async function syncPresenterMode(mode) {
  const nextMode = mode === 'paseto' ? 'paseto' : 'jwt';
  if (nextMode === currentMode) {
    setModeText(nextMode);
    return;
  }

  currentMode = nextMode;
  setModeText(currentMode);
  roleLabel.textContent = 'USER';

  const name = currentName || nameInput.value.trim();
  if (!name) {
    tokenRequestId += 1;
    tokenBox.value = '';
    refreshDecoder();
    setResult(
      `Presenter mengganti mode ke ${modeLabel.textContent}. Isi nama untuk mengambil token mode aktif.`,
      null
    );
    return;
  }

  currentName = name;
  const payload = await requestToken(currentName);
  if (!payload) {
    return;
  }
  setResult(
    `Presenter mengganti mode ke ${modeLabel.textContent}. Token USER diperbarui otomatis.`,
    null
  );
}

async function generateToken(event) {
  event.preventDefault();
  const payload = await requestToken(getParticipantName());
  if (!payload) {
    return;
  }
  setResult('Token USER siap dicoba.', null);
}

async function accessVault() {
  const token = tokenBox.value.trim();
  if (!token) {
    setResult('Token masih kosong.', 'error');
    return;
  }

  const response = await fetch('/api/vault/access', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`
    }
  });
  const payload = await response.json();
  const message = payload.message || payload.error || 'Request selesai.';
  setResult(message, response.ok ? 'success' : 'error');
  if (payload.claims && payload.claims.role) {
    roleLabel.textContent = payload.claims.role;
  }
}

async function copyToken() {
  const token = tokenBox.value.trim();
  if (!token) {
    setResult('Token masih kosong.', 'error');
    return;
  }
  await navigator.clipboard.writeText(token);
  setResult('Token tersalin.', null);
}

// ===== JWT: simulasi pemalsuan role ADMIN dengan alg:none =====
function forgeJwt() {
  const name = currentName || nameInput.value.trim() || 'Audience';
  const header = { alg: 'none', typ: 'JWT' };
  const payload = {
    name,
    role: 'ADMIN',
    iat: Math.floor(Date.now() / 1000)
  };
  tokenBox.value = `${toBase64UrlJson(header)}.${toBase64UrlJson(payload)}.`;
  roleLabel.textContent = 'ADMIN';
  refreshDecoder();
  setResult('JWT palsu dibuat dengan alg:none. Kirim ke brankas saat mode JWT aktif.', null);
}

// ===== PASETO-style: simulasi perubahan token untuk menguji autentikasi AEAD & Digital Signature =====
function tamperToken() {
  const token = tokenBox.value.trim();
  if (!token) {
    setResult('Token masih kosong.', 'error');
    return;
  }
  // Rusak karakter non-padding (misal 5 karakter sebelum akhir)
  const index = Math.max(0, token.length - 5);
  const char = token[index];
  const replacement = char === 'A' ? 'B' : char === 'a' ? 'b' : 'A';
  tokenBox.value = `${token.slice(0, index)}${replacement}${token.slice(index + 1)}`;
  refreshDecoder();
  setResult('Satu karakter token diubah. Pada PASETO secure, akses harus ditolak.', null);
}

function connectEvents() {
  const stream = new EventSource('/events');

  const synchronize = (message) => {
    const payload = JSON.parse(message.data);
    syncPresenterMode(payload.mode).catch(() => {
      setResult('Mode berubah, tetapi token baru gagal dibuat.', 'error');
    });
  };

  stream.addEventListener('snapshot', synchronize);
  stream.addEventListener('mode', synchronize);
}

nameForm.addEventListener('submit', generateToken);
accessButton.addEventListener('click', accessVault);
copyButton.addEventListener('click', copyToken);
forgeButton.addEventListener('click', forgeJwt);
tamperButton.addEventListener('click', tamperToken);
decodeButton.addEventListener('click', decodeToken);
tokenBox.addEventListener('input', refreshDecoder);

pasetoFormatInputs.forEach((input) => {
  input.addEventListener('change', () => {
    updatePasetoFormatCards();
    setModeText(currentMode);
    if (currentMode === 'paseto') {
      const name = currentName || nameInput.value.trim();
      if (name) {
        requestToken(name);
      }
    }
  });
});

loadState().then(connectEvents).catch(() => {
  setResult('Tidak bisa membaca status server.', 'error');
});

