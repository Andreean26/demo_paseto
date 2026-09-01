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

function setModeText(mode) {
  const secure = mode === 'paseto';
  modeLabel.textContent = secure ? 'PASETO Secure' : 'JWT Vulnerable';
  tokenHint.textContent =
    secure
      ? 'Token PASETO memakai library standar (v3.local / AEAD) dan payload-nya terenkripsi. Coba rusak satu karakter, lalu akses brankas.'
      : 'Token JWT dibuat dengan library standar jsonwebtoken. Coba Forge JWT ADMIN, lalu akses brankas.';
  tamperButton.hidden = !secure;
  forgeButton.hidden = secure;
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

// ===== PASETO: hanya struktur token terenkripsi yang ditampilkan =====
function isPasetoToken(token) {
  return /^v[1-4]\.(local|public)\./i.test(token);
}

function inspectSecureToken(token) {
  const match = token.match(/^(v[1-4])\.(local|public)\.(.+)$/i);
  if (!match) {
    throw new Error('Format token PASETO tidak valid.');
  }
  const version = match[1].toLowerCase();
  const purpose = match[2].toLowerCase();
  const body = match[3];
  const packed = decodeBase64UrlBytes(body);

  if (purpose === 'local') {
    showDecoderDetails({
      headerLabel: 'Header PASETO',
      header: `${version}.${purpose}`,
      payloadLabel: 'Payload Terenkripsi (AEAD)',
      payload: JSON.stringify(
        {
          version,
          purpose: 'local (Symmetric AEAD)',
          status: 'opaque / terenkripsi (tidak dapat dibaca tanpa symmetric key)',
          encodedLength: body.length,
          binaryBytes: packed.length
        },
        null,
        2
      ),
      signatureLabel: 'Autentikasi & Integritas',
      signature: 'Nonce, Ciphertext, dan AEAD Authentication Tag dikemas bersama. Perubahan 1 bit akan langsung membatalkan token.'
    });
    setDecoderSummary(
      'Berbeda dari JWT, payload PASETO local terenkripsi sepenuhnya. Penyerang tidak bisa membaca ataupun memodifikasi data.',
      'secure'
    );
  } else {
    showDecoderDetails({
      headerLabel: 'Header PASETO',
      header: `${version}.${purpose}`,
      payloadLabel: 'Payload PASETO Public',
      payload: JSON.stringify(
        {
          version,
          purpose: 'public (Asymmetric Signature)',
          encodedLength: body.length
        },
        null,
        2
      ),
      signatureLabel: 'Signature Kriptografi',
      signature: 'Ditandatangani secara asimetris dengan kunci privat Ed25519/ECDSA.'
    });
    setDecoderSummary(
      'PASETO Public ditandatangani dengan kunci privat kriptografi modern.',
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
}

async function requestToken(name) {
  const requestId = ++tokenRequestId;
  const response = await fetch('/api/auth/generate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name })
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

// ===== PASETO-style: simulasi perubahan token untuk menguji autentikasi AEAD =====
function tamperToken() {
  const token = tokenBox.value.trim();
  if (!token) {
    setResult('Token masih kosong.', 'error');
    return;
  }
  const index = token.length - 1;
  const replacement = token[index] === 'A' ? 'B' : 'A';
  tokenBox.value = `${token.slice(0, index)}${replacement}`;
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

loadState().then(connectEvents).catch(() => {
  setResult('Tidak bisa membaca status server.', 'error');
});
