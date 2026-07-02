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
const jwtDemoButton = document.querySelector('#jwtDemoButton');
const pasetoDemoButton = document.querySelector('#pasetoDemoButton');
const tamperButton = document.querySelector('#tamperButton');
const tokenHint = document.querySelector('#tokenHint');

let currentName = '';
let currentMode = 'jwt';

function setResult(text, kind) {
  resultText.textContent = text;
  resultPanel.classList.remove('success', 'error');
  if (kind) {
    resultPanel.classList.add(kind);
  }
}

function setModeText(mode) {
  modeLabel.textContent = mode === 'paseto' ? 'PASETO Secure' : 'JWT Vulnerable';
  tokenHint.textContent =
    mode === 'paseto'
      ? 'Token PASETO-style memakai prefix v4.local dan payload-nya terenkripsi. Coba rusak satu karakter, lalu akses brankas.'
      : 'Token JWT bisa dibaca. Coba Forge JWT ADMIN, lalu akses brankas.';
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

async function loadState() {
  const response = await fetch('/api/state');
  const payload = await response.json();
  currentMode = payload.mode;
  setModeText(currentMode);
}

async function requestToken(name) {
  const response = await fetch('/api/auth/generate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name })
  });
  const payload = await response.json();
  if (!payload.ok) {
    setResult(payload.error || 'Token gagal dibuat.', 'error');
    return null;
  }

  currentMode = payload.mode;
  tokenBox.value = payload.token;
  roleLabel.textContent = payload.role;
  setModeText(currentMode);
  return payload;
}

async function generateToken(event) {
  event.preventDefault();
  const payload = await requestToken(getParticipantName());
  if (!payload) {
    return;
  }
  setResult('Token USER siap dicoba.', null);
}

async function setServerMode(mode) {
  const response = await fetch('/api/mode', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ mode })
  });
  const payload = await response.json();
  currentMode = payload.mode;
  setModeText(currentMode);
}

async function startJwtDemo() {
  await setServerMode('jwt');
  const payload = await requestToken(getParticipantName());
  if (!payload) {
    return;
  }
  setResult('JWT USER dibuat. Tekan Forge JWT ADMIN, lalu akses brankas untuk menjebol mode rentan.', null);
}

async function startPasetoDemo() {
  await setServerMode('paseto');
  const payload = await requestToken(getParticipantName());
  if (!payload) {
    return;
  }
  setResult('PASETO secure dibuat. Tekan Rusak 1 karakter, lalu akses brankas untuk melihatnya diblokir.', null);
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
  setResult('JWT palsu dibuat dengan alg:none. Kirim ke brankas saat mode JWT aktif.', null);
}

function tamperToken() {
  const token = tokenBox.value.trim();
  if (!token) {
    setResult('Token masih kosong.', 'error');
    return;
  }
  const index = token.length - 1;
  const replacement = token[index] === 'A' ? 'B' : 'A';
  tokenBox.value = `${token.slice(0, index)}${replacement}`;
  setResult('Satu karakter token diubah. Pada PASETO secure, akses harus ditolak.', null);
}

nameForm.addEventListener('submit', generateToken);
accessButton.addEventListener('click', accessVault);
copyButton.addEventListener('click', copyToken);
forgeButton.addEventListener('click', forgeJwt);
jwtDemoButton.addEventListener('click', startJwtDemo);
pasetoDemoButton.addEventListener('click', startPasetoDemo);
tamperButton.addEventListener('click', tamperToken);

loadState().catch(() => {
  setResult('Tidak bisa membaca status server.', 'error');
});
