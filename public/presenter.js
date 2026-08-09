'use strict';

const modeBadge = document.querySelector('#modeBadge');
const modeHelp = document.querySelector('#modeHelp');
const modeToggle = document.querySelector('#modeToggle');
const resetButton = document.querySelector('#resetButton');
const alertPanel = document.querySelector('#alertPanel');
const headline = document.querySelector('#headline');
const subline = document.querySelector('#subline');
const eventList = document.querySelector('#eventList');
const audienceUrl = document.querySelector('#audienceUrl');
const presenterAccess = document.querySelector('#presenterAccess');

const presenterKeyStorage = 'demo-paseto-presenter-key';
const query = new URLSearchParams(window.location.search);
let presenterKey = query.get('key') || sessionStorage.getItem(presenterKeyStorage) || '';

if (query.has('key')) {
  if (presenterKey) {
    sessionStorage.setItem(presenterKeyStorage, presenterKey);
  }
  query.delete('key');
  const cleanQuery = query.toString();
  const cleanUrl = `${window.location.pathname}${cleanQuery ? `?${cleanQuery}` : ''}${window.location.hash}`;
  window.history.replaceState({}, '', cleanUrl);
}

function setControlAvailability() {
  const authorized = Boolean(presenterKey);
  modeToggle.disabled = !authorized;
  resetButton.disabled = !authorized;
  presenterAccess.textContent = authorized
    ? 'Akses presenter aktif. Perubahan mode akan disiarkan ke seluruh audience.'
    : 'Mode hanya-baca. Buka URL Presenter yang dicetak di terminal server.';
  presenterAccess.classList.toggle('authorized', authorized);
}

function revokePresenterAccess() {
  presenterKey = '';
  sessionStorage.removeItem(presenterKeyStorage);
  setControlAvailability();
}

async function presenterPost(path, body) {
  if (!presenterKey) {
    return {
      response: null,
      payload: { ok: false, error: 'Kunci presenter tidak tersedia.' }
    };
  }

  const headers = { 'x-presenter-key': presenterKey };
  if (body) {
    headers['content-type'] = 'application/json';
  }

  try {
    const response = await fetch(path, {
      method: 'POST',
      headers,
      body: body ? JSON.stringify(body) : undefined
    });
    const payload = await response.json();
    if (response.status === 403) {
      revokePresenterAccess();
    }
    return { response, payload };
  } catch {
    return {
      response: null,
      payload: { ok: false, error: 'Server tidak dapat dihubungi.' }
    };
  }
}

function setMode(mode) {
  const secure = mode === 'paseto';
  modeToggle.checked = secure;
  modeBadge.textContent = secure ? 'PASETO Secure' : 'JWT Vulnerable';
  modeBadge.classList.toggle('secure', secure);
  modeHelp.textContent = secure
    ? 'Token terenkripsi dan tamper-proof untuk demo pertahanan.'
    : 'JWT menerima alg:none untuk demo serangan.';
}

function renderEvents(events) {
  eventList.innerHTML = '';
  if (!events.length) {
    const empty = document.createElement('p');
    empty.className = 'muted';
    empty.textContent = 'Belum ada event.';
    eventList.append(empty);
    return;
  }

  for (const event of events) {
    const item = document.createElement('div');
    item.className = 'event-item';

    const title = document.createElement('strong');
    title.textContent = event.title || event.type;

    const detail = document.createElement('small');
    const date = new Date(event.at);
    detail.textContent = `${date.toLocaleTimeString()} - ${event.warning || event.detail || event.mode || ''}`;

    item.append(title, detail);
    eventList.append(item);
  }
}

function showBreach(event) {
  headline.textContent = 'SISTEM DIRETAS';
  subline.textContent = `Oleh: ${event.name || 'Anonim'}`;
  alertPanel.classList.remove('breach');
  window.requestAnimationFrame(() => {
    alertPanel.classList.add('breach');
  });
}

async function loadState() {
  const response = await fetch('/api/state');
  const payload = await response.json();
  setMode(payload.mode);
  renderEvents(payload.events || []);
}

async function changeMode() {
  const mode = modeToggle.checked ? 'paseto' : 'jwt';
  modeToggle.disabled = true;
  const { response, payload } = await presenterPost('/api/mode', { mode });
  if (!response || !response.ok) {
    await loadState().catch(() => {});
    subline.textContent = payload.error || 'Mode gagal diganti.';
    setControlAvailability();
    return;
  }

  setMode(payload.mode);
  headline.textContent = payload.mode === 'paseto' ? 'Benteng aktif' : 'Sistem menunggu';
  subline.textContent =
    payload.mode === 'paseto'
      ? 'Sekarang token secure akan menolak modifikasi satu karakter pun.'
      : 'Mode JWT rentan aktif. Biarkan audiens mencoba alg:none.';
  alertPanel.classList.remove('breach');
  setControlAvailability();
}

async function resetEvents() {
  resetButton.disabled = true;
  const { response, payload } = await presenterPost('/api/reset');
  if (!response || !response.ok) {
    subline.textContent = payload.error || 'Event gagal dibersihkan.';
    setControlAvailability();
    return;
  }

  renderEvents(payload.events || []);
  headline.textContent = 'Sistem menunggu';
  subline.textContent = 'Belum ada peserta yang berhasil membuka brankas.';
  alertPanel.classList.remove('breach');
  setControlAvailability();
}

function connectEvents() {
  const stream = new EventSource('/events');

  stream.addEventListener('snapshot', (message) => {
    const payload = JSON.parse(message.data);
    setMode(payload.mode);
    renderEvents(payload.events || []);
  });

  stream.addEventListener('mode', (message) => {
    const event = JSON.parse(message.data);
    setMode(event.mode);
    loadState();
  });

  stream.addEventListener('hacked', (message) => {
    const event = JSON.parse(message.data);
    showBreach(event);
    loadState();
  });

  stream.addEventListener('blocked', () => {
    loadState();
  });
}

audienceUrl.textContent = `${window.location.origin}/audience.html`;
modeToggle.addEventListener('change', changeMode);
resetButton.addEventListener('click', resetEvents);
setControlAvailability();

loadState().then(connectEvents).catch(() => {
  eventList.textContent = 'Tidak bisa terhubung ke server.';
});
