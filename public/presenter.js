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
  const response = await fetch('/api/mode', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ mode })
  });
  const payload = await response.json();
  setMode(payload.mode);
  headline.textContent = payload.mode === 'paseto' ? 'Benteng aktif' : 'Sistem menunggu';
  subline.textContent =
    payload.mode === 'paseto'
      ? 'Sekarang token secure akan menolak modifikasi satu karakter pun.'
      : 'Mode JWT rentan aktif. Biarkan audiens mencoba alg:none.';
  alertPanel.classList.remove('breach');
}

async function resetEvents() {
  const response = await fetch('/api/reset', { method: 'POST' });
  const payload = await response.json();
  renderEvents(payload.events || []);
  headline.textContent = 'Sistem menunggu';
  subline.textContent = 'Belum ada peserta yang berhasil membuka brankas.';
  alertPanel.classList.remove('breach');
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

loadState().then(connectEvents).catch(() => {
  eventList.textContent = 'Tidak bisa terhubung ke server.';
});
