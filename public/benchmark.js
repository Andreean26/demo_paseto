'use strict';

const runBtn = document.querySelector('#runBtn');
const runBtnText = document.querySelector('#runBtnText');
const quickBtn = document.querySelector('#quickBtn');
const roundsSelect = document.querySelector('#roundsSelect');
const presetSelect = document.querySelector('#presetSelect');
const rawSizeLabel = document.querySelector('#rawSizeLabel');
const progressWrap = document.querySelector('#progressWrap');
const progressBar = document.querySelector('#progressBar');
const envNode = document.querySelector('#envNode');
const envArch = document.querySelector('#envArch');

// KPI elements
const kpiJwtRoundtrip = document.querySelector('#kpiJwtRoundtrip');
const kpiPasetoLocRoundtrip = document.querySelector('#kpiPasetoLocRoundtrip');
const kpiPasetoPubRoundtrip = document.querySelector('#kpiPasetoPubRoundtrip');

// Chart containers
const chartGenerateTime = document.querySelector('#chartGenerateTime');
const chartVerifyTime = document.querySelector('#chartVerifyTime');
const trendBarsGrid = document.querySelector('#trendBarsGrid');
const trendTitle = document.querySelector('#trendTitle');
const trendSubtitle = document.querySelector('#trendSubtitle');
const chartSize = document.querySelector('#chartSize');

// Token inspector
const tokenTabs = document.querySelector('#tokenTabs');
const tokenPreviewCode = document.querySelector('#tokenPreviewCode');

let lastBenchmarkData = null;
let activeTokenTab = 'jwt';

function formatNumber(num) {
  return new Intl.NumberFormat('id-ID').format(Math.round(num));
}

function renderBarChart(container, items, { unit = '' } = {}) {
  container.innerHTML = '';
  if (!items || !items.length) return;

  const maxVal = Math.max(...items.map((i) => (i.barVal !== undefined ? i.barVal : i.value)), 1);

  for (const item of items) {
    const row = document.createElement('div');
    row.className = 'bar-row';

    const labelWrap = document.createElement('div');
    labelWrap.className = 'bar-label-wrap';

    const name = document.createElement('span');
    name.className = 'bar-name';
    name.textContent = item.label;

    const val = document.createElement('span');
    val.className = 'bar-value';
    val.textContent = item.displayValue || `${formatNumber(item.value)} ${unit}`.trim();

    labelWrap.append(name, val);

    const track = document.createElement('div');
    track.className = 'bar-track';

    const fill = document.createElement('div');
    fill.className = `bar-fill ${item.colorClass || 'cyan'}`;
    const metricVal = item.barVal !== undefined ? item.barVal : item.value;
    const percentage = Math.max(4, Math.min(100, (metricVal / maxVal) * 100));
    fill.style.width = '0%';
    setTimeout(() => {
      fill.style.width = `${percentage}%`;
    }, 40);

    track.append(fill);
    row.append(labelWrap, track);
    container.append(row);
  }
}

// Visualisasi Grafik Multi-Round (Trend Konsistensi 10 Putaran)
function renderTrendBars(container, roundsHistory) {
  container.innerHTML = '';
  if (!roundsHistory || !roundsHistory.length) return;

  // Cari ops/sec tertinggi di seluruh putaran untuk skala tinggi 100%
  let maxOps = 1;
  for (const r of roundsHistory) {
    maxOps = Math.max(
      maxOps,
      r.jwtHs.roundtripOpsSec || 0,
      r.pasetoLoc.roundtripOpsSec || 0,
      r.pasetoPub.roundtripOpsSec || 0
    );
  }

  for (const roundData of roundsHistory) {
    const col = document.createElement('div');
    col.className = 'trend-col';

    const barsGroup = document.createElement('div');
    barsGroup.className = 'trend-bars-group';

    // 1. JWT Bar
    const jwtOps = roundData.jwtHs.roundtripOpsSec || 0;
    const jwtHeight = Math.max(4, Math.round((jwtOps / maxOps) * 100));
    const jwtBar = document.createElement('div');
    jwtBar.className = 'trend-bar jwt';
    jwtBar.style.height = `${jwtHeight}%`;
    jwtBar.title = `Putaran ${roundData.round} - JWT: ${formatNumber(jwtOps)} ops/s (${roundData.jwtHs.avgLatencyUs} \u03BCs)`;

    // 2. PASETO v4.local Bar
    const locOps = roundData.pasetoLoc.roundtripOpsSec || 0;
    const locHeight = Math.max(4, Math.round((locOps / maxOps) * 100));
    const locBar = document.createElement('div');
    locBar.className = 'trend-bar paseto-loc';
    locBar.style.height = `${locHeight}%`;
    locBar.title = `Putaran ${roundData.round} - PASETO Local: ${formatNumber(locOps)} ops/s (${roundData.pasetoLoc.avgLatencyUs} \u03BCs)`;

    // 3. PASETO v4.public Bar
    const pubOps = roundData.pasetoPub.roundtripOpsSec || 0;
    const pubHeight = Math.max(4, Math.round((pubOps / maxOps) * 100));
    const pubBar = document.createElement('div');
    pubBar.className = 'trend-bar paseto-pub';
    pubBar.style.height = `${pubHeight}%`;
    pubBar.title = `Putaran ${roundData.round} - PASETO Public: ${formatNumber(pubOps)} ops/s (${roundData.pasetoPub.avgLatencyUs} \u03BCs)`;

    barsGroup.append(jwtBar, locBar, pubBar);

    const label = document.createElement('span');
    label.className = 'trend-col-label';
    label.textContent = `R${roundData.round}`;

    col.append(barsGroup, label);
    container.append(col);
  }
}

function updateKpiCards(results) {
  const { jwtHs, pasetoLoc, pasetoPub } = results;

  if (kpiJwtRoundtrip && jwtHs) {
    kpiJwtRoundtrip.textContent = `${formatNumber(jwtHs.performance.roundtrip.opsSec)} ops/s`;
  }
  if (kpiPasetoLocRoundtrip && pasetoLoc) {
    kpiPasetoLocRoundtrip.textContent = `${formatNumber(pasetoLoc.performance.roundtrip.opsSec)} ops/s`;
  }
  if (kpiPasetoPubRoundtrip && pasetoPub) {
    kpiPasetoPubRoundtrip.textContent = `${formatNumber(pasetoPub.performance.roundtrip.opsSec)} ops/s`;
  }
}

function updateCharts(data) {
  const { results, roundsHistory, benchmarkMeta } = data;
  const { jwtHs, pasetoLoc, pasetoPub } = results;

  // 1A. Grafik Waktu Pembuatan (Generate Time — Signing / Enkripsi)
  const jwtSignUs = (jwtHs.performance.sign.stats?.mean || 0).toFixed(1);
  const locEncUs = (pasetoLoc.performance.encrypt.stats?.mean || 0).toFixed(1);
  const pubSignUs = (pasetoPub.performance.sign.stats?.mean || 0).toFixed(1);

  renderBarChart(
    chartGenerateTime,
    [
      {
        label: 'JWT (HS256) — Signing HMAC',
        value: Number(jwtSignUs),
        barVal: jwtHs.performance.sign.opsSec,
        displayValue: `${jwtSignUs} \u03BCs (${formatNumber(jwtHs.performance.sign.opsSec)} ops/s)`,
        colorClass: 'cyan'
      },
      {
        label: 'PASETO (v4.local) — Enkripsi AEAD XChaCha20',
        value: Number(locEncUs),
        barVal: pasetoLoc.performance.encrypt.opsSec,
        displayValue: `${locEncUs} \u03BCs (${formatNumber(pasetoLoc.performance.encrypt.opsSec)} ops/s)`,
        colorClass: 'green'
      },
      {
        label: 'PASETO (v4.public) — Digital Signature Ed25519',
        value: Number(pubSignUs),
        barVal: pasetoPub.performance.sign.opsSec,
        displayValue: `${pubSignUs} \u03BCs (${formatNumber(pasetoPub.performance.sign.opsSec)} ops/s)`,
        colorClass: 'yellow'
      }
    ],
    { unit: '\u03BCs' }
  );

  // 1B. Grafik Waktu Verifikasi (Verify Time — Validasi / Dekripsi)
  const jwtVerifyUs = (jwtHs.performance.verify.stats?.mean || 0).toFixed(1);
  const locDecUs = (pasetoLoc.performance.decrypt.stats?.mean || 0).toFixed(1);
  const pubVerifyUs = (pasetoPub.performance.verify.stats?.mean || 0).toFixed(1);

  renderBarChart(
    chartVerifyTime,
    [
      {
        label: 'JWT (HS256) — Validasi Signature',
        value: Number(jwtVerifyUs),
        barVal: jwtHs.performance.verify.opsSec,
        displayValue: `${jwtVerifyUs} \u03BCs (${formatNumber(jwtHs.performance.verify.opsSec)} ops/s)`,
        colorClass: 'cyan'
      },
      {
        label: 'PASETO (v4.local) — Dekripsi & Tag BLAKE2b',
        value: Number(locDecUs),
        barVal: pasetoLoc.performance.decrypt.opsSec,
        displayValue: `${locDecUs} \u03BCs (${formatNumber(pasetoLoc.performance.decrypt.opsSec)} ops/s)`,
        colorClass: 'green'
      },
      {
        label: 'PASETO (v4.public) — Verifikasi Kunci Publik',
        value: Number(pubVerifyUs),
        barVal: pasetoPub.performance.verify.opsSec,
        displayValue: `${pubVerifyUs} \u03BCs (${formatNumber(pasetoPub.performance.verify.opsSec)} ops/s)`,
        colorClass: 'yellow'
      }
    ],
    { unit: '\u03BCs' }
  );

  // 2. Grafik Konsistensi 10 Putaran (Trend Bar Columns)
  if (trendTitle && benchmarkMeta) {
    trendTitle.textContent = `2. Grafik Konsistensi ${benchmarkMeta.rounds} Putaran Pengujian`;
  }
  if (trendSubtitle && benchmarkMeta) {
    trendSubtitle.textContent = `Membandingkan kestabilan throughput masing-masing token dari Putaran 1 sampai Putaran ${benchmarkMeta.rounds} (Arahkan kursor pada bar untuk melihat detail angka).`;
  }
  renderTrendBars(trendBarsGrid, roundsHistory);

  // 3. Grafik Ukuran Token & Overhead Bytes
  renderBarChart(
    chartSize,
    [
      {
        label: 'Raw JSON Payload Asli (Tanpa Header / Signature)',
        value: benchmarkMeta.rawPayloadBytes,
        colorClass: 'muted-bar'
      },
      {
        label: `JWT (HS256) — Overhead +${jwtHs.overheadBytes} B (+${jwtHs.overheadPercentage}%)`,
        value: jwtHs.byteSize,
        colorClass: 'cyan'
      },
      {
        label: `PASETO (v4.local) — Overhead +${pasetoLoc.overheadBytes} B (+${pasetoLoc.overheadPercentage}%)`,
        value: pasetoLoc.byteSize,
        colorClass: 'green'
      },
      {
        label: `PASETO (v4.public) — Overhead +${pasetoPub.overheadBytes} B (+${pasetoPub.overheadPercentage}%)`,
        value: pasetoPub.byteSize,
        colorClass: 'yellow'
      }
    ],
    { unit: 'Bytes' }
  );
}

function updateTokenInspector() {
  if (!lastBenchmarkData || !lastBenchmarkData.results) return;
  const { results } = lastBenchmarkData;

  let currentRawToken = '';
  if (activeTokenTab === 'jwt') {
    currentRawToken = results.jwtHs.token;
  } else if (activeTokenTab === 'pasetoLoc') {
    currentRawToken = results.pasetoLoc.token;
  } else if (activeTokenTab === 'pasetoPub') {
    currentRawToken = results.pasetoPub.token;
  }

  tokenPreviewCode.textContent = currentRawToken || '-';
}

async function runBenchmark(customRounds = null) {
  const rounds = customRounds || Number(roundsSelect ? roundsSelect.value : 10);
  const preset = presetSelect ? presetSelect.value : 'standard';

  runBtn.disabled = true;
  quickBtn.disabled = true;
  runBtnText.textContent = `Menguji ${rounds} Putaran...`;
  progressWrap.hidden = false;
  progressBar.style.width = '30%';

  try {
    const response = await fetch('/api/benchmark', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ rounds, preset })
    });

    progressBar.style.width = '80%';
    const data = await response.json();
    progressBar.style.width = '100%';

    if (!data.ok) {
      throw new Error(data.error || 'Benchmark gagal.');
    }

    lastBenchmarkData = data;

    // Metadata environment
    if (data.benchmarkMeta) {
      rawSizeLabel.textContent = `${data.benchmarkMeta.rawPayloadBytes} Bytes`;
      if (data.benchmarkMeta.environment) {
        const env = data.benchmarkMeta.environment;
        envNode.textContent = `Node ${env.nodeVersion} (${env.platform}_${env.arch})`;
        envArch.textContent = `${env.cpus} Cores | ${env.cpuModel}`;
      }
    }

    // Render 3 Visual Graphs & KPIs
    updateKpiCards(data.results);
    updateCharts(data);
    updateTokenInspector();
  } catch (error) {
    alert(`Gagal menjalankan benchmark: ${error.message}`);
  } finally {
    setTimeout(() => {
      progressWrap.hidden = true;
      progressBar.style.width = '0%';
      runBtn.disabled = false;
      quickBtn.disabled = false;
      runBtnText.innerHTML = '&#9889; Jalankan Benchmark (10x Sampel)';
    }, 400);
  }
}

// Event Listeners
tokenTabs.addEventListener('click', (event) => {
  const btn = event.target.closest('.tab-btn');
  if (!btn) return;
  tokenTabs.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
  btn.classList.add('active');
  activeTokenTab = btn.dataset.target;
  updateTokenInspector();
});

runBtn.addEventListener('click', () => runBenchmark());
quickBtn.addEventListener('click', () => {
  if (roundsSelect) roundsSelect.value = '10';
  runBenchmark(10);
});

// Auto-run initial benchmark on page load (10 rounds)
runBenchmark(10);
