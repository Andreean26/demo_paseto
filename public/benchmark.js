'use strict';

const runBtn = document.querySelector('#runBtn');
const runBtnText = document.querySelector('#runBtnText');
const quickBtn = document.querySelector('#quickBtn');
const iterationsSelect = document.querySelector('#iterationsSelect');
const presetSelect = document.querySelector('#presetSelect');
const rawSizeLabel = document.querySelector('#rawSizeLabel');
const customPayloadWrap = document.querySelector('#customPayloadWrap');
const customJsonInput = document.querySelector('#customJsonInput');
const progressWrap = document.querySelector('#progressWrap');
const progressBar = document.querySelector('#progressBar');
const envNode = document.querySelector('#envNode');
const envArch = document.querySelector('#envArch');

// KPI elements
const kpiJwtSign = document.querySelector('#kpiJwtSign');
const kpiJwtSignSub = document.querySelector('#kpiJwtSignSub');
const kpiPasetoEnc = document.querySelector('#kpiPasetoEnc');
const kpiPasetoEncSub = document.querySelector('#kpiPasetoEncSub');
const kpiJwtVerify = document.querySelector('#kpiJwtVerify');
const kpiJwtVerifySub = document.querySelector('#kpiJwtVerifySub');
const kpiPasetoDec = document.querySelector('#kpiPasetoDec');
const kpiPasetoDecSub = document.querySelector('#kpiPasetoDecSub');

// Chart containers
const chartSignOps = document.querySelector('#chartSignOps');
const chartVerifyOps = document.querySelector('#chartVerifyOps');
const chartSize = document.querySelector('#chartSize');
const chartOverhead = document.querySelector('#chartOverhead');
const latencyTableBody = document.querySelector('#latencyTableBody');

// Segmented bar elements & legend grids
const jwtSizeSummary = document.querySelector('#jwtSizeSummary');
const pasetoLocSizeSummary = document.querySelector('#pasetoLocSizeSummary');
const pasetoPubSizeSummary = document.querySelector('#pasetoPubSizeSummary');
const jwtSegmentedBar = document.querySelector('#jwtSegmentedBar');
const pasetoLocSegmentedBar = document.querySelector('#pasetoLocSegmentedBar');
const pasetoPubSegmentedBar = document.querySelector('#pasetoPubSegmentedBar');
const jwtLegendGrid = document.querySelector('#jwtLegendGrid');
const pasetoLocLegendGrid = document.querySelector('#pasetoLocLegendGrid');
const pasetoPubLegendGrid = document.querySelector('#pasetoPubLegendGrid');

// Token inspector preview
const tokenTabs = document.querySelector('#tokenTabs');
const tokenPreviewCode = document.querySelector('#tokenPreviewCode');

let lastBenchmarkData = null;
let activeTokenTab = 'jwt';

function formatNumber(num) {
  return new Intl.NumberFormat('id-ID').format(Math.round(num));
}

function formatLatency(us) {
  if (us >= 1000) {
    return `${(us / 1000).toFixed(2)} ms`;
  }
  return `${us.toFixed(1)} \u03BCs`;
}

function renderBarChart(container, items, { unit = '', higherIsBetter = true } = {}) {
  container.innerHTML = '';
  if (!items || !items.length) return;

  const maxVal = Math.max(...items.map((i) => i.value), 1);

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
    val.textContent = `${formatNumber(item.value)} ${unit}`;

    labelWrap.append(name, val);

    const track = document.createElement('div');
    track.className = 'bar-track';

    const fill = document.createElement('div');
    fill.className = `bar-fill ${item.colorClass || 'cyan'}`;
    const percentage = Math.max(4, Math.min(100, (item.value / maxVal) * 100));
    fill.style.width = '0%';
    setTimeout(() => {
      fill.style.width = `${percentage}%`;
    }, 40);

    track.append(fill);
    row.append(labelWrap, track);
    container.append(row);
  }
}

// ============================================================================
// SECTION 1: KPI CARDS (Ringkasan Kecepatan Signing & Verifikasi Teratas)
// ============================================================================
function updateKpiCards(results) {
  const { jwtHs, pasetoLoc } = results;

  // 1. Throughput Signing JWT & Rata-rata Latensi (µs)
  kpiJwtSign.textContent = formatNumber(jwtHs.performance.sign.opsSec);
  kpiJwtSignSub.textContent = `Ops/detik (${formatLatency(jwtHs.performance.sign.stats.mean)})`;

  // 2. Throughput Enkripsi PASETO v4.local & Rata-rata Latensi (µs)
  kpiPasetoEnc.textContent = formatNumber(pasetoLoc.performance.encrypt.opsSec);
  kpiPasetoEncSub.textContent = `Ops/detik (${formatLatency(pasetoLoc.performance.encrypt.stats.mean)})`;

  // 3. Throughput Verifikasi Signature JWT
  kpiJwtVerify.textContent = formatNumber(jwtHs.performance.verify.opsSec);
  kpiJwtVerifySub.textContent = `Ops/detik (${formatLatency(jwtHs.performance.verify.stats.mean)})`;

  // 4. Throughput Dekripsi & Autentikasi PASETO v4.local
  kpiPasetoDec.textContent = formatNumber(pasetoLoc.performance.decrypt.opsSec);
  kpiPasetoDecSub.textContent = `Ops/detik (${formatLatency(pasetoLoc.performance.decrypt.stats.mean)})`;
}

// ============================================================================
// SECTION 2: GRAFIK BATANG & TABEL PERSENTIL LATENSI
// ============================================================================
function updateCharts(results) {
  const { jwtHs, pasetoLoc, pasetoPub } = results;

  // --------------------------------------------------------------------------
  // 1. Grafik Kecepatan Pembuatan (Sign / Encrypt) -> Ops/sec (Higher is Better)
  // --------------------------------------------------------------------------
  renderBarChart(
    chartSignOps,
    [
      { label: 'JWT (HS256 Sign)', value: jwtHs.performance.sign.opsSec, colorClass: 'cyan' },
      { label: 'PASETO (v4.local Encrypt AEAD)', value: pasetoLoc.performance.encrypt.opsSec, colorClass: 'green' },
      { label: 'PASETO (v4.public Ed25519 Sign)', value: pasetoPub.performance.sign.opsSec, colorClass: 'yellow' }
    ],
    { unit: 'ops/sec' }
  );

  // --------------------------------------------------------------------------
  // 2. Grafik Kecepatan Verifikasi (Verify / Decrypt) -> Ops/sec (Higher is Better)
  // --------------------------------------------------------------------------
  renderBarChart(
    chartVerifyOps,
    [
      { label: 'JWT (HS256 Verify)', value: jwtHs.performance.verify.opsSec, colorClass: 'cyan' },
      { label: 'PASETO (v4.local Decrypt AEAD)', value: pasetoLoc.performance.decrypt.opsSec, colorClass: 'green' },
      { label: 'PASETO (v4.public Ed25519 Verify)', value: pasetoPub.performance.verify.opsSec, colorClass: 'yellow' }
    ],
    { unit: 'ops/sec' }
  );

  // --------------------------------------------------------------------------
  // 3. Grafik Ukuran Total Token (Bytes) -> Dibandingkan Raw JSON Asli
  // --------------------------------------------------------------------------
  renderBarChart(
    chartSize,
    [
      { label: 'Raw Payload JSON', value: jwtHs.rawPayloadBytes, colorClass: 'muted-bar' },
      { label: 'JWT (HS256)', value: jwtHs.byteSize, colorClass: 'cyan' },
      { label: 'PASETO (v4.local)', value: pasetoLoc.byteSize, colorClass: 'green' },
      { label: 'PASETO (v4.public)', value: pasetoPub.byteSize, colorClass: 'yellow' }
    ],
    { unit: 'bytes' }
  );

  // --------------------------------------------------------------------------
  // 4. Grafik Rasio Overhead Kriptografi (%) -> ((TokenBytes - RawBytes)/RawBytes)*100
  // --------------------------------------------------------------------------
  renderBarChart(
    chartOverhead,
    [
      { label: 'JWT (HS256) Overhead', value: Math.max(0, jwtHs.overheadPercentage), colorClass: 'cyan' },
      { label: 'PASETO (v4.local) Overhead', value: Math.max(0, pasetoLoc.overheadPercentage), colorClass: 'green' },
      { label: 'PASETO (v4.public) Overhead', value: Math.max(0, pasetoPub.overheadPercentage), colorClass: 'yellow' }
    ],
    { unit: '%' }
  );

  // --------------------------------------------------------------------------
  // 5. Tabel Distribusi Latensi Persentil (Mean, p50, p95, p99 & Roundtrip)
  // --------------------------------------------------------------------------
  latencyTableBody.innerHTML = '';
  const rows = [
    {
      name: 'JWT (HS256)',
      type: 'HMAC-SHA256 (Signing)',
      signStats: jwtHs.performance.sign.stats,
      roundtrip: jwtHs.performance.roundtrip
    },
    {
      name: 'PASETO (v4.local)',
      type: 'XChaCha20-Poly1305 + BLAKE2b (AEAD)',
      signStats: pasetoLoc.performance.encrypt.stats,
      roundtrip: pasetoLoc.performance.roundtrip
    },
    {
      name: 'PASETO (v4.public)',
      type: 'Ed25519 / EdDSA (Asymmetric Sign)',
      signStats: pasetoPub.performance.sign.stats,
      roundtrip: pasetoPub.performance.roundtrip
    }
  ];

  for (const r of rows) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${r.name}</strong></td>
      <td><span class="mono-tag">${r.type}</span></td>
      <td>${formatLatency(r.signStats.mean)}</td>
      <td>${formatLatency(r.signStats.p50)}</td>
      <td>${formatLatency(r.signStats.p95)}</td>
      <td>${formatLatency(r.signStats.p99)}</td>
      <td><span class="highlight-badge">${formatLatency(r.roundtrip.avgLatencyUs)}</span></td>
    `;
    latencyTableBody.append(tr);
  }

  // --------------------------------------------------------------------------
  // 6. Visualisasi Segmented Bar Breakdown (Komponen Header, Payload & Tag)
  // --------------------------------------------------------------------------
  updateStructureBreakdown(results);
}

// ============================================================================
// SECTION 3: STRUKTUR TOKEN SEGMENTED BREAKDOWN (Alokasi Byte per Komponen)
// ============================================================================
function updateStructureBreakdown(results) {
  const { jwtHs, pasetoLoc, pasetoPub } = results;

  // --------------------------------------------------------------------------
  // A. Breakdown JWT (HS256): Header (Base64) + Payload (Base64) + Signature
  // --------------------------------------------------------------------------
  const jwtH = jwtHs.structureBreakdown.headerBytes;
  const jwtP = jwtHs.structureBreakdown.payloadBytes;
  const jwtS = jwtHs.structureBreakdown.signatureBytes;
  const jwtTotal = jwtH + jwtP + jwtS || 1;
  const jwtHpct = ((jwtH / jwtTotal) * 100).toFixed(1);
  const jwtPpct = ((jwtP / jwtTotal) * 100).toFixed(1);
  const jwtSpct = ((jwtS / jwtTotal) * 100).toFixed(1);

  jwtSizeSummary.textContent = `${jwtHs.byteSize} Bytes total (${jwtHs.charLength} karakter)`;
  jwtSegmentedBar.innerHTML = `
    <div class="seg seg-header" style="width: ${jwtHpct}%" title="Header: ${jwtH}B (${jwtHpct}%)"></div>
    <div class="seg seg-payload" style="width: ${jwtPpct}%" title="Payload: ${jwtP}B (${jwtPpct}%)"></div>
    <div class="seg seg-signature" style="width: ${jwtSpct}%" title="Signature: ${jwtS}B (${jwtSpct}%)"></div>
  `;

  jwtLegendGrid.innerHTML = `
    <div class="legend-card">
      <div class="legend-card-top">
        <span class="legend-dot header-dot"></span>
        <span class="legend-card-title">Header</span>
        <span class="legend-card-size purple-text">${jwtH} Bytes (${jwtHpct}%)</span>
      </div>
      <div class="legend-card-detail"><code>{"alg":"HS256","typ":"JWT"}</code> Base64Url</div>
    </div>
    <div class="legend-card">
      <div class="legend-card-top">
        <span class="legend-dot payload-dot"></span>
        <span class="legend-card-title">Payload (Claims)</span>
        <span class="legend-card-size cyan-text">${jwtP} Bytes (${jwtPpct}%)</span>
      </div>
      <div class="legend-card-detail">JSON Claims Base64Url (Terbuka / Plaintext)</div>
    </div>
    <div class="legend-card">
      <div class="legend-card-top">
        <span class="legend-dot signature-dot"></span>
        <span class="legend-card-title">Signature HMAC</span>
        <span class="legend-card-size yellow-text">${jwtS} Bytes (${jwtSpct}%)</span>
      </div>
      <div class="legend-card-detail">32-Byte Binary HMAC-SHA256 Base64Url</div>
    </div>
  `;

  // --------------------------------------------------------------------------
  // B. Breakdown PASETO (v4.local): Prefix (9B) + Ciphertext & Nonce + BLAKE2b (32B)
  // --------------------------------------------------------------------------
  const locH = pasetoLoc.structureBreakdown.headerBytes;
  const locP = Math.max(1, pasetoLoc.structureBreakdown.payloadBytes);
  const locS = pasetoLoc.structureBreakdown.signatureBytes;
  const locTotal = locH + locP + locS || 1;
  const locHpct = ((locH / locTotal) * 100).toFixed(1);
  const locPpct = ((locP / locTotal) * 100).toFixed(1);
  const locSpct = ((locS / locTotal) * 100).toFixed(1);

  pasetoLocSizeSummary.textContent = `${pasetoLoc.byteSize} Bytes total (${pasetoLoc.charLength} karakter)`;
  pasetoLocSegmentedBar.innerHTML = `
    <div class="seg seg-header" style="width: ${locHpct}%" title="Prefix: ${locH}B (${locHpct}%)"></div>
    <div class="seg seg-ciphertext" style="width: ${locPpct}%" title="Ciphertext & Nonce: ${locP}B (${locPpct}%)"></div>
    <div class="seg seg-auth-tag" style="width: ${locSpct}%" title="BLAKE2b Tag: ${locS}B (${locSpct}%)"></div>
  `;

  pasetoLocLegendGrid.innerHTML = `
    <div class="legend-card">
      <div class="legend-card-top">
        <span class="legend-dot header-dot"></span>
        <span class="legend-card-title">Header Prefix</span>
        <span class="legend-card-size purple-text">${locH} Bytes (${locHpct}%)</span>
      </div>
      <div class="legend-card-detail">Header protokol <code>v4.local.</code> konstan</div>
    </div>
    <div class="legend-card">
      <div class="legend-card-top">
        <span class="legend-dot ciphertext-dot"></span>
        <span class="legend-card-title">Ciphertext & Nonce</span>
        <span class="legend-card-size green-text">${locP} Bytes (${locPpct}%)</span>
      </div>
      <div class="legend-card-detail">XChaCha20 Terenkripsi + 32-Byte Nonce Dinamis</div>
    </div>
    <div class="legend-card">
      <div class="legend-card-top">
        <span class="legend-dot auth-tag-dot"></span>
        <span class="legend-card-title">AEAD Auth Tag</span>
        <span class="legend-card-size yellow-text">${locS} Bytes (${locSpct}%)</span>
      </div>
      <div class="legend-card-detail">32-Byte BLAKE2b Authentication Tag</div>
    </div>
  `;

  // --------------------------------------------------------------------------
  // C. Breakdown PASETO (v4.public): Prefix (10B) + Claims (Base64) + Ed25519 (86B)
  // --------------------------------------------------------------------------
  const pubH = pasetoPub.structureBreakdown.headerBytes;
  const pubP = Math.max(1, pasetoPub.structureBreakdown.payloadBytes);
  const pubS = pasetoPub.structureBreakdown.signatureBytes;
  const pubTotal = pubH + pubP + pubS || 1;
  const pubHpct = ((pubH / pubTotal) * 100).toFixed(1);
  const pubPpct = ((pubP / pubTotal) * 100).toFixed(1);
  const pubSpct = ((pubS / pubTotal) * 100).toFixed(1);

  pasetoPubSizeSummary.textContent = `${pasetoPub.byteSize} Bytes total (${pasetoPub.charLength} karakter)`;
  pasetoPubSegmentedBar.innerHTML = `
    <div class="seg seg-header" style="width: ${pubHpct}%" title="Prefix: ${pubH}B (${pubHpct}%)"></div>
    <div class="seg seg-payload" style="width: ${pubPpct}%" title="Payload Claims: ${pubP}B (${pubPpct}%)"></div>
    <div class="seg seg-signature" style="width: ${pubSpct}%" title="Ed25519 Sig: ${pubS}B (${pubSpct}%)"></div>
  `;

  pasetoPubLegendGrid.innerHTML = `
    <div class="legend-card">
      <div class="legend-card-top">
        <span class="legend-dot header-dot"></span>
        <span class="legend-card-title">Header Prefix</span>
        <span class="legend-card-size purple-text">${pubH} Bytes (${pubHpct}%)</span>
      </div>
      <div class="legend-card-detail">Header protokol <code>v4.public.</code> konstan</div>
    </div>
    <div class="legend-card">
      <div class="legend-card-top">
        <span class="legend-dot payload-dot"></span>
        <span class="legend-card-title">Payload Claims</span>
        <span class="legend-card-size cyan-text">${pubP} Bytes (${pubPpct}%)</span>
      </div>
      <div class="legend-card-detail">JSON Claims Base64Url (Asymmetric Payload)</div>
    </div>
    <div class="legend-card">
      <div class="legend-card-top">
        <span class="legend-dot signature-dot"></span>
        <span class="legend-card-title">Ed25519 Signature</span>
        <span class="legend-card-size yellow-text">${pubS} Bytes (${pubSpct}%)</span>
      </div>
      <div class="legend-card-detail">64-Byte EdDSA Binary Signature Base64Url</div>
    </div>
  `;
}

// ============================================================================
// SECTION 4: LIVE TOKEN INSPECTOR PREVIEW
// ============================================================================
function updateTokenInspector() {
  if (!lastBenchmarkData || !lastBenchmarkData.results) return;
  const { results } = lastBenchmarkData;

  if (activeTokenTab === 'jwt') {
    tokenPreviewCode.textContent = results.jwtHs.token;
  } else if (activeTokenTab === 'pasetoLoc') {
    tokenPreviewCode.textContent = results.pasetoLoc.token;
  } else if (activeTokenTab === 'pasetoPub') {
    tokenPreviewCode.textContent = results.pasetoPub.token;
  }
}

// ============================================================================
// SECTION 5: TRIGGER PENGUJIAN BENCHMARK (Request HTTP ke Server API)
// ============================================================================
async function runBenchmark(customIterations = null) {
  const iterations = customIterations || Number(iterationsSelect.value || 1000);
  const preset = presetSelect.value;

  let customPayload = null;
  if (preset === 'custom') {
    try {
      customPayload = JSON.parse(customJsonInput.value || '{}');
    } catch {
      alert('Format JSON kustom tidak valid. Harap periksa kembali sintaks JSON Anda.');
      return;
    }
  }

  // 1. Update status UI ke state 'loading'
  runBtn.disabled = true;
  quickBtn.disabled = true;
  runBtnText.textContent = 'Menguji performa...';
  progressWrap.hidden = false;
  progressBar.style.width = '30%';

  try {
    // 2. Kirim request ke backend untuk menjalankan benchmark kriptografi riil
    const response = await fetch('/api/benchmark', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ iterations, preset, customPayload })
    });

    progressBar.style.width = '80%';
    const data = await response.json();
    progressBar.style.width = '100%';

    if (!data.ok) {
      throw new Error(data.error || 'Benchmark gagal.');
    }

    lastBenchmarkData = data;

    // 3. Tampilkan metadata lingkungan server (Versi Node, CPU, Cores)
    if (data.benchmarkMeta) {
      rawSizeLabel.textContent = `${data.benchmarkMeta.rawPayloadBytes} Bytes`;
      if (data.benchmarkMeta.environment) {
        const env = data.benchmarkMeta.environment;
        envNode.textContent = `Node ${env.nodeVersion} (${env.platform}_${env.arch})`;
        envArch.textContent = `${env.cpus} Cores | ${env.cpuModel}`;
      }
    }

    // 4. Render seluruh data hasil ke UI (KPI Cards, Bar Charts, Token Preview)
    updateKpiCards(data.results);
    updateCharts(data.results);
    updateTokenInspector();
  } catch (error) {
    alert(`Gagal menjalankan benchmark: ${error.message}`);
  } finally {
    // 5. Reset status tombol dan progress bar
    setTimeout(() => {
      progressWrap.hidden = true;
      progressBar.style.width = '0%';
    }, 400);
    runBtn.disabled = false;
    quickBtn.disabled = false;
    runBtnText.textContent = 'Jalankan Benchmark';
  }
}

presetSelect.addEventListener('change', () => {
  if (presetSelect.value === 'custom') {
    customPayloadWrap.hidden = false;
    if (!customJsonInput.value.trim()) {
      customJsonInput.value = JSON.stringify(
        {
          sub: 'custom_usr_123',
          role: 'ADMIN',
          company: 'Acme Corporation',
          tier: 'PLATINUM'
        },
        null,
        2
      );
    }
  } else {
    customPayloadWrap.hidden = true;
  }
});

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
  iterationsSelect.value = '500';
  runBenchmark(500);
});

// Auto-run initial benchmark on page load
runBenchmark(1000);
