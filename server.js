'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const jwt = require('jsonwebtoken');
const { V3, V4 } = require('paseto');

const PORT = Number(process.env.PORT || 8080);
const PUBLIC_DIR = path.join(__dirname, 'public');

// JWT: secret untuk membuat dan memverifikasi signature HMAC-SHA256
const JWT_SECRET = process.env.JWT_DEMO_SECRET || 'live-demo-jwt-secret-key-32-chars-long';

// PASETO: symmetric key untuk v3.local
const PASETO_LOCAL_RAW = crypto
  .createHash('sha256')
  .update(process.env.PASETO_DEMO_KEY || 'live-demo-paseto-local-key-32-bytes')
  .digest();
const PASETO_LOCAL_KEY = crypto.createSecretKey(PASETO_LOCAL_RAW);

// Asymmetric keys untuk JWT (Ed25519) dan PASETO (v4.public)
const ASYMMETRIC_ED_KEYPAIR = crypto.generateKeyPairSync('ed25519');

let mode = 'jwt';
let events = [];
const sseClients = new Set();

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body)
  });
  res.end(body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 2 * 1024 * 1024) {
        req.destroy();
        reject(new Error('Body too large'));
      }
    });
    req.on('end', () => {
      if (!raw) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (error) {
        reject(error);
      }
    });
    req.on('error', reject);
  });
}

// ===== Standard JWT with jsonwebtoken =====
function makeJwt(name) {
  return jwt.sign(
    {
      name,
      role: 'USER',
      iat: Math.floor(Date.now() / 1000)
    },
    JWT_SECRET,
    { algorithm: 'HS256' }
  );
}

function verifyJwtVulnerable(token) {
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || typeof decoded !== 'object' || !decoded.header || !decoded.payload) {
    throw new Error('JWT format tidak valid');
  }

  const algorithm = String(decoded.header.alg || '').toLowerCase();
  if (algorithm === 'none') {
    return {
      claims: decoded.payload,
      warning: 'alg:none diterima tanpa verifikasi signature'
    };
  }

  if (decoded.header.alg !== 'HS256') {
    throw new Error(`Algoritma JWT tidak didukung: ${decoded.header.alg || 'kosong'}`);
  }

  const claims = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  return {
    claims,
    warning: null
  };
}

// ===== Standard PASETO with panva/paseto =====
async function makeSecureLocalToken(name) {
  return await V3.encrypt(
    {
      name,
      role: 'USER',
      iat: Math.floor(Date.now() / 1000)
    },
    PASETO_LOCAL_KEY
  );
}

async function verifySecureLocalToken(token) {
  if (!token.startsWith('v3.local.') && !token.startsWith('v4.local.')) {
    throw new Error('Token secure harus berformat v3.local atau v4.local');
  }
  return await V3.decrypt(token, PASETO_LOCAL_KEY);
}

function addEvent(type, payload) {
  const event = {
    id: crypto.randomUUID(),
    type,
    at: new Date().toISOString(),
    ...payload
  };
  events = [event, ...events].slice(0, 40);
  broadcast(type, event);
  return event;
}

function broadcast(type, payload) {
  const packet = `event: ${type}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const res of sseClients) {
    res.write(packet);
  }
}

function contentType(filePath) {
  const ext = path.extname(filePath);
  return (
    {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.js': 'text/javascript; charset=utf-8',
      '.json': 'application/json; charset=utf-8',
      '.svg': 'image/svg+xml'
    }[ext] || 'application/octet-stream'
  );
}

function serveStatic(req, res) {
  const requestPath = new URL(req.url, `http://${req.headers.host}`).pathname;
  const fileName = requestPath === '/' ? 'audience.html' : requestPath.replace(/^\/+/, '');
  const filePath = path.normalize(path.join(PUBLIC_DIR, fileName));

  if (!filePath.startsWith(PUBLIC_DIR)) {
    sendJson(res, 403, { ok: false, error: 'Forbidden' });
    return;
  }

  fs.readFile(filePath, (error, content) => {
    if (error) {
      sendJson(res, 404, { ok: false, error: 'Not found' });
      return;
    }
    res.writeHead(200, {
      'content-type': contentType(filePath),
      'cache-control': 'no-store'
    });
    res.end(content);
  });
}

function handleEvents(req, res) {
  res.writeHead(200, {
    'content-type': 'text/event-stream',
    'cache-control': 'no-store',
    connection: 'keep-alive'
  });
  res.write(`event: snapshot\ndata: ${JSON.stringify({ mode, events })}\n\n`);
  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));
}

function extractBearer(req) {
  const auth = req.headers.authorization || '';
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    throw new Error('Header Authorization Bearer tidak ditemukan');
  }
  return match[1].trim();
}

// ===== Benchmark & Parametric Engine =====
const PAYLOAD_PRESETS = {
  minimal: {
    sub: 'usr_1001',
    role: 'USER'
  },
  standard: {
    sub: 'usr_948271029',
    name: 'Alice W. Johnson',
    email: 'alice.johnson@example.com',
    role: 'USER',
    department: 'Infrastructure & SecOps',
    permissions: ['read:profile', 'write:notes', 'access:vault'],
    iss: 'https://auth.company.local',
    aud: 'api.company.local'
  },
  rich: {
    sub: 'usr_948271029',
    name: 'Alice W. Johnson',
    email: 'alice.johnson@example.com',
    role: 'USER',
    department: 'Infrastructure & SecOps',
    title: 'Senior Security Architect',
    organization_id: 'org_sec_884102',
    permissions: [
      'read:profile',
      'write:notes',
      'access:vault',
      'audit:logs:export',
      'infra:cluster:monitor',
      'secrets:rotate'
    ],
    device: {
      id: 'dev_macbook_m3_8912',
      os: 'macOS Sonoma 14.5',
      ip: '192.168.10.45',
      trusted: true,
      last_mfa: '2026-09-01T07:00:00Z'
    },
    geo: {
      country: 'ID',
      city: 'Jakarta',
      tz: 'Asia/Jakarta'
    },
    attributes: {
      department_code: 'DPT-ENG-SEC',
      clearance_level: 4,
      session_affinity: 'primary_datacenter_ap_southeast_3'
    },
    iss: 'https://auth.company.local',
    aud: 'api.company.local'
  },
  large: {
    sub: 'usr_948271029',
    name: 'Alice W. Johnson',
    email: 'alice.johnson@example.com',
    role: 'USER',
    department: 'Infrastructure & SecOps',
    title: 'Senior Security Architect',
    organization: {
      id: 'org_enterprise_9921',
      name: 'Global Financial Solutions Inc',
      tier: 'ENTERPRISE_PLUS',
      sub_entities: ['apac_branch', 'emea_hub', 'us_east_datacenter']
    },
    roles: ['USER', 'DEVELOPER', 'SEC_AUDITOR', 'INCIDENT_RESPONDER'],
    permissions: Array.from({ length: 40 }, (_, idx) => `resource:module_${idx}:action_${idx % 5}`),
    security_context: {
      mfa_methods: ['fido2_webauthn', 'totp', 'hardware_key'],
      risk_score: 0.02,
      compliance_tags: ['SOC2_TYPE_II', 'ISO27001', 'PCI_DSS_3_2_1', 'GDPR_EU', 'OJK_POJK'],
      session_policies: {
        max_duration_seconds: 28800,
        idle_timeout_seconds: 1800,
        require_step_up_for: ['vault:modify', 'billing:change', 'keys:export']
      }
    },
    audit_trail_preview: [
      { action: 'login_password', status: 'OK', at: '2026-09-01T06:45:10Z' },
      { action: 'mfa_fido2_verify', status: 'OK', at: '2026-09-01T06:45:22Z' },
      { action: 'access_vault_token', status: 'PENDING', at: '2026-09-01T07:12:00Z' }
    ],
    iss: 'https://auth.company.local',
    aud: 'api.company.local'
  }
};

function calculateStats(latencies) {
  if (!latencies.length) return { min: 0, max: 0, p50: 0, p95: 0, p99: 0, mean: 0 };
  const sorted = [...latencies].sort((a, b) => a - b);
  const min = Number(sorted[0].toFixed(2));
  const max = Number(sorted[sorted.length - 1].toFixed(2));
  const sum = sorted.reduce((acc, val) => acc + val, 0);
  const mean = Number((sum / sorted.length).toFixed(2));
  const p50 = Number(sorted[Math.floor(sorted.length * 0.5)].toFixed(2));
  const p95 = Number(sorted[Math.floor(sorted.length * 0.95)].toFixed(2));
  const p99 = Number(sorted[Math.floor(sorted.length * 0.99)].toFixed(2));
  return { min, max, mean, p50, p95, p99 };
}

async function runBenchmarkEngine(options = {}) {
  const iterations = Math.max(10, Math.min(Number(options.iterations || 1000), 5000));
  const presetKey = options.preset && PAYLOAD_PRESETS[options.preset] ? options.preset : 'standard';
  const custom = options.customPayload && typeof options.customPayload === 'object' ? options.customPayload : null;
  const basePayload = custom || PAYLOAD_PRESETS[presetKey];
  const payload = {
    ...basePayload,
    iat: Math.floor(Date.now() / 1000)
  };

  const rawJson = JSON.stringify(payload);
  const rawPayloadBytes = Buffer.byteLength(rawJson);

  // Warmup run
  for (let i = 0; i < 20; i++) {
    const tJwtHs = jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });
    jwt.verify(tJwtHs, JWT_SECRET, { algorithms: ['HS256'] });
    const tPasLoc = await V3.encrypt(payload, PASETO_LOCAL_KEY);
    await V3.decrypt(tPasLoc, PASETO_LOCAL_KEY);
    const tPasPub = await V4.sign(payload, ASYMMETRIC_ED_KEYPAIR.privateKey);
    await V4.verify(tPasPub, ASYMMETRIC_ED_KEYPAIR.publicKey);
  }

  // ===== 1. JWT HS256 (Symmetric Signing & Verification) =====
  const jwtHsSignLatencies = [];
  let sampleJwtHs = '';
  const startJwtHsSign = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    const t0 = process.hrtime.bigint();
    sampleJwtHs = jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });
    const t1 = process.hrtime.bigint();
    jwtHsSignLatencies.push(Number(t1 - t0) / 1000);
  }
  const endJwtHsSign = process.hrtime.bigint();
  const totalJwtHsSignMs = Number(endJwtHsSign - startJwtHsSign) / 1e6;

  const jwtHsVerifyLatencies = [];
  const startJwtHsVerify = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    const t0 = process.hrtime.bigint();
    jwt.verify(sampleJwtHs, JWT_SECRET, { algorithms: ['HS256'] });
    const t1 = process.hrtime.bigint();
    jwtHsVerifyLatencies.push(Number(t1 - t0) / 1000);
  }
  const endJwtHsVerify = process.hrtime.bigint();
  const totalJwtHsVerifyMs = Number(endJwtHsVerify - startJwtHsVerify) / 1e6;

  const jwtHsParts = sampleJwtHs.split('.');
  const jwtHsStats = {
    name: 'JWT (HS256)',
    type: 'Symmetric (HMAC-SHA256)',
    token: sampleJwtHs,
    charLength: sampleJwtHs.length,
    byteSize: Buffer.byteLength(sampleJwtHs),
    rawPayloadBytes,
    overheadBytes: Buffer.byteLength(sampleJwtHs) - rawPayloadBytes,
    overheadPercentage: Number((((Buffer.byteLength(sampleJwtHs) - rawPayloadBytes) / rawPayloadBytes) * 100).toFixed(1)),
    structureBreakdown: {
      headerBytes: Buffer.byteLength(jwtHsParts[0] || ''),
      payloadBytes: Buffer.byteLength(jwtHsParts[1] || ''),
      signatureBytes: Buffer.byteLength(jwtHsParts[2] || '')
    },
    performance: {
      sign: {
        opsSec: Math.round((iterations / totalJwtHsSignMs) * 1000),
        totalTimeMs: Number(totalJwtHsSignMs.toFixed(2)),
        stats: calculateStats(jwtHsSignLatencies)
      },
      verify: {
        opsSec: Math.round((iterations / totalJwtHsVerifyMs) * 1000),
        totalTimeMs: Number(totalJwtHsVerifyMs.toFixed(2)),
        stats: calculateStats(jwtHsVerifyLatencies)
      },
      roundtrip: {
        opsSec: Math.round((iterations / (totalJwtHsSignMs + totalJwtHsVerifyMs)) * 1000),
        totalTimeMs: Number((totalJwtHsSignMs + totalJwtHsVerifyMs).toFixed(2)),
        avgLatencyUs: Number(((totalJwtHsSignMs + totalJwtHsVerifyMs) * 1000 / iterations).toFixed(2))
      }
    }
  };

  // ===== 2. PASETO v3.local (Symmetric AEAD Encrypt & Decrypt) =====
  const pasetoLocEncLatencies = [];
  let samplePasetoLoc = '';
  const startPasetoLocEnc = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    const t0 = process.hrtime.bigint();
    samplePasetoLoc = await V3.encrypt(payload, PASETO_LOCAL_KEY);
    const t1 = process.hrtime.bigint();
    pasetoLocEncLatencies.push(Number(t1 - t0) / 1000);
  }
  const endPasetoLocEnc = process.hrtime.bigint();
  const totalPasetoLocEncMs = Number(endPasetoLocEnc - startPasetoLocEnc) / 1e6;

  const pasetoLocDecLatencies = [];
  const startPasetoLocDec = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    const t0 = process.hrtime.bigint();
    await V3.decrypt(samplePasetoLoc, PASETO_LOCAL_KEY);
    const t1 = process.hrtime.bigint();
    pasetoLocDecLatencies.push(Number(t1 - t0) / 1000);
  }
  const endPasetoLocDec = process.hrtime.bigint();
  const totalPasetoLocDecMs = Number(endPasetoLocDec - startPasetoLocDec) / 1e6;

  const pasetoLocStats = {
    name: 'PASETO (v3.local)',
    type: 'Symmetric AEAD (AES-256-CTR + HMAC-SHA384)',
    token: samplePasetoLoc,
    charLength: samplePasetoLoc.length,
    byteSize: Buffer.byteLength(samplePasetoLoc),
    rawPayloadBytes,
    overheadBytes: Buffer.byteLength(samplePasetoLoc) - rawPayloadBytes,
    overheadPercentage: Number((((Buffer.byteLength(samplePasetoLoc) - rawPayloadBytes) / rawPayloadBytes) * 100).toFixed(1)),
    structureBreakdown: {
      headerBytes: 9, // 'v3.local.'
      payloadBytes: Buffer.byteLength(samplePasetoLoc) - 9 - 48, // Ciphertext & Nonce
      signatureBytes: 48 // 384-bit Auth Tag
    },
    performance: {
      encrypt: {
        opsSec: Math.round((iterations / totalPasetoLocEncMs) * 1000),
        totalTimeMs: Number(totalPasetoLocEncMs.toFixed(2)),
        stats: calculateStats(pasetoLocEncLatencies)
      },
      decrypt: {
        opsSec: Math.round((iterations / totalPasetoLocDecMs) * 1000),
        totalTimeMs: Number(totalPasetoLocDecMs.toFixed(2)),
        stats: calculateStats(pasetoLocDecLatencies)
      },
      roundtrip: {
        opsSec: Math.round((iterations / (totalPasetoLocEncMs + totalPasetoLocDecMs)) * 1000),
        totalTimeMs: Number((totalPasetoLocEncMs + totalPasetoLocDecMs).toFixed(2)),
        avgLatencyUs: Number(((totalPasetoLocEncMs + totalPasetoLocDecMs) * 1000 / iterations).toFixed(2))
      }
    }
  };

  // ===== 3. PASETO v4.public (Asymmetric Ed25519 Sign & Verify) =====
  const pasetoPubSignLatencies = [];
  let samplePasetoPub = '';
  const startPasetoPubSign = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    const t0 = process.hrtime.bigint();
    samplePasetoPub = await V4.sign(payload, ASYMMETRIC_ED_KEYPAIR.privateKey);
    const t1 = process.hrtime.bigint();
    pasetoPubSignLatencies.push(Number(t1 - t0) / 1000);
  }
  const endPasetoPubSign = process.hrtime.bigint();
  const totalPasetoPubSignMs = Number(endPasetoPubSign - startPasetoPubSign) / 1e6;

  const pasetoPubVerifyLatencies = [];
  const startPasetoPubVerify = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    const t0 = process.hrtime.bigint();
    await V4.verify(samplePasetoPub, ASYMMETRIC_ED_KEYPAIR.publicKey);
    const t1 = process.hrtime.bigint();
    pasetoPubVerifyLatencies.push(Number(t1 - t0) / 1000);
  }
  const endPasetoPubVerify = process.hrtime.bigint();
  const totalPasetoPubVerifyMs = Number(endPasetoPubVerify - startPasetoPubVerify) / 1e6;

  const pasetoPubStats = {
    name: 'PASETO (v4.public)',
    type: 'Asymmetric (Ed25519 / EdDSA)',
    token: samplePasetoPub,
    charLength: samplePasetoPub.length,
    byteSize: Buffer.byteLength(samplePasetoPub),
    rawPayloadBytes,
    overheadBytes: Buffer.byteLength(samplePasetoPub) - rawPayloadBytes,
    overheadPercentage: Number((((Buffer.byteLength(samplePasetoPub) - rawPayloadBytes) / rawPayloadBytes) * 100).toFixed(1)),
    structureBreakdown: {
      headerBytes: 10, // 'v4.public.'
      payloadBytes: Buffer.byteLength(samplePasetoPub) - 10 - 86, // Base64url claims
      signatureBytes: 86 // Ed25519 signature base64url
    },
    performance: {
      sign: {
        opsSec: Math.round((iterations / totalPasetoPubSignMs) * 1000),
        totalTimeMs: Number(totalPasetoPubSignMs.toFixed(2)),
        stats: calculateStats(pasetoPubSignLatencies)
      },
      verify: {
        opsSec: Math.round((iterations / totalPasetoPubVerifyMs) * 1000),
        totalTimeMs: Number(totalPasetoPubVerifyMs.toFixed(2)),
        stats: calculateStats(pasetoPubVerifyLatencies)
      },
      roundtrip: {
        opsSec: Math.round((iterations / (totalPasetoPubSignMs + totalPasetoPubVerifyMs)) * 1000),
        totalTimeMs: Number((totalPasetoPubSignMs + totalPasetoPubVerifyMs).toFixed(2)),
        avgLatencyUs: Number(((totalPasetoPubSignMs + totalPasetoPubVerifyMs) * 1000 / iterations).toFixed(2))
      }
    }
  };

  return {
    ok: true,
    benchmarkMeta: {
      iterations,
      preset: presetKey,
      rawPayloadBytes,
      timestamp: new Date().toISOString(),
      environment: {
        nodeVersion: process.version,
        arch: process.arch,
        platform: process.platform,
        cpus: os.cpus().length,
        cpuModel: os.cpus()[0]?.model || 'Unknown'
      }
    },
    payloadSample: payload,
    results: {
      jwtHs: jwtHsStats,
      pasetoLoc: pasetoLocStats,
      pasetoPub: pasetoPubStats
    }
  };
}

async function handleApi(req, res) {
  const pathname = new URL(req.url, `http://${req.headers.host}`).pathname;

  if (req.method === 'GET' && pathname === '/api/state') {
    sendJson(res, 200, { ok: true, mode, events });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/mode') {
    const body = await readJson(req);
    if (body.mode !== 'jwt' && body.mode !== 'paseto') {
      sendJson(res, 400, { ok: false, error: 'Mode harus jwt atau paseto.' });
      return;
    }

    const nextMode = body.mode;
    mode = nextMode;
    addEvent('mode', {
      title: `Mode diganti ke ${mode.toUpperCase()}`,
      mode
    });
    sendJson(res, 200, { ok: true, mode });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/reset') {
    events = [];
    broadcast('snapshot', { mode, events });
    sendJson(res, 200, { ok: true, mode, events });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/auth/generate') {
    const body = await readJson(req);
    const name = String(body.name || '').trim().slice(0, 60);
    if (!name) {
      sendJson(res, 400, { ok: false, error: 'Nama wajib diisi' });
      return;
    }
    const token = mode === 'jwt' ? makeJwt(name) : await makeSecureLocalToken(name);
    sendJson(res, 200, {
      ok: true,
      mode,
      name,
      role: 'USER',
      token
    });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/vault/access') {
    let token;
    try {
      token = extractBearer(req);
    } catch (error) {
      sendJson(res, 401, { ok: false, error: error.message });
      return;
    }

    if (mode === 'jwt') {
      try {
        const result = verifyJwtVulnerable(token);
        const name = String(result.claims.name || 'Anonim').slice(0, 60);
        const role = String(result.claims.role || 'UNKNOWN').toUpperCase();
        if (role === 'ADMIN') {
          addEvent('hacked', {
            title: `SISTEM DIRETAS OLEH: ${name}`,
            name,
            role,
            warning: result.warning || 'JWT valid dengan role ADMIN'
          });
          sendJson(res, 200, {
            ok: true,
            status: 'HACKED',
            message: `Vault terbuka. Presenter akan melihat nama ${name}.`,
            claims: result.claims,
            warning: result.warning
          });
          return;
        }
        sendJson(res, 403, {
          ok: false,
          status: 'DENIED',
          message: 'Token valid, tapi role masih USER. Ubah payload kalau berani.',
          claims: result.claims
        });
      } catch (error) {
        sendJson(res, 401, { ok: false, status: 'INVALID', error: error.message });
      }
      return;
    }

    // PASETO-style mode
    try {
      const claims = await verifySecureLocalToken(token);
      sendJson(res, 403, {
        ok: false,
        status: 'DENIED',
        message: 'Token secure valid, tapi role tetap USER. Brankas tetap terkunci.',
        claims
      });
    } catch (error) {
      addEvent('blocked', {
        title: 'Percobaan token secure diblokir',
        detail: error.message
      });
      sendJson(res, 401, {
        ok: false,
        status: 'BLOCKED',
        error: 'Token secure rusak atau tidak autentik. Akses ditolak.'
      });
    }
    return;
  }

  // Benchmark endpoint
  if (pathname === '/api/benchmark') {
    if (req.method === 'POST') {
      const body = await readJson(req);
      const data = await runBenchmarkEngine(body);
      sendJson(res, 200, data);
      return;
    }
    if (req.method === 'GET') {
      const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
      const iterations = Number(parsedUrl.searchParams.get('iterations') || 1000);
      const preset = parsedUrl.searchParams.get('preset') || 'standard';
      const data = await runBenchmarkEngine({ iterations, preset });
      sendJson(res, 200, data);
      return;
    }
  }

  sendJson(res, 404, { ok: false, error: 'Endpoint tidak ditemukan' });
}

function createServer() {
  return http.createServer((req, res) => {
    if (req.url === '/events') {
      handleEvents(req, res);
      return;
    }

    if (req.url.startsWith('/api/')) {
      handleApi(req, res).catch((error) => {
        sendJson(res, 500, { ok: false, error: error.message });
      });
      return;
    }

    serveStatic(req, res);
  });
}

function startServer() {
  const server = createServer();

  server.listen(PORT, '0.0.0.0', () => {
    const address = server.address();
    const activePort = typeof address === 'object' && address ? address.port : PORT;
    const urls = [`http://localhost:${activePort}`];
    for (const network of Object.values(os.networkInterfaces())) {
      for (const entry of network || []) {
        if (entry.family === 'IPv4' && !entry.internal) {
          urls.push(`http://${entry.address}:${activePort}`);
        }
      }
    }

    console.log('Live Demo PASETO running');
    console.log(`Audience  : ${urls[0]}/audience.html`);
    console.log(`Presenter : ${urls[0]}/presenter.html`);
    console.log(`Benchmark : ${urls[0]}/benchmark.html`);
    if (urls.length > 1) {
      console.log('LAN URLs :');
      for (const url of urls.slice(1)) {
        console.log(`  Audience  : ${url}/audience.html`);
        console.log(`  Presenter : ${url}/presenter.html`);
        console.log(`  Benchmark : ${url}/benchmark.html`);
      }
    }
  });

  return server;
}

if (require.main === module) {
  startServer();
}

module.exports = {
  createServer,
  handleApi,
  handleEvents,
  runBenchmarkEngine,
  makeJwt,
  verifyJwtVulnerable,
  makeSecureLocalToken,
  verifySecureLocalToken
};
