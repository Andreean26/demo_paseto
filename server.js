'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const PORT = Number(process.env.PORT || 8080);
const PUBLIC_DIR = path.join(__dirname, 'public');
const JWT_SECRET = process.env.JWT_DEMO_SECRET || 'live-ctf-jwt-demo-secret';
const SECURE_KEY = crypto
  .createHash('sha256')
  .update(process.env.PASETO_DEMO_KEY || 'live-ctf-paseto-style-local-key')
  .digest();

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

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

function decodeBase64urlJson(value) {
  return JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 1024 * 1024) {
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

function makeJwt(name) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = {
    name,
    role: 'USER',
    iat: Math.floor(Date.now() / 1000)
  };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(signingInput).digest('base64url');
  return `${signingInput}.${signature}`;
}

function parseJwt(token) {
  const parts = token.split('.');
  if (parts.length < 2) {
    throw new Error('JWT format tidak valid');
  }
  return {
    header: decodeBase64urlJson(parts[0]),
    payload: decodeBase64urlJson(parts[1]),
    signingInput: `${parts[0]}.${parts[1]}`,
    signature: parts[2] || ''
  };
}

function verifyJwtVulnerable(token) {
  const parsed = parseJwt(token);
  const algorithm = String(parsed.header.alg || '').toLowerCase();

  if (algorithm === 'none') {
    return {
      claims: parsed.payload,
      warning: 'alg:none diterima tanpa verifikasi signature'
    };
  }

  if (parsed.header.alg !== 'HS256') {
    throw new Error(`Algoritma JWT tidak didukung: ${parsed.header.alg || 'kosong'}`);
  }

  const expected = crypto.createHmac('sha256', JWT_SECRET).update(parsed.signingInput).digest();
  const received = Buffer.from(parsed.signature, 'base64url');
  if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) {
    throw new Error('Signature JWT tidak valid');
  }

  return {
    claims: parsed.payload,
    warning: null
  };
}

function makeSecureLocalToken(name) {
  const nonce = crypto.randomBytes(12);
  const payload = Buffer.from(
    JSON.stringify({
      name,
      role: 'USER',
      iat: Math.floor(Date.now() / 1000)
    }),
    'utf8'
  );
  const cipher = crypto.createCipheriv('aes-256-gcm', SECURE_KEY, nonce);
  cipher.setAAD(Buffer.from('v4.local', 'utf8'));
  const encrypted = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v4.local.${Buffer.concat([nonce, encrypted, tag]).toString('base64url')}`;
}

function verifySecureLocalToken(token) {
  if (!token.startsWith('v4.local.')) {
    throw new Error('Token secure harus berformat v4.local');
  }

  const packed = Buffer.from(token.slice('v4.local.'.length), 'base64url');
  if (packed.length <= 28) {
    throw new Error('Token secure terlalu pendek');
  }

  const nonce = packed.subarray(0, 12);
  const tag = packed.subarray(packed.length - 16);
  const encrypted = packed.subarray(12, packed.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', SECURE_KEY, nonce);
  decipher.setAAD(Buffer.from('v4.local', 'utf8'));
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return JSON.parse(decrypted.toString('utf8'));
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
  return {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8'
  }[ext] || 'application/octet-stream';
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

async function handleApi(req, res) {
  const pathname = new URL(req.url, `http://${req.headers.host}`).pathname;

  if (req.method === 'GET' && pathname === '/api/state') {
    sendJson(res, 200, { ok: true, mode, events });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/mode') {
    const body = await readJson(req);
    const nextMode = body.mode === 'paseto' ? 'paseto' : 'jwt';
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
    const token = mode === 'jwt' ? makeJwt(name) : makeSecureLocalToken(name);
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

    try {
      const claims = verifySecureLocalToken(token);
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

  sendJson(res, 404, { ok: false, error: 'Endpoint tidak ditemukan' });
}

const server = http.createServer((req, res) => {
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

server.listen(PORT, '0.0.0.0', () => {
  const urls = [`http://localhost:${PORT}`];
  for (const network of Object.values(os.networkInterfaces())) {
    for (const entry of network || []) {
      if (entry.family === 'IPv4' && !entry.internal) {
        urls.push(`http://${entry.address}:${PORT}`);
      }
    }
  }

  console.log('Live Demo PASETO running');
  console.log(`Audience : ${urls[0]}/audience.html`);
  console.log(`Presenter: ${urls[0]}/presenter.html`);
  if (urls.length > 1) {
    console.log('LAN URLs :');
    for (const url of urls.slice(1)) {
      console.log(`  ${url}/audience.html`);
      console.log(`  ${url}/presenter.html`);
    }
  }
});
