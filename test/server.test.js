'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const test = require('node:test');

const {
  handleApi,
  handleEvents,
  makeJwt,
  verifyJwtVulnerable,
  makeSecureLocalToken,
  verifySecureLocalToken
} = require('../server');

async function requestApi(method, url, { body, headers = {} } = {}) {
  const req = new PassThrough();
  req.method = method;
  req.url = url;
  req.headers = { host: 'localhost', ...headers };

  const response = {
    status: null,
    headers: null,
    body: '',
    writeHead(status, responseHeaders) {
      this.status = status;
      this.headers = responseHeaders;
    },
    end(chunk = '') {
      this.body += chunk;
    }
  };

  req.end(body ? JSON.stringify(body) : undefined);
  await handleApi(req, response);
  return {
    status: response.status,
    headers: response.headers,
    json: response.body ? JSON.parse(response.body) : null
  };
}

function parseSse(packet) {
  const lines = packet.trim().split('\n');
  const event = lines.find((line) => line.startsWith('event: '))?.slice(7);
  const data = lines
    .filter((line) => line.startsWith('data: '))
    .map((line) => line.slice(6))
    .join('\n');
  return { event, data: JSON.parse(data) };
}

test('mode can be changed without an authorization header and clients receive the change over SSE', async () => {
  const invalidMode = await requestApi('POST', '/api/mode', {
    body: { mode: 'unknown' }
  });
  assert.equal(invalidMode.status, 400);

  const streamRequest = new EventEmitter();
  const packets = [];
  const streamResponse = {
    status: null,
    writeHead(status) {
      this.status = status;
    },
    write(packet) {
      packets.push(packet);
    }
  };
  handleEvents(streamRequest, streamResponse);

  assert.equal(streamResponse.status, 200);
  const snapshot = parseSse(packets[0]);
  assert.equal(snapshot.event, 'snapshot');

  const changed = await requestApi('POST', '/api/mode', {
    body: { mode: 'jwt' }
  });
  assert.equal(changed.status, 200);
  assert.equal(changed.json.mode, 'jwt');

  const reset = await requestApi('POST', '/api/reset');
  assert.equal(reset.status, 200);
  assert.deepEqual(reset.json.events, []);

  streamRequest.emit('close');
});

test('JWT flow with standard jsonwebtoken library: creates token, denies USER role, allows forged alg:none ADMIN', async () => {
  await requestApi('POST', '/api/mode', { body: { mode: 'jwt' } });

  // 1. Generate token
  const gen = await requestApi('POST', '/api/auth/generate', {
    body: { name: 'Budi Santoso' }
  });
  assert.equal(gen.status, 200);
  assert.equal(gen.json.mode, 'jwt');
  assert.ok(gen.json.token);

  // 2. Normal USER token gets DENIED access to vault
  const accessUser = await requestApi('POST', '/api/vault/access', {
    headers: { authorization: `Bearer ${gen.json.token}` }
  });
  assert.equal(accessUser.status, 403);
  assert.equal(accessUser.json.status, 'DENIED');

  // 3. Forged JWT with alg:none and role ADMIN succeeds (demonstrates vulnerability)
  const headerB64 = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payloadB64 = Buffer.from(JSON.stringify({ name: 'Hacker', role: 'ADMIN' })).toString('base64url');
  const forgedToken = `${headerB64}.${payloadB64}.`;

  const accessAdmin = await requestApi('POST', '/api/vault/access', {
    headers: { authorization: `Bearer ${forgedToken}` }
  });
  assert.equal(accessAdmin.status, 200);
  assert.equal(accessAdmin.json.status, 'HACKED');
});

test('PASETO flow with standard paseto library: creates AEAD v3.local token, denies USER, blocks tampered token', async () => {
  await requestApi('POST', '/api/mode', { body: { mode: 'paseto' } });

  // 1. Generate PASETO token
  const gen = await requestApi('POST', '/api/auth/generate', {
    body: { name: 'Citra Dewi' }
  });
  assert.equal(gen.status, 200);
  assert.equal(gen.json.mode, 'paseto');
  assert.ok(gen.json.token.startsWith('v3.local.'));

  // 2. Normal USER PASETO token gets DENIED (role USER)
  const accessUser = await requestApi('POST', '/api/vault/access', {
    headers: { authorization: `Bearer ${gen.json.token}` }
  });
  assert.equal(accessUser.status, 403);
  assert.equal(accessUser.json.status, 'DENIED');

  // 3. Tampered PASETO token (1 character changed) gets BLOCKED
  const originalToken = gen.json.token;
  const lastChar = originalToken.slice(-1);
  const tamperedToken = originalToken.slice(0, -1) + (lastChar === 'A' ? 'B' : 'A');

  const accessTampered = await requestApi('POST', '/api/vault/access', {
    headers: { authorization: `Bearer ${tamperedToken}` }
  });
  assert.equal(accessTampered.status, 401);
  assert.equal(accessTampered.json.status, 'BLOCKED');
});

test('Benchmark API returns accurate performance metrics and size breakdowns', async () => {
  // GET benchmark
  const getRes = await requestApi('GET', '/api/benchmark?iterations=50&preset=minimal');
  assert.equal(getRes.status, 200);
  assert.ok(getRes.json.ok);
  assert.ok(getRes.json.results.jwtHs);
  assert.ok(getRes.json.results.pasetoLoc);
  assert.ok(getRes.json.results.pasetoPub);

  // Validate stats structure
  assert.ok(getRes.json.results.jwtHs.performance.sign.opsSec > 0);
  assert.ok(getRes.json.results.pasetoLoc.performance.encrypt.opsSec > 0);
  assert.ok(getRes.json.results.jwtHs.structureBreakdown.headerBytes > 0);
  assert.ok(getRes.json.results.pasetoLoc.structureBreakdown.signatureBytes === 48);

  // POST benchmark with custom payload
  const postRes = await requestApi('POST', '/api/benchmark', {
    body: {
      iterations: 30,
      preset: 'custom',
      customPayload: { test: 'value', number: 12345 }
    }
  });
  assert.equal(postRes.status, 200);
  assert.ok(postRes.json.ok);
  assert.equal(postRes.json.benchmarkMeta.iterations, 30);
});
