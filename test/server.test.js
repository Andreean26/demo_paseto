'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const test = require('node:test');

process.env.PRESENTER_KEY = 'test-presenter-key';
const { handleApi, handleEvents } = require('../server');

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

test('only the presenter can change mode and audience clients receive the change over SSE', async () => {
  const unauthorized = await requestApi('POST', '/api/mode', {
    body: { mode: 'paseto' },
    headers: { 'content-type': 'application/json' }
  });
  assert.equal(unauthorized.status, 403);

  const wrongKey = await requestApi('POST', '/api/mode', {
    body: { mode: 'paseto' },
    headers: {
      'content-type': 'application/json',
      'x-presenter-key': 'audience-key'
    }
  });
  assert.equal(wrongKey.status, 403);

  const unauthorizedReset = await requestApi('POST', '/api/reset');
  assert.equal(unauthorizedReset.status, 403);

  const unchangedState = await requestApi('GET', '/api/state');
  assert.equal(unchangedState.json.mode, 'jwt');

  const invalidMode = await requestApi('POST', '/api/mode', {
    body: { mode: 'unknown' },
    headers: {
      'content-type': 'application/json',
      'x-presenter-key': 'test-presenter-key'
    }
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
  assert.equal(snapshot.data.mode, 'jwt');

  const changed = await requestApi('POST', '/api/mode', {
    body: { mode: 'paseto' },
    headers: {
      'content-type': 'application/json',
      'x-presenter-key': 'test-presenter-key'
    }
  });
  assert.equal(changed.status, 200);
  assert.equal(changed.json.mode, 'paseto');

  const modeEvent = parseSse(packets[1]);
  assert.equal(modeEvent.event, 'mode');
  assert.equal(modeEvent.data.mode, 'paseto');

  const changedState = await requestApi('GET', '/api/state');
  assert.equal(changedState.json.mode, 'paseto');
  streamRequest.emit('close');
});
