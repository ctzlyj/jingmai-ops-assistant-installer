import assert from 'node:assert/strict';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import * as identity from '../identity.mjs';
import { diagnoseIdentity } from '../diagnose-identity.mjs';

test('identity failures keep local recovery with Codex; only product qualification routes to owner', () => {
  for (const code of ['ERP_HIOFFICE_UNREACHABLE', 'ERP_HIOFFICE_TIMEOUT', 'ERP_HIOFFICE_ACCESS_DENIED',
    'ERP_HIOFFICE_PROTOCOL_ERROR', 'ERP_TOKEN_EXCHANGE_FAILED', 'ERP_IDENTITY_REJECTED',
    'ERP_AUTH_RESPONSE_INVALID', 'ERP_AUTH_TIMEOUT', 'ERP_AUTH_UNAVAILABLE', 'ERP_NOT_LOGGED_IN', 'ERP_AUTH_INVALID']) {
    const report = identity.identityFailure(new Error(code));
    assert.equal(report.code, code);
    assert.equal(report.ok, false);
    assert.equal(report.recovery.owner, 'codex');
    assert.match(report.message, /Codex/);
    assert.doesNotMatch(report.message, /交IT|由IT|交维护人|联系维护人/);
  }
  const qualification = identity.identityFailure(new Error('ERP_NOT_ALLOWED'));
  assert.equal(qualification.recovery.owner, 'caotong.888');
  assert.equal(qualification.recovery.reason, 'product-qualification');
  assert.match(qualification.message, /caotong\.888/);
});

function fixture(local, exchange = { code: 0, data: { accessToken: 'synthetic-ticket' } }, verified = { IsSuccess: true, Data: { pin: 'fixture.user' } }) {
  const calls = [];
  const fetchImpl = async (target, options) => {
    const url = new URL(target);
    calls.push(url.hostname === '127.0.0.1' ? Number(url.port) : url.searchParams.get('functionId') || 'verify');
    if (url.hostname === '127.0.0.1') return local(url, options);
    if (url.searchParams.get('functionId') === 'desk.agent.auth.encrypt') return Response.json({ code: 0, data: { aesKey: 'synthetic-key', content: 'synthetic-encrypted-request' } });
    if (url.searchParams.get('functionId') === 'desk.agent.auth.getWebToken') return Response.json(exchange);
    if (url.pathname === '/api') return Response.json(verified);
    throw new Error('UNEXPECTED_TARGET');
  };
  return { calls, fetchImpl };
}

const connected = () => new Response('synthetic-local-token', { headers: { 'X-AES-Key': 'synthetic-response-key' } });
const refused = () => { throw Object.assign(new TypeError('synthetic sensitive transport details'), { cause: { code: 'ECONNREFUSED' } }); };

for (const [name, local, code] of [
  ['refused connections are not a login assertion', refused, 'ERP_HIOFFICE_UNREACHABLE'],
  ['local timeouts are distinguished', () => { throw new DOMException('synthetic', 'TimeoutError'); }, 'ERP_HIOFFICE_TIMEOUT'],
  ['permission failures remain blocked', () => { throw Object.assign(new Error('synthetic'), { cause: { code: 'EACCES' } }); }, 'ERP_HIOFFICE_ACCESS_DENIED'],
  ['HTTP denial is not silently ignored', () => new Response('', { status: 403 }), 'ERP_HIOFFICE_ACCESS_DENIED'],
  ['missing protocol header is distinguished', () => new Response('synthetic body'), 'ERP_HIOFFICE_PROTOCOL_ERROR'],
  ['empty local ticket is not accepted', () => new Response('', { headers: { 'X-AES-Key': 'synthetic' } }), 'ERP_HIOFFICE_PROTOCOL_ERROR'],
]) {
  test(name, async () => {
    const probe = fixture(local);
    let authorizationCalls = 0;
    await assert.rejects(identity.verifyIdentity({ fetchImpl: probe.fetchImpl, authorize: async () => { authorizationCalls += 1; } }), error => {
      assert.equal(error.code, code);
      assert.equal(error.stage, 'hioffice');
      const report = identity.identityFailure(error);
      assert.equal(report.diagnostics.ports.length, 10);
      assert.doesNotMatch(JSON.stringify(report), /synthetic|cookie|aesKey|accessToken/i);
      return true;
    });
    assert.equal(authorizationCalls, 0);
    assert.equal(probe.calls.filter(item => item === 'desk.agent.auth.getWebToken').length, 0);
  });
}

test('logged-in client taking longer than 1.2 seconds succeeds without grants', async () => {
  const probe = fixture(async (url, options) => {
    if (url.port !== '9006') return refused();
    await delay(1500, undefined, { signal: options.signal });
    return connected();
  });
  let authorizations = 0;
  const result = await identity.verifyIdentity({ fetchImpl: probe.fetchImpl, authorize: async ({ erp, ticket }) => {
    authorizations += 1;
    assert.equal(erp, 'fixture.user');
    assert.equal(ticket, 'synthetic-ticket');
    return { ok: true };
  } });
  assert.deepEqual(result, { ok: true });
  assert.equal(authorizations, 1);
  assert.deepEqual(probe.calls.filter(item => typeof item === 'number').sort((left, right) => left - right), Array.from({ length: 10 }, (_, index) => 8988 + index * 2));
});

test('exchange rejection is not labelled not logged in or allowed through', async () => {
  const probe = fixture(connected, { code: 9, msg: 'synthetic-secret-do-not-report' });
  await assert.rejects(identity.verifyIdentity({ fetchImpl: probe.fetchImpl }), error => {
    assert.equal(error.code, 'ERP_TOKEN_EXCHANGE_FAILED');
    assert.equal(error.stage, 'token_exchange');
    assert.doesNotMatch(JSON.stringify(identity.identityFailure(error)), /synthetic-secret/);
    return true;
  });
});

test('identity rejection and malformed responses remain distinct', async () => {
  for (const [response, code] of [[{ IsSuccess: false }, 'ERP_IDENTITY_REJECTED'], [{ IsSuccess: true, Data: {} }, 'ERP_AUTH_RESPONSE_INVALID']]) {
    const probe = fixture(connected, undefined, response);
    await assert.rejects(identity.verifyIdentity({ fetchImpl: probe.fetchImpl }), error => error.code === code && error.stage === 'identity');
  }
});

test('global deadline bounds stalled local requests', async () => {
  const probe = fixture(async (url, options) => { await delay(1000, undefined, { signal: options.signal }); return connected(); });
  await assert.rejects(identity.verifyIdentity({ fetchImpl: probe.fetchImpl, timeoutMs: 30 }), error => error.code === 'ERP_AUTH_TIMEOUT');
});

test('product authorization denial is preserved and not retried', async () => {
  const probe = fixture(connected);
  let calls = 0;
  await assert.rejects(identity.verifyIdentity({ fetchImpl: probe.fetchImpl, authorize: async () => { calls += 1; throw Object.assign(new Error('ERP_NOT_ALLOWED'), { code: 'ERP_NOT_ALLOWED' }); } }), error => error.code === 'ERP_NOT_ALLOWED' && error.stage === 'authorization');
  assert.equal(calls, 1);
});

test('untrusted error fields never reach diagnostic output', () => {
  const result = identity.identityFailure(Object.assign(new Error('synthetic-secret'), { stage: 'synthetic-secret', diagnostics: { cookie: 'synthetic-secret' } }));
  assert.equal(result.ok, false);
  assert.doesNotMatch(JSON.stringify(result), /synthetic-secret|cookie/i);
});

test('diagnosis does not disclose identity or claim installation or product grants', async () => {
  const result = await diagnoseIdentity({ verify: async options => {
    assert.equal(options.authorize, undefined);
    return { authenticated: true, erp: 'synthetic-private-identity', ticket: 'synthetic-private-ticket' };
  } });
  assert.equal(result.identityVerified, true);
  assert.equal(result.productAuthorizationChecked, false);
  assert.equal(result.installed, false);
  assert.doesNotMatch(JSON.stringify(result), /synthetic-private/);
  const failed = await diagnoseIdentity({ verify: async () => { throw new Error('synthetic-private-ticket'); } });
  assert.equal(failed.ok, false);
  assert.doesNotMatch(JSON.stringify(failed), /synthetic-private/);
});
