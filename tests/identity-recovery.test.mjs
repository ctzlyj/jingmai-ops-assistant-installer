import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import test from 'node:test';
import { verifyIdentity, identityFailure } from '../identity.mjs';
import { inspectIdentityEnvironment, enrichIdentityFailure } from '../identity-environment.mjs';
import { requestLocalIdentity } from '../identity-transport.mjs';
import { installerFailure } from '../install.mjs';

const refused = () => { throw Object.assign(new Error('private transport message'), { cause: { code: 'ECONNREFUSED' } }); };
const connected = () => new Response('synthetic-token', { headers: { 'X-AES-Key': 'synthetic-key' } });
function gateway() {
  const calls = [];
  return { calls, fetchImpl: async target => {
    const url = new URL(target);
    const operation = url.searchParams.get('functionId') || 'verify';
    calls.push(operation);
    if (operation === 'desk.agent.auth.encrypt') return Response.json({ code: 0, data: { aesKey: 'synthetic', content: 'synthetic' } });
    if (operation === 'desk.agent.auth.getWebToken') return Response.json({ code: 0, data: { accessToken: 'synthetic' } });
    if (operation === 'verify') return Response.json({ IsSuccess: true, Data: { pin: 'fixture.user' } });
    assert.fail('unexpected gateway');
  } };
}

test('IPv6-only local identity recovers without a new port or skipping server verification', async () => {
  const remote = gateway();
  const endpoints = [];
  const result = await verifyIdentity({ ...remote, retryDelayMs: 1, localFetchImpl: async target => {
    const url = new URL(target);
    endpoints.push(url);
    return url.hostname === '[::1]' && url.port === '9006' ? connected() : refused();
  } });
  assert.equal(result.authenticated, true);
  assert.ok(endpoints.some(url => url.hostname === '[::1]'));
  assert.ok(endpoints.every(url => Number(url.port) >= 8988 && Number(url.port) <= 9006 && Number(url.port) % 2 === 0));
  assert.deepEqual(remote.calls, ['desk.agent.auth.encrypt', 'desk.agent.auth.getWebToken', 'verify']);
});

test('startup race gets one bounded retry and product authorization happens only once', async () => {
  const remote = gateway();
  let candidateAttempts = 0;
  let authorizations = 0;
  await verifyIdentity({ ...remote, retryDelayMs: 1, localFetchImpl: async target => {
    const url = new URL(target);
    if (url.hostname === '127.0.0.1' && url.port === '8988' && ++candidateAttempts === 2) return connected();
    return refused();
  }, authorize: async () => { authorizations += 1; return { authenticated: true }; } });
  assert.equal(candidateAttempts, 2);
  assert.equal(authorizations, 1);
});

test('exhausted recovery retains sanitized per-attempt evidence, never requests qualification', async () => {
  const remote = gateway();
  await assert.rejects(verifyIdentity({ ...remote, retryDelayMs: 1, localFetchImpl: refused }), error => {
    const report = identityFailure(error);
    assert.equal(report.code, 'ERP_HIOFFICE_UNREACHABLE');
    assert.equal(report.diagnostics.ports.length, 40);
    assert.equal(report.recovery.owner, 'codex');
    assert.doesNotMatch(JSON.stringify(report), /private transport|synthetic-token|synthetic-key/);
    return true;
  });
  assert.deepEqual(remote.calls, ['desk.agent.auth.encrypt']);
});

test('denied access and incompatible responses do not trigger blind retries', async () => {
  for (const status of [403, 200]) {
    let attempts = 0;
    await assert.rejects(verifyIdentity({ ...gateway(), retryDelayMs: 1, localFetchImpl: async () => {
      attempts += 1;
      return new Response('private body', { status });
    } }));
    assert.equal(attempts, 10);
  }
});

test('qualification denial is not retried or converted to local environment failure', async () => {
  let authorizations = 0;
  await assert.rejects(verifyIdentity({ ...gateway(), localFetchImpl: connected, authorize: async () => {
    authorizations += 1;
    throw new Error('ERP_NOT_ALLOWED');
  } }), error => identityFailure(error).code === 'ERP_NOT_ALLOWED');
  assert.equal(authorizations, 1);
});

test('environment probes disclose only allowlisted facts and do not treat process names as identity', async () => {
  const report = await inspectIdentityEnvironment({ platform: 'win32', nodeVersion: '24.18.0', env: { SSH_CONNECTION: 'private-host', HTTP_PROXY: 'private-secret' }, collectWindows: async () => ({
    inspected: true, clientProcessCount: 1, identityHostProcessCount: 1, sameUserProcessCount: 0, otherUserProcessCount: 1,
    listeners: [{ port: 8988, recognizedClient: true, sameUser: false, sameSession: false, pid: 123, secret: 'private-secret' }, { port: 18988 }],
    username: 'private-user', ticket: 'private-ticket',
  }) });
  assert.equal(report.remoteSession, true);
  assert.equal(report.windows.otherUserProcessCount, 1);
  assert.equal(report.windows.identityHostProcessCount, 1);
  assert.equal(report.windows.listeners.length, 1);
  assert.doesNotMatch(JSON.stringify(report), /private-|18988|username|ticket|pid/);
});

test('WSL and failed process inspection produce concrete Codex actions, not maintenance escalation', async () => {
  const environment = await inspectIdentityEnvironment({ platform: 'linux', nodeVersion: '24.18.0', env: { WSL_DISTRO_NAME: 'private-distro' } });
  const report = await enrichIdentityFailure(new Error('ERP_HIOFFICE_UNREACHABLE'), { inspect: async () => environment });
  assert.equal(report.recovery.owner, 'codex');
  assert.ok(report.recovery.actions.some(action => action.id === 'use-desktop-execution-context'));
  assert.equal(report.loginState, 'unknown');
  assert.equal(report.productAuthorizationChecked, false);
  assert.equal(report.recovery.maintenanceNeed, 'not-established');
  const failed = await inspectIdentityEnvironment({ platform: 'win32', env: {}, collectWindows: async () => { throw new Error('private-secret'); } });
  assert.equal(failed.windows.inspected, false);
  assert.doesNotMatch(JSON.stringify(failed), /private-secret/);
});

test('installer failure includes environment evidence without rerunning identity or business', async () => {
  const report = await installerFailure(new Error('ERP_HIOFFICE_UNREACHABLE'), { reportIdentityFailure: enrichIdentityFailure, inspect: async () => ({ platform: 'win32', windows: { inspected: true, clientProcessCount: 1, listeners: [] } }) });
  assert.equal(report.recovery.owner, 'codex');
  assert.ok(report.recovery.actions.some(action => action.id === 'inspect-client-interface'));
  assert.equal(report.installed, false);
  assert.equal(report.businessExecuted, false);
  const qualification = await installerFailure(new Error('ERP_NOT_ALLOWED'), { reportIdentityFailure: enrichIdentityFailure, inspect: async () => assert.fail('no local inspection for product denial') });
  assert.equal(qualification.recovery.owner, 'caotong.888');
});

test('runtime transport failures are not falsely classified as unreachable or logged out', async () => {
  await assert.rejects(verifyIdentity({ ...gateway(), localFetchImpl: async () => { throw new Error('private runtime error'); } }), error => {
    const report = identityFailure(error);
    assert.equal(report.code, 'ERP_HIOFFICE_TRANSPORT_ERROR');
    assert.doesNotMatch(JSON.stringify(report), /private runtime/);
    return true;
  });
});

test('total deadline also bounds retry delay and retains the failed endpoint evidence', async () => {
  await assert.rejects(verifyIdentity({ ...gateway(), timeoutMs: 40, retryDelayMs: 5000, localFetchImpl: refused }), error => {
    const report = identityFailure(error);
    assert.equal(report.code, 'ERP_AUTH_TIMEOUT');
    assert.equal(report.stage, 'hioffice');
    assert.equal(report.diagnostics.ports.length, 20);
    return true;
  });
});

test('native loopback transport ignores proxy routing, limits response size and never follows redirects', async context => {
  const server = createServer((request, response) => {
    const mode = request.headers['x-fixture-mode'];
    if (mode === 'stall') return;
    if (mode === 'redirect') { response.writeHead(302, { Location: 'http://example.invalid/private-token' }); response.end(); return; }
    response.setHeader('X-AES-Key', mode === 'large-header' ? 'x'.repeat(10000) : 'synthetic-key');
    response.end(mode === 'large' ? 'x'.repeat(65537) : 'synthetic-token');
  });
  let port;
  for (let candidate = 8988; candidate <= 9006; candidate += 2) {
    try {
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(candidate, '127.0.0.1', () => { server.removeListener('error', reject); resolve(); });
      });
      port = candidate;
      break;
    } catch (error) { if (error.code !== 'EADDRINUSE') throw error; }
  }
  assert.ok(port, 'fixture needs one unused official candidate port');
  context.after(() => { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); });
  const target = `http://127.0.0.1:${port}/hioffice?from=hio_plugin_joydesk`;
  const options = mode => ({ method: 'POST', headers: { 'X-Fixture-Mode': mode }, body: 'synthetic', signal: AbortSignal.timeout(2000) });
  assert.equal(await (await requestLocalIdentity(target, options('ok'))).text(), 'synthetic-token');
  assert.equal((await requestLocalIdentity(target, options('redirect'))).status, 302);
  await assert.rejects(requestLocalIdentity(target, options('large')), error => error.code === 'LOCAL_RESPONSE_TOO_LARGE');
  await assert.rejects(requestLocalIdentity(target, options('large-header')), error => error.code === 'HPE_HEADER_OVERFLOW');
  await assert.rejects(requestLocalIdentity(target, { ...options('stall'), signal: AbortSignal.timeout(50) }), error => error.name === 'AbortError');
  for (const invalid of ['http://example.invalid/hioffice', 'http://127.0.0.1:18988/hioffice', `http://127.0.0.1:${port}/other`]) {
    await assert.rejects(requestLocalIdentity(invalid, options('ok')), /LOCAL_TARGET_INVALID/);
  }
  const transport = new URL('../identity-transport.mjs', import.meta.url).href;
  const source = `import {requestLocalIdentity} from ${JSON.stringify(transport)}; const reply = await requestLocalIdentity(${JSON.stringify(target)}, {method:'POST',body:'synthetic'}); console.log(await reply.text());`;
  const child = await promisify(execFile)(process.execPath, ['--input-type=module', '-e', source], {
    windowsHide: true, timeout: 10000, env: { ...process.env, NODE_USE_ENV_PROXY: '1', HTTP_PROXY: 'http://127.0.0.1:1', HTTPS_PROXY: 'http://127.0.0.1:1', NO_PROXY: '' },
  });
  assert.equal(child.stdout.trim(), 'synthetic-token');
});
