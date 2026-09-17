import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { installDistribution, checkQualification } from '../install.mjs';

test('qualification check never downloads the package or invokes installation', async () => {
  const calls = [];
  const result = await checkQualification({ requestCore: async (name, args) => {
    calls.push(name);
    assert.deepEqual(args, {});
    return { ready: true };
  } });
  assert.deepEqual(calls, ['system.ready']);
  assert.equal(result.productAuthorized, true);
  assert.equal(result.installed, false);
  assert.equal(result.businessExecuted, false);
  await assert.rejects(checkQualification({ requestCore: async () => ({ ready: false }) }), /CORE_RESPONSE_INVALID/);
  await assert.rejects(checkQualification({ requestCore: async () => { throw new Error('ERP_NOT_ALLOWED'); } }), /ERP_NOT_ALLOWED/);
});

function fixture(context) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'gated-install-'));
  assert.equal(path.dirname(root), path.resolve(os.tmpdir()));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  return { root, home: path.join(root, 'not-created') };
}

test('ERP denial occurs before creating files or invoking Codex installation', async context => {
  const { home } = fixture(context);
  let commands = 0;
  await assert.rejects(installDistribution({ home, requestCore: async () => { throw new Error('ERP_NOT_ALLOWED'); }, runCodex: async () => { commands += 1; } }), /ERP_NOT_ALLOWED/);
  assert.equal(existsSync(home), false);
  assert.equal(commands, 0);
});

test('tampered packages and unsafe paths never reach Codex installation', async context => {
  const { home } = fixture(context);
  let commands = 0;
  const bytes = Buffer.from(JSON.stringify({ schemaVersion: 1, files: { '../escape': { content: '', sha256: createHash('sha256').update('').digest('hex') } } }));
  const manifest = { product: 'jingmai-ops-assistant', coreVersion: '2026.09.17.1', pluginVersion: '0.4.0', packageSha256: createHash('sha256').update(bytes).digest('hex'), packageBytes: bytes.length,
    installationRequiresErp: true, authorizationScope: 'whole-plugin' };
  const requestCore = async name => name === 'distribution.manifest' ? manifest : { packageSha256: manifest.packageSha256, content: bytes.toString('base64') };
  await assert.rejects(installDistribution({ home, requestCore, runCodex: async () => { commands += 1; } }), /UNSAFE_PACKAGE_PATH/);
  assert.equal(existsSync(home), false);
  assert.equal(commands, 0);
});

function authorizedFixture() {
  const hash = content => createHash('sha256').update(content).digest('hex');
  const files = Object.fromEntries(['.agents/plugins/marketplace.json', 'plugins/jingmai-ops-assistant/.codex-plugin/plugin.json'].map(name => [name, { content: Buffer.from('{}').toString('base64'), sha256: hash('{}') }]));
  const bytes = gzipSync(Buffer.from(JSON.stringify({ schemaVersion: 1, files })));
  const manifest = { product: 'jingmai-ops-assistant', coreVersion: '2026.09.17.1', pluginVersion: '0.4.0', packageEncoding: 'gzip', packageBytes: bytes.length, packageSha256: hash(bytes), installationRequiresErp: true, authorizationScope: 'whole-plugin' };
  const requestCore = async name => name === 'distribution.manifest' ? manifest : { pluginVersion: manifest.pluginVersion, packageSha256: manifest.packageSha256, content: bytes.toString('base64') };
  return { manifest, requestCore };
}

test('authorized compressed install is repeatable and preserves changed local files', async context => {
  const { home } = fixture(context);
  const { requestCore } = authorizedFixture();
  const commands = [];
  const runCodex = async args => { commands.push(args); return args[2] === 'list' ? { marketplaces: [] } : { installedPath: 'fixture-only' }; };
  const result = await installDistribution({ home, requestCore, runCodex });
  assert.equal(result.version, '0.4.0');
  assert.equal(commands.length, 3);
  await installDistribution({ home, requestCore, runCodex });
  const filename = path.join(result.directory, '.agents/plugins/marketplace.json');
  writeFileSync(filename, 'local edits');
  await assert.rejects(installDistribution({ home, requestCore, runCodex }), /LOCAL_MODIFICATION_PRESERVED/);
  assert.equal(readFileSync(filename, 'utf8'), 'local edits');
  assert.equal(commands.length, 6);
});

test('upgrade switches only the owned versioned marketplace and preserves its old directory', async context => {
  const { home } = fixture(context);
  const previous = path.join(home, 'distributions', '0.3.9-' + 'b'.repeat(12));
  const plugin = path.join(previous, 'plugins/jingmai-ops-assistant');
  mkdirSync(plugin, { recursive: true });
  writeFileSync(path.join(plugin, 'fixture.txt'), 'preserved');
  writeFileSync(path.join(plugin, 'INVENTORY.json'), JSON.stringify({ 'fixture.txt': createHash('sha256').update('preserved').digest('hex') }));
  const commands = [];
  const runCodex = async args => { commands.push(args); return args[2] === 'list' ? { marketplaces: [{ name: 'jingmai-caixiao', root: previous }] } : { installedPath: 'fixture-only' }; };
  await installDistribution({ home, ...authorizedFixture(), runCodex });
  assert.equal(commands[1].join(' '), 'plugin marketplace remove jingmai-caixiao');
  assert.equal(readFileSync(path.join(plugin, 'fixture.txt'), 'utf8'), 'preserved');
  const unrelated = async args => args[2] === 'list' ? { marketplaces: [{ name: 'jingmai-caixiao', root: path.dirname(home) }] } : assert.fail('no changes');
  await assert.rejects(installDistribution({ home, ...authorizedFixture(), runCodex: unrelated }), /MARKETPLACE_SOURCE_CONFLICT/);
});

test('wrong product and revoked authorization fail before file creation', async context => {
  const { home } = fixture(context);
  const { manifest, requestCore } = authorizedFixture();
  const runCodex = async () => assert.fail('must not install');
  await assert.rejects(installDistribution({ home, requestCore: async () => ({ ...manifest, product: 'other' }), runCodex }), /INVALID_DISTRIBUTION/);
  let checks = 0;
  await assert.rejects(installDistribution({ home, requestCore: async (name, args) => {
    if (name === 'distribution.manifest' && ++checks === 2) throw new Error('ERP_NOT_ALLOWED');
    return requestCore(name, args);
  }, runCodex }), /ERP_NOT_ALLOWED/);
  assert.equal(existsSync(home), false);
});
