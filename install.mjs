import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');

function safePath(relative) {
  if (typeof relative !== 'string' || relative.includes('\\') || relative.includes(':') || path.isAbsolute(relative)
    || relative.split('/').some(part => !part || part === '.' || part === '..' || /^(?:\.git|credentials|private-core|jingmai-private|node_modules)$/i.test(part))) throw new Error('UNSAFE_PACKAGE_PATH');
}

function rejectSymlinks(filename) {
  let current = path.resolve(filename);
  while (current !== path.dirname(current)) {
    if (existsSync(current) && lstatSync(current).isSymbolicLink()) throw new Error('UNSAFE_INSTALL_PATH');
    current = path.dirname(current);
  }
}

export async function installDistribution({ home, requestCore, runCodex }) {
  const manifest = await requestCore('distribution.manifest', {});
  if (manifest.product !== 'jingmai-ops-assistant' || manifest.coreVersion !== '2026.09.17.1'
    || !/^\d+\.\d+\.\d+$/.test(manifest.pluginVersion || '') || manifest.installationRequiresErp !== true
    || manifest.authorizationScope !== 'whole-plugin' || !/^[a-f0-9]{64}$/.test(manifest.packageSha256 || '')) throw new Error('INVALID_DISTRIBUTION');
  const response = await requestCore('distribution.package', { pluginVersion: manifest.pluginVersion, packageSha256: manifest.packageSha256 });
  const bytes = Buffer.from(response.content || '', 'base64');
  if (bytes.length > 2_900_000 || bytes.length !== manifest.packageBytes || response.packageSha256 !== manifest.packageSha256 || digest(bytes) !== manifest.packageSha256) throw new Error('PACKAGE_HASH_MISMATCH');
  if (manifest.packageEncoding && manifest.packageEncoding !== 'gzip') throw new Error('INVALID_DISTRIBUTION');
  const decoded = manifest.packageEncoding === 'gzip' ? gunzipSync(bytes, { maxOutputLength: 16_000_000 }) : bytes;
  const artifact = JSON.parse(decoded.toString('utf8'));
  if (artifact.schemaVersion !== 1 || !artifact.files || Array.isArray(artifact.files)) throw new Error('INVALID_PACKAGE');
  const files = Object.entries(artifact.files).map(([relative, record]) => {
    safePath(relative);
    const content = Buffer.from(record.content || '', 'base64');
    if (digest(content) !== record.sha256) throw new Error('PACKAGE_HASH_MISMATCH');
    return { relative, content, sha256: record.sha256 };
  });
  if (!files.some(file => file.relative === '.agents/plugins/marketplace.json') || !files.some(file => file.relative === 'plugins/jingmai-ops-assistant/.codex-plugin/plugin.json')) throw new Error('INVALID_PACKAGE');
  const directory = path.resolve(home, 'distributions', manifest.pluginVersion + '-' + manifest.packageSha256.slice(0, 12));
  rejectSymlinks(directory);
  for (const file of files) {
    const filename = path.join(directory, file.relative);
    rejectSymlinks(filename);
    if (existsSync(filename) && digest(readFileSync(filename)) !== file.sha256) throw new Error('LOCAL_MODIFICATION_PRESERVED');
  }
  const current = await requestCore('distribution.manifest', {});
  if (JSON.stringify(current) !== JSON.stringify(manifest)) throw new Error('DISTRIBUTION_CHANGED');
  for (const file of files) {
    const filename = path.join(directory, file.relative);
    if (!existsSync(filename)) {
      mkdirSync(path.dirname(filename), { recursive: true });
      writeFileSync(filename, file.content, { flag: 'wx' });
    }
    if (digest(readFileSync(filename)) !== file.sha256) throw new Error('INSTALLATION_VERIFY_FAILED');
  }
  await runCodex(['plugin', 'marketplace', 'add', directory]);
  const installed = await runCodex(['plugin', 'add', 'jingmai-ops-assistant@jingmai-caixiao']);
  return { ok: true, version: manifest.pluginVersion, directory, installedPath: installed.installedPath,
    authorizationScope: 'whole-plugin', businessExecuted: false };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { requestCore } = await import('./rpc-client.mjs');
    const args = process.argv.slice(2);
    if (args.length && (args.length !== 2 || args[0] !== '--home')) throw new Error('INVALID_ARGUMENTS');
    const result = await installDistribution({ home: args[1] || path.join(os.homedir(), '.jingmai-ops-assistant'), requestCore,
      runCodex: async argumentsList => {
        const result = spawnSync('codex', [...argumentsList, '--json'], { encoding: 'utf8', shell: false, windowsHide: true, timeout: 120_000 });
        if (result.error || result.status !== 0) throw new Error('CODEX_INSTALL_FAILED');
        return JSON.parse(result.stdout);
      } });
    console.log(JSON.stringify(result));
  } catch (error) {
    console.log(JSON.stringify({ ok: false, code: /^[A-Z_]{1,64}$/.test(error.message) ? error.message : 'INSTALLATION_STOPPED' }));
    process.exitCode = 1;
  }
}
