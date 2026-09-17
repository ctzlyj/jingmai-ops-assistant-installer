import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('.', import.meta.url));
const manifest = JSON.parse(readFileSync(path.join(root, 'BOOTSTRAP_FILES.json'), 'utf8'));
for (const [relative, expected] of Object.entries(manifest)) {
  if (relative.includes('..') || relative.includes('\\') || path.isAbsolute(relative)) throw new Error('UNSAFE_MANIFEST');
  if (createHash('sha256').update(readFileSync(path.join(root, relative))).digest('hex') !== expected) throw new Error('BOOTSTRAP_HASH_MISMATCH');
}
if (readdirSync(root).some(name => ['plugins', '.agents', 'skills', 'jingmai-private', 'private-core'].includes(name))) throw new Error('COMPLETE_PLUGIN_MUST_NOT_BE_PUBLIC');
console.log(JSON.stringify({ ok: true, files: Object.keys(manifest).length, containsInstallablePlugin: false }));
