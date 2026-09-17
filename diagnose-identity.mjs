import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyIdentity, identityFailure } from './identity.mjs';

export async function diagnoseIdentity({ verify = verifyIdentity } = {}) {
  try {
    const result = await verify({ timeoutMs: 60_000 });
    if (result?.authenticated !== true) throw new Error('ERP_AUTH_INVALID');
    return { ok: true, identityVerified: true, productAuthorizationChecked: false, installed: false, businessExecuted: false };
  } catch (error) {
    return { ...identityFailure(error), identityVerified: false, productAuthorizationChecked: false, installed: false, businessExecuted: false };
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await diagnoseIdentity();
  console.log(JSON.stringify(result));
  process.exitCode = result.ok ? 0 : 1;
}
