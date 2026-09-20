import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyIdentity } from './identity.mjs';
import { enrichIdentityFailure } from './identity-environment.mjs';

export async function diagnoseIdentity({ verify = verifyIdentity, inspect } = {}) {
  try {
    const result = await verify({ timeoutMs: 60_000 });
    if (result?.authenticated !== true) throw new Error('ERP_AUTH_INVALID');
    return { ok: true, identityVerified: true, productAuthorizationChecked: false, installed: false, businessExecuted: false };
  } catch (error) {
    return { ...await enrichIdentityFailure(error, { inspect }), identityVerified: false, productAuthorizationChecked: false, installed: false, businessExecuted: false };
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await diagnoseIdentity();
  console.log(JSON.stringify(result));
  process.exitCode = result.ok ? 0 : 1;
}
