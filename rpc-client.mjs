import { randomUUID } from 'node:crypto';
import { verifyIdentity } from './identity.mjs';

const product = 'jingmai-ops-assistant';
const coreVersion = '2026.09.17.1';
const endpoint = 'https://material-auth.space.jd.com/__space/ssa-free/jingmai/v1/execute';

export async function requestCore(functionName, argumentsObject) {
  const input = { version: 1, product, coreVersion, operation: 'core-call', requestId: randomUUID(), payload: { function: functionName, arguments: argumentsObject } };
  let reply;
  await verifyIdentity({ timeoutMs: 60_000, authorize: async ({ ticket }) => {
    const response = await fetch(endpoint, { method: 'POST', redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(45_000),
      headers: { 'content-type': 'application/json', authorization: `Bearer ${ticket}` }, body: JSON.stringify(input) });
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > 5_000_000) throw new Error('CORE_RESPONSE_INVALID');
      chunks.push(chunk);
    }
    reply = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    return { authenticated: true };
  } });
  if (reply?.ok !== true) throw new Error(/^[A-Z_]{1,64}$/.test(reply?.code || '') ? reply.code : 'CORE_RESPONSE_INVALID');
  if (reply.version !== 1 || reply.product !== product || reply.requestId !== input.requestId || !/^[a-f0-9]{64}$/.test(reply.requestHash || '')
    || reply.result?.product !== product || reply.result.coreVersion !== coreVersion || reply.result.function !== functionName
    || !Object.hasOwn(reply.result, 'value')) throw new Error('CORE_RESPONSE_INVALID');
  return reply.result.value;
}
