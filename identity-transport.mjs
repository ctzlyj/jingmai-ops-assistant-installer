import { request } from 'node:http';

export const IDENTITY_PORTS = Object.freeze(Array.from({ length: 10 }, (_, index) => 8988 + index * 2));

export async function requestLocalIdentity(target, { body, headers, signal = AbortSignal.timeout(5000), method } = {}) {
  const url = new URL(target);
  if (url.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(url.hostname)
    || !IDENTITY_PORTS.includes(Number(url.port)) || url.pathname !== '/hioffice'
    || url.username || url.password || method !== 'POST' || typeof body !== 'string'
    || Buffer.byteLength(body) > 65536) throw new Error('LOCAL_TARGET_INVALID');
  return new Promise((resolve, reject) => {
    const pending = request(url, { method, headers, signal, agent: false, maxHeaderSize: 8192 }, response => {
      const chunks = [];
      let size = 0;
      response.on('data', chunk => {
        size += chunk.length;
        if (size > 65536) {
          pending.destroy(Object.assign(new Error('LOCAL_RESPONSE_TOO_LARGE'), { code: 'LOCAL_RESPONSE_TOO_LARGE' }));
          return;
        }
        chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('end', () => {
        if (!response.complete || size > 65536) {
          reject(Object.assign(new Error('LOCAL_RESPONSE_INVALID'), { code: 'LOCAL_RESPONSE_INVALID' }));
          return;
        }
        const key = response.headers['x-aes-key'];
        resolve(new Response([204, 205, 304].includes(response.statusCode) ? null : Buffer.concat(chunks), {
          status: response.statusCode, headers: typeof key === 'string' ? { 'X-AES-Key': key } : {},
        }));
      });
    });
    pending.on('error', reject);
    pending.end(body);
  });
}
