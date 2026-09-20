import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { IDENTITY_PORTS as PORTS, requestLocalIdentity } from './identity-transport.mjs';

const GATEWAY = 'https://api.m.jd.com';
const CALLER = process.platform === 'darwin' ? 'hio_plugin_joydesk_Mac' : 'hio_plugin_joydesk';
const DETAILS = new WeakMap();
const MESSAGES = {
  ERP_HIOFFICE_UNREACHABLE: '未连接到本机京ME接口，不代表未登录。由当前 Codex 核对同机同用户、实际端口与执行环境，实施已授权修复并回查，不反复登录或关闭防护。',
  ERP_HIOFFICE_TIMEOUT: '本机京ME响应超时，不代表未登录。由当前 Codex 排查进程和响应耗时，按证据修复并回查，不反复安装。',
  ERP_HIOFFICE_ACCESS_DENIED: '本机接口访问被拒绝。由当前 Codex 核对实际进程身份及权限，带本人完成必要批准，不绕过公司策略。',
  ERP_HIOFFICE_PROTOCOL_ERROR: '本机身份响应协议异常。由当前 Codex 核对京ME版本、实际接口与官方兼容性，不把一次异常直接认定为发行缺陷。',
  ERP_HIOFFICE_TRANSPORT_ERROR: '本机身份请求发生未归类的运行时错误，不能据此断言京ME未登录或接口未启动。由当前 Codex 结合阶段、运行环境及官方协议继续诊断。',
  ERP_TOKEN_EXCHANGE_FAILED: '本机身份响应已取得，但换票失败。由当前 Codex 排查换票网络和有效期，修复后重新验权，不重复开白或盲目重装。',
  ERP_IDENTITY_REJECTED: '当前票据被拒绝，不是产品资格结论。由当前 Codex 核对当前本人会话和服务状态，必要时引导本人重新登录并回查，不输出票据。',
  ERP_AUTH_RESPONSE_INVALID: '身份响应格式异常，停止受保护操作。由当前 Codex 排查实际版本与协议，不输出响应正文或凭据。',
  ERP_AUTH_TIMEOUT: '身份校验达到总时限。由当前 Codex 按失败阶段排查网络或本机接口，不等于未登录。',
  ERP_AUTH_UNAVAILABLE: '身份服务请求失败。由当前 Codex 排查京东网络和失败阶段，修复后重新验权，不关闭验证或借用身份。',
  ERP_NOT_LOGGED_IN: '未取得有效身份，不能仅据此判断京ME未登录。由当前 Codex 先诊断本人本机环境，确需登录时引导本人完成并回查。',
  ERP_NOT_ALLOWED: '本人插件产品资格未通过，请联系负责人 ERP：caotong.888 核对资格，不借用账号或绕过门禁。',
  ERP_AUTH_INVALID: '身份响应校验失败，停止受保护操作。由当前 Codex 排查实际调用参数和执行环境，不以失败码代替根因。',
};

function failure(code, stage, ports) {
  const error = Object.assign(new Error(code), { code, stage });
  DETAILS.set(error, { stage, ...(ports ? { diagnostics: { ports } } : {}) });
  return error;
}

export function identityFailure(error) {
  const candidate = error?.code || error?.message;
  const code = Object.hasOwn(MESSAGES, candidate || '') ? candidate : 'ERP_AUTH_UNAVAILABLE';
  const recovery = code === 'ERP_NOT_ALLOWED'
    ? { owner: 'caotong.888', reason: 'product-qualification' }
    : { owner: 'codex', reason: 'diagnose-repair-recheck' };
  return { ok: false, code, ...(DETAILS.get(error) || {}), message: MESSAGES[code], recovery };
}

async function jsonResponse(response, stage) {
  try { return await response.json(); } catch { throw failure('ERP_AUTH_RESPONSE_INVALID', stage); }
}

export async function resolveErpFromTicket(ticket, { fetchImpl = fetch, signal = AbortSignal.timeout(10_000) } = {}) {
  if (typeof ticket !== 'string' || !ticket.trim() || ticket.length > 8192 || /[\r\n;]/.test(ticket)) throw failure('ERP_AUTH_RESPONSE_INVALID', 'identity');
  try {
    const functionId = 'joymail.authentication.publickey';
    const response = await fetchImpl(`${GATEWAY}/api`, {
      method: 'POST', redirect: 'error', signal,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: `me_token=${ticket.trim()};`, functionid: functionId, logintype: '15', referer: GATEWAY,
      },
      body: new URLSearchParams({ appid: 'joymail', body: '{}', functionId, lang: 'zh_CN', loginType: '15', cthr: '1', t: String(Date.now()), uuid: randomUUID().replaceAll('-', '').slice(0, 20) }),
    });
    if (!response.ok) throw failure(response.status === 401 || response.status === 403 ? 'ERP_IDENTITY_REJECTED' : 'ERP_AUTH_UNAVAILABLE', 'identity');
    const payload = await jsonResponse(response, 'identity');
    const erp = typeof payload?.Data?.pin === 'string' ? payload.Data.pin.trim().toLowerCase() : '';
    if (payload?.IsSuccess === false) throw failure('ERP_IDENTITY_REJECTED', 'identity');
    if (payload?.IsSuccess !== true || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(erp)) throw failure('ERP_AUTH_RESPONSE_INVALID', 'identity');
    return { authenticated: true, erp };
  } catch (error) {
    if (signal.aborted) throw failure('ERP_AUTH_TIMEOUT', 'identity');
    if (DETAILS.has(error)) throw error;
    throw failure('ERP_AUTH_UNAVAILABLE', 'identity');
  }
}

export async function verifyIdentity({ fetchImpl = fetch, localFetchImpl = fetchImpl === fetch ? requestLocalIdentity : fetchImpl, timeoutMs = 12_000, retryDelayMs = 750, authorize } = {}) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 120_000
    || !Number.isFinite(retryDelayMs) || retryDelayMs < 0 || retryDelayMs > 5000) throw failure('ERP_AUTH_INVALID', 'configuration');
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), timeoutMs);
  let stage = 'encrypt';
  const reports = [];
  async function request(url, options, signal = controller.signal) {
    const response = await fetchImpl(url, { ...options, redirect: 'error', signal });
    if (!response.ok) throw failure('ERP_AUTH_UNAVAILABLE', stage);
    return response;
  }
  async function gateway(functionId, body) {
    const response = await request(`${GATEWAY}?functionId=${encodeURIComponent(functionId)}&appid=JDME_DESKTOP`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ functionId, body, appid: 'JDME_DESKTOP' }),
    });
    return jsonResponse(response, stage);
  }
  try {
    const encrypted = await gateway('desk.agent.auth.encrypt', {
      content: JSON.stringify({ method: 'query', param: 'appToken', timestamp: String(Math.floor(Date.now() / 1000)), from: CALLER, to: 'HiOfficeClient' }),
      jdmeAppId: 'ee',
    });
    if (encrypted?.code !== 0 || typeof encrypted.data?.aesKey !== 'string' || !encrypted.data.aesKey || typeof encrypted.data?.content !== 'string' || !encrypted.data.content) throw failure('ERP_AUTH_RESPONSE_INVALID', stage);
    stage = 'hioffice';
    async function probe(host, attempt) {
      const localController = new AbortController();
      const round = [];
      const attempts = PORTS.map(async port => {
        const signal = AbortSignal.any([controller.signal, localController.signal, AbortSignal.timeout(5_000)]);
        const endpoint = { port, family: host === '127.0.0.1' ? 'ipv4' : 'ipv6', attempt };
        let report = { ...endpoint, outcome: 'transport_error' };
        try {
          const response = await localFetchImpl(`http://${host}:${port}/hioffice?from=${CALLER}`, {
            method: 'POST',
            redirect: 'error', signal,
            headers: { 'Content-Type': 'application/json', 'X-AES-Key': encrypted.data.aesKey },
            body: encrypted.data.content,
          });
          if (!response.ok) {
            report = { ...endpoint, outcome: [401, 403].includes(response.status) ? 'denied' : 'http_error', status: response.status };
            throw new Error('LOCAL_RESPONSE_REJECTED');
          }
          const aesKey = response.headers.get('X-AES-Key');
          if (!aesKey) { report = { ...endpoint, outcome: 'protocol_error' }; throw new Error('LOCAL_RESPONSE_REJECTED'); }
          const token = await response.text();
          if (!token.trim() || token.length > 65536) { report = { ...endpoint, outcome: 'protocol_error' }; throw new Error('LOCAL_RESPONSE_REJECTED'); }
          return { aesKey, token };
        } catch (error) {
          const systemCode = error.cause?.code || error.code;
          if (['EACCES', 'EPERM', 'ERR_ACCESS_DENIED'].includes(systemCode)) report = { ...endpoint, outcome: 'denied', systemCode };
          else if (error.name === 'TimeoutError' || (!localController.signal.aborted && signal.aborted)) report = { ...endpoint, outcome: 'timeout' };
          else if (['ECONNREFUSED', 'ECONNRESET', 'ENETUNREACH', 'EHOSTUNREACH', 'EAFNOSUPPORT', 'EADDRNOTAVAIL'].includes(systemCode)) report = { ...endpoint, outcome: 'unreachable', systemCode };
          else if (['LOCAL_RESPONSE_TOO_LARGE', 'LOCAL_RESPONSE_INVALID', 'HPE_HEADER_OVERFLOW'].includes(systemCode)) report = { ...endpoint, outcome: 'protocol_error', systemCode };
          reports.push(report);
          round.push(report);
          throw new Error('LOCAL_PROBE_FAILED');
        }
      });
      try { return await Promise.any(attempts); }
      catch {
        if (controller.signal.aborted) throw failure('ERP_AUTH_TIMEOUT', stage, reports);
        const outcome = ['denied', 'protocol_error', 'http_error', 'transport_error'].find(value => round.some(report => report.outcome === value));
        if (outcome) throw failure({ denied: 'ERP_HIOFFICE_ACCESS_DENIED', protocol_error: 'ERP_HIOFFICE_PROTOCOL_ERROR', http_error: 'ERP_HIOFFICE_PROTOCOL_ERROR', transport_error: 'ERP_HIOFFICE_TRANSPORT_ERROR' }[outcome], stage, reports);
        return null;
      } finally { localController.abort(); }
    }
    let localTicket;
    for (let attempt = 1; attempt <= 2 && !localTicket; attempt += 1) {
      if (attempt > 1) await delay(retryDelayMs, undefined, { signal: controller.signal });
      localTicket = await probe('127.0.0.1', attempt) || await probe('[::1]', attempt);
    }
    if (!localTicket) throw failure(reports.some(report => report.outcome === 'timeout') ? 'ERP_HIOFFICE_TIMEOUT' : 'ERP_HIOFFICE_UNREACHABLE', stage, reports);
    stage = 'token_exchange';
    const exchanged = await gateway('desk.agent.auth.getWebToken', {
      ...localTicket, tenantCode: 'CN.JD.GROUP', deviceUuid: 'noDeviceId', jdmeAppId: 'ee',
    });
    const ticket = exchanged?.data?.accessToken;
    if (exchanged?.code !== 0) throw failure('ERP_TOKEN_EXCHANGE_FAILED', stage);
    if (typeof ticket !== 'string' || !ticket.trim() || ticket.length > 8192 || /[\r\n;]/.test(ticket)) {
      throw failure('ERP_AUTH_RESPONSE_INVALID', stage);
    }
    stage = 'identity';
    const identity = await resolveErpFromTicket(ticket, { fetchImpl, signal: controller.signal });
    stage = 'authorization';
    return authorize ? await authorize({ ...identity, ticket: ticket.trim() }) : identity;
  } catch (error) {
    if (DETAILS.has(error)) throw error;
    if (controller.signal.aborted) throw failure('ERP_AUTH_TIMEOUT', stage, stage === 'hioffice' ? reports : undefined);
    const code = error.code || error.message;
    throw failure(Object.hasOwn(MESSAGES, code || '') ? code : 'ERP_AUTH_UNAVAILABLE', stage);
  } finally {
    clearTimeout(deadline);
  }
}
