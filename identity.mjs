import { randomUUID } from 'node:crypto';

const GATEWAY = 'https://api.m.jd.com';
const CALLER = process.platform === 'darwin' ? 'hio_plugin_joydesk_Mac' : 'hio_plugin_joydesk';
const PORTS = Array.from({ length: 10 }, (_, index) => 8988 + index * 2);
const DETAILS = new WeakMap();
const MESSAGES = {
  ERP_HIOFFICE_UNREACHABLE: '校验程序未能连接本机京ME身份接口，不代表京ME未登录。请检查该进程与桌面京ME是否处于同一台电脑和用户环境；由IT核对本机接口或安全策略，不要反复登录或关闭防护。',
  ERP_HIOFFICE_TIMEOUT: '本机京ME身份接口响应超时，不能据此判断未登录。请保留诊断结果，由维护人排查响应耗时；不要反复安装。',
  ERP_HIOFFICE_ACCESS_DENIED: '访问本机京ME身份接口被拒绝。请由IT核对进程访问权限，不要扩大权限或绕过公司策略。',
  ERP_HIOFFICE_PROTOCOL_ERROR: '已收到本机接口响应，但身份协议内容不符合预期。请核对京ME版本与接口兼容性，不要把此问题当成未登录。',
  ERP_TOKEN_EXCHANGE_FAILED: '本机身份响应已取得，但京ME网关换票失败。请交维护人排查换票阶段，不要重复开白或重新安装。',
  ERP_IDENTITY_REJECTED: '身份验票服务拒绝了当前票据；这不是插件开白结果。请先由维护人确认票据有效性和服务状态，再决定是否需要重新登录。',
  ERP_AUTH_RESPONSE_INVALID: '身份服务返回不符合预期的响应。已停止，不输出响应正文或凭据；请交维护人核对协议。',
  ERP_AUTH_TIMEOUT: '身份校验达到总时限。请根据失败阶段排查网络或本机接口，不等于未登录。',
  ERP_AUTH_UNAVAILABLE: '身份服务请求失败。请检查京东网络及失败阶段，不要关闭验证或改用其他人的身份。',
  ERP_NOT_LOGGED_IN: '未取得有效身份凭证；仅凭此码不能判断桌面京ME未登录。已登录时请运行只读诊断，不要反复登录。',
  ERP_NOT_ALLOWED: '身份校验后未获准使用该插件，请联系负责人核对本人的插件产品资格，不要借用账号。',
  ERP_AUTH_INVALID: '身份响应校验失败，请停止并联系维护人。',
};

function failure(code, stage, ports) {
  const error = Object.assign(new Error(code), { code, stage });
  DETAILS.set(error, { stage, ...(ports ? { diagnostics: { ports } } : {}) });
  return error;
}

export function identityFailure(error) {
  const candidate = error?.code || error?.message;
  const code = Object.hasOwn(MESSAGES, candidate || '') ? candidate : 'ERP_AUTH_UNAVAILABLE';
  return { ok: false, code, ...(DETAILS.get(error) || {}), message: MESSAGES[code] };
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

export async function verifyIdentity({ fetchImpl = fetch, timeoutMs = 12_000, authorize } = {}) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 120_000) throw failure('ERP_AUTH_INVALID', 'configuration');
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), timeoutMs);
  let stage = 'encrypt';
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
    const localController = new AbortController();
    const reports = [];
    const attempts = PORTS.map(async port => {
      const signal = AbortSignal.any([controller.signal, localController.signal, AbortSignal.timeout(5_000)]);
      let report = { port, outcome: 'unreachable' };
      try {
        const response = await fetchImpl(`http://127.0.0.1:${port}/hioffice?from=${CALLER}`, {
          method: 'POST',
          redirect: 'error', signal,
          headers: { 'Content-Type': 'application/json', 'X-AES-Key': encrypted.data.aesKey },
          body: encrypted.data.content,
        });
        if (!response.ok) {
          report = { port, outcome: [401, 403].includes(response.status) ? 'denied' : 'http_error', status: response.status };
          throw new Error('LOCAL_RESPONSE_REJECTED');
        }
        const aesKey = response.headers.get('X-AES-Key');
        if (!aesKey) { report = { port, outcome: 'protocol_error' }; throw new Error('LOCAL_RESPONSE_REJECTED'); }
        const token = await response.text();
        if (!token.trim() || token.length > 65536) { report = { port, outcome: 'protocol_error' }; throw new Error('LOCAL_RESPONSE_REJECTED'); }
        return { aesKey, token };
      } catch (error) {
        const systemCode = error.cause?.code || error.code;
        if (['EACCES', 'EPERM'].includes(systemCode)) report = { port, outcome: 'denied', systemCode };
        else if (error.name === 'TimeoutError' || (!controller.signal.aborted && !localController.signal.aborted && signal.aborted)) report = { port, outcome: 'timeout' };
        else if (['ECONNREFUSED', 'ECONNRESET', 'ENETUNREACH', 'EHOSTUNREACH'].includes(systemCode)) report = { port, outcome: 'unreachable', systemCode };
        reports.push(report);
        throw new Error('LOCAL_PROBE_FAILED');
      }
    });
    let localTicket;
    try { localTicket = await Promise.any(attempts); }
    catch {
      if (controller.signal.aborted) throw failure('ERP_AUTH_TIMEOUT', stage);
      const outcome = ['denied', 'protocol_error', 'http_error', 'timeout'].find(value => reports.some(report => report.outcome === value));
      const code = { denied: 'ERP_HIOFFICE_ACCESS_DENIED', protocol_error: 'ERP_HIOFFICE_PROTOCOL_ERROR', http_error: 'ERP_HIOFFICE_PROTOCOL_ERROR', timeout: 'ERP_HIOFFICE_TIMEOUT' }[outcome] || 'ERP_HIOFFICE_UNREACHABLE';
      throw failure(code, stage, reports.sort((left, right) => left.port - right.port));
    } finally {
      localController.abort();
    }
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
    if (controller.signal.aborted) throw failure('ERP_AUTH_TIMEOUT', stage);
    if (DETAILS.has(error)) throw error;
    throw failure(Object.hasOwn(MESSAGES, error.code || '') ? error.code : 'ERP_AUTH_UNAVAILABLE', stage);
  } finally {
    clearTimeout(deadline);
  }
}
