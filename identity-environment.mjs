import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import { identityFailure } from './identity.mjs';
import { IDENTITY_PORTS } from './identity-transport.mjs';

const run = promisify(execFile);
const WINDOWS_PROBE = String.raw`
$ErrorActionPreference = 'Stop'
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$currentSession = (Get-Process -Id $PID).SessionId
$clients = @(Get-CimInstance Win32_Process -Filter "Name = 'HiOffice.exe' OR Name = 'JDME.exe' OR Name = 'JoyDesk.exe' OR Name = 'JingME.exe' OR Name = 'JDITDesk.exe'")
$owners = @{}
foreach ($client in $clients) {
  $sameUser = $null
  try {
    $owner = Invoke-CimMethod -InputObject $client -MethodName GetOwnerSid
    if ($owner.ReturnValue -eq 0) { $sameUser = ($owner.Sid -eq $currentSid) }
  } catch {}
  $owners[[string]$client.ProcessId] = @{ sameUser = $sameUser; sameSession = ($client.SessionId -eq $currentSession) }
}
$ports = @(8988,8990,8992,8994,8996,8998,9000,9002,9004,9006)
$listeners = @()
$listenersInspected = $false
try {
  $connections = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
  $listenersInspected = $true
  foreach ($connection in $connections) {
    if ($connection.LocalPort -notin $ports) { continue }
    $owner = $owners[[string]$connection.OwningProcess]
    $listeners += @{ port = [int]$connection.LocalPort; recognizedClient = ($null -ne $owner); sameUser = $(if ($owner) { $owner.sameUser } else { $null }); sameSession = $(if ($owner) { $owner.sameSession } else { $null }) }
  }
} catch {}
@{ inspected = $true; listenersInspected = $listenersInspected; clientProcessCount = $clients.Count; identityHostProcessCount = @($clients | Where-Object { $_.Name -in @('JoyDesk.exe','JDITDesk.exe') }).Count; sameUserProcessCount = @($owners.Values | Where-Object { $_.sameUser -eq $true }).Count; otherUserProcessCount = @($owners.Values | Where-Object { $_.sameUser -eq $false }).Count; listeners = $listeners } | ConvertTo-Json -Depth 4 -Compress
`;

async function collectWindows() {
  const executable = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const { stdout } = await run(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(WINDOWS_PROBE, 'utf16le').toString('base64')], {
    timeout: 8000, maxBuffer: 65536, windowsHide: true, encoding: 'utf8',
  });
  return JSON.parse(stdout.replace(/^\uFEFF/, '').trim());
}

const count = value => Number.isSafeInteger(value) && value >= 0 && value <= 10000 ? value : null;
const triState = value => typeof value === 'boolean' ? value : null;

export async function inspectIdentityEnvironment({ platform = process.platform, nodeVersion = process.versions.node, env = process.env, collectWindows: collect = collectWindows } = {}) {
  const report = {
    platform: ['win32', 'darwin', 'linux'].includes(platform) ? platform : 'other',
    nodeVersion: /^\d+\.\d+\.\d+$/.test(nodeVersion || '') ? nodeVersion : 'unknown',
    wsl: Boolean(env.WSL_DISTRO_NAME || env.WSL_INTEROP),
    remoteSession: Boolean(env.SSH_CONNECTION || env.SSH_TTY),
    containerHint: Boolean(env.REMOTE_CONTAINERS || env.CODESPACES || env.container),
    localTransport: 'direct-loopback-http',
  };
  if (platform === 'win32') {
    try {
      const facts = await collect();
      report.windows = {
        inspected: facts?.inspected === true,
        listenersInspected: facts?.listenersInspected === true,
        clientProcessCount: count(facts?.clientProcessCount),
        identityHostProcessCount: count(facts?.identityHostProcessCount),
        sameUserProcessCount: count(facts?.sameUserProcessCount),
        otherUserProcessCount: count(facts?.otherUserProcessCount),
        processNamesAreHintsOnly: true,
        listeners: (Array.isArray(facts?.listeners) ? facts.listeners : []).filter(item => IDENTITY_PORTS.includes(item?.port)).slice(0, 40).map(item => ({
          port: item.port, recognizedClient: item.recognizedClient === true, sameUser: triState(item.sameUser), sameSession: triState(item.sameSession),
        })),
      };
    } catch { report.windows = { inspected: false, reason: 'inspection-unavailable' }; }
  }
  return report;
}

export async function enrichIdentityFailure(error, { inspect = inspectIdentityEnvironment } = {}) {
  const report = identityFailure(error);
  if (report.code === 'ERP_NOT_ALLOWED') return report;
  let environment;
  try { environment = await inspect(); } catch { environment = { inspectionUnavailable: true }; }
  const actions = [];
  if (environment.wsl || environment.remoteSession || environment.containerHint) actions.push({
    id: 'use-desktop-execution-context', instruction: '当前执行环境可能与京ME桌面不在同一系统。由当前Codex确认并使用本人桌面的原生Node运行诊断，不复制登录态，不直接把远端127.0.0.1当本机。',
  });
  if (environment.windows?.otherUserProcessCount > 0 || environment.windows?.listeners?.some(item => item.sameUser === false || item.sameSession === false)) actions.push({
    id: 'use-same-user-session', instruction: '发现不同用户或会话的客户端线索。由当前Codex核对并在本人已登录京ME的同一Windows用户和会话运行；不要提权、借用其他账号或要求重新开通产品。',
  });
  if (report.stage === 'hioffice' || /^ERP_HIOFFICE_/.test(report.code) || report.code === 'ERP_NOT_LOGGED_IN') actions.push({
    id: 'inspect-client-interface', instruction: '由当前Codex结合每个候选端口的结果及进程/监听线索核对官方接口和运行环境，同时检查JoyDesk/ITDesk等独立身份宿主，不只看京ME窗口。进程名不能证明已登录；未识别进程不能证明未安装；不能仅凭18988在监听就当作身份接口，也不能据此断言缺JoyDesk。仅按证据修复，不强退京ME或关闭防护。',
  });
  else actions.push({ id: 'inspect-failed-stage', instruction: '由当前Codex按失败阶段核对京东网络、官方服务状态、票据有效期或响应契约，不把网络/换票/验票失败当作产品资格不足，不盲目重装。' });
  actions.push({ id: 'verify-recovery', command: 'node diagnose-identity.mjs', instruction: '修复后先只读验票，再用node install.mjs --check核验产品资格；均通过后继续原安装任务，不自动恢复店铺业务。' });
  const beforeAuthorization = /^ERP_HIOFFICE_/.test(report.code) || ['configuration', 'encrypt', 'hioffice', 'token_exchange', 'identity'].includes(report.stage);
  return { ...report, environment, loginState: 'unknown', productAuthorizationChecked: beforeAuthorization ? false : null,
    recovery: { ...report.recovery, maintenanceNeed: 'not-established', independentTasksBlocked: false, actions,
      escalationEvidence: ['失败阶段和正式入口版本', '脱敏端口及环境结果', '已验证的恢复尝试', '必须改安装器发版且无合规替代的依据'] } };
}
