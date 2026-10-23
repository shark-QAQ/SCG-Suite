import path from 'node:path'
import type { ActionRisk, AgentAction, RiskLevel, SessionState } from './types.js'

const NETWORK_TOOLS = new Set([
  'curl',
  'wget',
  'nc',
  'ncat',
  'netcat',
  'ssh',
  'scp',
  'sftp',
  'rsync',
  'ftp',
  'telnet',
  'invoke-webrequest',
  'invoke-restmethod',
  'iwr',
  'irm',
  'psql',
  'mysql',
  'sqlcmd',
  'redis-cli',
  'mongosh',
  'aws',
  'gcloud',
  'az',
  'kubectl',
  'helm',
])

const SECRET_BASENAMES = new Set([
  '.env',
  '.envrc',
  '.netrc',
  '.npmrc',
  '.pypirc',
  'id_rsa',
  'id_dsa',
  'id_ecdsa',
  'id_ed25519',
  'credentials',
  'credentials.json',
  'secrets',
  'secrets.json',
  'secrets.yaml',
  'secrets.yml',
  'token',
  'token.txt',
  '.pgpass',
  '.git-credentials',
  'kubeconfig',
])

const SECRET_EXTENSIONS = new Set(['.pem', '.key', '.p12', '.pfx'])

function stripQuotes(value: string): string {
  return value.replace(/^["'`]|["'`]$/g, '')
}

/** 判断路径是否像敏感文件（密钥、凭据、环境变量文件）。 */
export function isSecretPath(input: string): boolean {
  if (!input) return false
  const normalized = input.replace(/\\/g, '/').toLowerCase()
  const base = path.posix.basename(normalized)

  if (base === '.env' || base.startsWith('.env.') || base.endsWith('.env')) {
    return true
  }
  if (SECRET_BASENAMES.has(base)) return true
  if (SECRET_EXTENSIONS.has(path.posix.extname(base))) return true
  if (normalized.includes('/.ssh/') || normalized.endsWith('/.ssh')) return true
  if (normalized.includes('/.aws/credentials')) return true
  if (normalized.includes('/.kube/config')) return true
  if (normalized.includes('/.docker/config.json')) return true
  if (normalized.includes('/.config/gcloud/')) return true

  return false
}

/** rm 递归 + 强制删除绝对路径/根目录；兼容参数顺序与长选项。 */
export function isDangerousRm(command: string): boolean {
  for (const segment of command.split(/[;&|\n]+/)) {
    // 去引号后再找 rm，覆盖 bash -c 'rm -rf /' 这类嵌套形式
    const tokens = segment
      .trim()
      .split(/\s+/)
      .filter(Boolean)
      .map(stripQuotes)
    const rmIndex = tokens.indexOf('rm')
    if (rmIndex === -1) continue

    let recursive = false
    let forced = false
    const targets: string[] = []

    for (const token of tokens.slice(rmIndex + 1)) {
      if (token.startsWith('-') && token.length > 1) {
        const flags = token.toLowerCase()
        recursive = recursive || flags.includes('r')
        forced = forced || flags.includes('f')
        continue
      }
      targets.push(stripQuotes(token))
    }

    if (
      recursive &&
      forced &&
      targets.some(
        (target) =>
          target.startsWith('/') ||
          target === '~' ||
          target.startsWith('~/') ||
          target === '$HOME' ||
          target.startsWith('$HOME/') ||
          target === '${HOME}' ||
          target.startsWith('${HOME}/'),
      )
    ) {
      return true
    }
  }
  return false
}

/** Windows 批量删除/磁盘操作（cmd.exe 与 PowerShell）。 */
function isWindowsDestructive(command: string): boolean {
  for (const segment of command.split(/[;&|\n]+/)) {
    const tokens = segment
      .trim()
      .split(/\s+/)
      .filter(Boolean)
      .map((token) => token.toLowerCase())
    if (tokens.length === 0) continue

    const first = tokens[0]
    if (first === 'diskpart' || first === 'clear-disk' || first === 'format-volume') {
      return true
    }

    if (first === 'rd' || first === 'rmdir' || first === 'del') {
      const hasRecursive = tokens.includes('/s')
      const hasQuiet = tokens.includes('/q')
      const hasForce = first !== 'del' || tokens.includes('/f')
      const driveTarget = tokens.some((token) => /^[a-z]:[\\/]/i.test(token))
      if (hasRecursive && hasQuiet && hasForce && driveTarget) return true
    }
  }
  return false
}

/** 结构性危险命令：删除、格式化、基础设施销毁。 */
export function isDestructiveCommand(command: string): boolean {
  const lower = command.toLowerCase()

  if (isDangerousRm(command)) return true
  if (isWindowsDestructive(command)) return true
  if (/\bmkfs(?:\.[a-z0-9]+)?\b/.test(lower)) return true
  if (/\bdd\s+[^\n;&|]*\bif=/.test(lower)) return true
  if (/\b(drop\s+(table|database)|truncate\s+table)\b/.test(lower)) return true
  if (/\b(shutdown|reboot|halt|poweroff)\b/.test(lower)) return true
  if (/\bformat\s+[a-z]:/i.test(command)) return true
  if (/\bchmod\s+-r\s+777\s+\//i.test(command)) return true
  if (/\bremove-item\b[^\n]*-recurse\b[^\n]*-force\b/i.test(command)) return true
  if (/\bremove-item\b[^\n]*-force\b[^\n]*-recurse\b/i.test(command)) return true
  if (/\b(kubectl\s+delete|terraform\s+destroy|helm\s+uninstall)\b/.test(lower)) return true
  if (/\baws\s+s3\s+rm\b[^\n]*--recursive\b/.test(lower)) return true
  if (/\bfind\b[^\n;&|]*-delete\b/.test(lower)) return true
  if (/\btruncate\s+-s\s+/.test(lower)) return true
  if (/\bbase64\b[^\n|]*\|\s*(?:sh|bash|zsh|pwsh)\b/.test(lower)) return true
  if (/:\(\)\s*\{\s*:\|:&\s*\}\s*;?\s*:/.test(command)) return true

  return false
}

/** 命令是否具备网络出站能力。 */
export function isNetworkCommand(command: string): boolean {
  for (const segment of command.split(/[;&|\n]+/)) {
    const tokens = segment.trim().split(/\s+/).filter(Boolean)
    if (tokens.length === 0) continue

    const first = tokens[0].toLowerCase()
    if (NETWORK_TOOLS.has(first)) return true
    if (
      first === 'git' &&
      ['push', 'fetch', 'clone', 'pull'].includes(tokens[1]?.toLowerCase())
    ) {
      return true
    }
    if (tokens.some((token) => /^(https?|ftp):\/\//i.test(stripQuotes(token)))) {
      return true
    }
  }

  // 通过解释器直接发起网络请求
  if (
    /\b(socket\.create_connection|socket\.socket|urllib\.request|requests\.(?:get|post|put|delete|patch)|http\.client|https?\.request)\b/i.test(
      command,
    )
  ) {
    return true
  }

  return false
}

/** 命令是否在读取敏感数据（文件、环境变量、进程环境）。 */
export function commandReadsSecret(command: string): boolean {
  if (/get-childitem\s+env:/i.test(command)) return true
  if (/\/proc\/[^\s]*\/environ/i.test(command)) return true
  if (
    /(?:\$|%)\{?[a-z0-9_]*(?:password|secret|token|api[_-]?key|access[_-]?key)[a-z0-9_]*\}?/i.test(
      command,
    )
  ) {
    return true
  }

  for (const segment of command.split(/[;&|\n]+/)) {
    const tokens = segment.trim().split(/\s+/).filter(Boolean)
    if (tokens.length === 0) continue
    const first = tokens[0].toLowerCase()
    if (
      (first === 'printenv' || first === 'env') &&
      !tokens.slice(1).some((token) => token.includes('='))
    ) {
      return true
    }
    if (tokens.some((token) => isSecretPath(stripQuotes(token)))) {
      return true
    }
  }

  // Interpreter one-liners such as `python -c "open('.env').read()"` hide the
  // path inside punctuation, so strip punctuation before matching tokens.
  const normalized = command.replace(/[()'"`=;,]/g, ' ')
  if (normalized.split(/\s+/).some((token) => isSecretPath(token))) {
    return true
  }

  // 解释器直接读取进程环境：os.environ / process.env / os.getenv(...)。
  // 仅当同一命令里出现敏感键名时才判定，避免把所有环境访问当成密钥读取。
  if (
    /\b(?:os\.environ|os\.getenv|process\.env|process\.getenv|sys\.environ)\b/i.test(
      command,
    ) &&
    /\b[A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY)[A-Za-z0-9_]*\b/i.test(
      command,
    )
  ) {
    return true
  }

  return false
}

/** 写入目标是否在工作区之外。 */
export function isOutsideWorkspace(target: string, cwd: string): boolean {
  if (!target) return false
  const resolvedCwd = path.resolve(cwd)
  const resolvedTarget = path.resolve(cwd, target)
  const relative = path.relative(resolvedCwd, resolvedTarget)
  return relative.startsWith('..') || path.isAbsolute(relative)
}

function riskLevel(input: {
  destructive: boolean
  network: boolean
  readsSecret: boolean
  writesOutsideWorkspace: boolean
  taintedEgress: boolean
}): RiskLevel {
  if (input.taintedEgress) return 'critical'
  if (input.destructive || (input.readsSecret && input.network)) return 'high'
  if (input.network || input.readsSecret || input.writesOutsideWorkspace) {
    return 'medium'
  }
  return 'low'
}

/** 把动作和会话状态归一化为可解释的风险画像。 */
export function classifyAction(
  action: AgentAction,
  state: SessionState,
): ActionRisk {
  let destructive = false
  let network = false
  let readsSecret = false
  let writesOutsideWorkspace = false

  if (action.kind === 'process.exec') {
    const command = action.command ?? ''
    destructive = isDestructiveCommand(command)
    network = isNetworkCommand(command)
    readsSecret = commandReadsSecret(command)
  } else if (action.kind === 'fs.read') {
    readsSecret = isSecretPath(action.path ?? '')
  } else if (action.kind === 'fs.write') {
    writesOutsideWorkspace = isOutsideWorkspace(action.path ?? '', state.cwd)
  } else if (action.kind === 'network.connect') {
    network = true
  }

  const sessionTainted = state.taintSources.length > 0
  const taintedEgress =
    sessionTainted && (network || writesOutsideWorkspace)

  const reasons: string[] = []
  if (destructive) reasons.push('destructive command')
  if (network) reasons.push('network-capable action')
  if (readsSecret) reasons.push('reads secret material')
  if (writesOutsideWorkspace) reasons.push('writes outside workspace')
  if (sessionTainted) reasons.push('session is tainted by sensitive data')
  if (taintedEgress) reasons.push('tainted data can leave the workspace')

  return {
    level: riskLevel({
      destructive,
      network,
      readsSecret,
      writesOutsideWorkspace,
      taintedEgress,
    }),
    destructive,
    network,
    readsSecret,
    writesOutsideWorkspace,
    sessionTainted,
    taintedEgress,
    reasons,
  }
}
