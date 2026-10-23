// DSH 插件入口：把 DSH 的工具执行管线接到 SCG 策略内核。
import path from 'node:path'
import {
  CedarPolicyEngine,
  DEFAULT_APPROVAL_TTL_MS,
  approveAction,
  classifyAction,
  consumeApproval,
  createSessionState,
  markTaintedFromAction,
  type AgentAction,
  type Decision,
  type PolicyEngine,
  type SessionState,
} from '@scg/core'
import {
  EventLog,
  JsonlEventStore,
  redactDeep,
} from '@scg/events'
import { startEgressProxy, type EgressProxyHandle } from '@scg/egress'
import { buildNetnsCommand, probeNetnsSupport } from '@scg/netns'

export const name = 'scg-guard'
export const inject = ['tools']

export interface SCGConfig {
  /** 总开关，默认 true。 */
  enabled?: boolean
  /** enforce 会阻断/询问；audit 只记录，不改变执行。 */
  mode?: 'enforce' | 'audit'
  /** 兼容旧配置：false 等价于 audit。 */
  blockOnHigh?: boolean
  /** Cedar 策略文件；默认使用 @scg/core 内置策略。 */
  policyPath?: string
  /** 审计 JSONL 路径；null 表示只保存在内存中。 */
  auditPath?: string | null
  /** 策略引擎/审计异常时是否 fail-closed，默认 true。 */
  failClosed?: boolean
  /**
   * 会话接触敏感数据后，是否把 DSH 文件沙箱切到 read-only。
   * 这是 L2 强制：即使命令绕过 L1 分类器，后续写/删文件也会在 OS 层失败。
   * 默认 true；用户仍可通过 DSH 的 sandbox 策略控件显式切换回来。
   */
  lockdownOnTaint?: boolean
  /** 污染会话是否注入本地 egress 代理，默认 true。 */
  egressProxy?: boolean
  /** 代理允许的目标；默认仅 loopback。支持 ".example.com" 后缀与 "*"。 */
  egressAllowlist?: string[]
  /** 允许 allowlist 中的域名解析到私网/回环地址（默认 false，防 rebinding）。 */
  egressAllowPrivate?: boolean
  /** 测试/高级用法：直接指定代理 URL，不启动内置代理。 */
  egressProxyUrl?: string
  /** 未监控工具的默认策略；默认允许但写审计事件。 */
  unmonitoredTools?: 'allow' | 'deny'
  /**
   * 网络隔离方式：
   * - proxy（默认）：污染会话注入本地 egress proxy
   * - netns：Linux 上尝试 unshare --net（raw socket 也隔离）；不可用时回退 proxy
   * - off：只依赖 L1
   */
  networkIsolation?: 'off' | 'proxy' | 'netns'
}

const COMMAND_TOOLS = new Set(['bash', 'pwsh', 'shell', 'execute_command'])
const READ_TOOLS = new Set(['read', 'read_file', 'view', 'fs_read', 'read_image'])
const WRITE_TOOLS = new Set([
  'write',
  'write_file',
  'edit',
  'str_replace',
  'str_replace_editor',
])
const NETWORK_TOOLS = new Set(['web_fetch', 'fetch', 'http', 'web_search'])

const MONITORED_TOOLS = new Set([
  ...COMMAND_TOOLS,
  ...READ_TOOLS,
  ...WRITE_TOOLS,
  ...NETWORK_TOOLS,
])

/** 等待 DSH 审批结果的 ask 上限，避免长时间运行时无界增长。 */
const MAX_PENDING_ASKS = 1024

interface PendingAsk {
  sessionId: string
  actionHash: string
  tool: string
  expiresAt: number
}

function stringArg(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

function readArgs(exec: any): Record<string, unknown> {
  const args = exec?.arguments ?? exec?.args
  return args !== null && typeof args === 'object'
    ? (args as Record<string, unknown>)
    : {}
}

function readSessionId(exec: any): string {
  return String(exec?.agent?.id ?? exec?.agent?.sessionId ?? 'default')
}

function readCwd(exec: any, args: Record<string, unknown>): string {
  const workdir = stringArg(args.workdir) ?? stringArg(args.cwd)
  return workdir ? path.resolve(process.cwd(), workdir) : process.cwd()
}

/** 把 DSH 的 ToolExecution 归一化为 SCG 动作。 */
export function buildAction(exec: any): AgentAction {
  const tool = String(exec?.name ?? 'unknown')
  const args = readArgs(exec)

  if (COMMAND_TOOLS.has(tool)) {
    return {
      kind: 'process.exec',
      tool,
      command: stringArg(args.command) ?? stringArg(args.cmd),
    }
  }
  if (READ_TOOLS.has(tool)) {
    return {
      kind: 'fs.read',
      tool,
      path:
        stringArg(args.path) ??
        stringArg(args.file_path) ??
        stringArg(args.filePath),
    }
  }
  if (WRITE_TOOLS.has(tool)) {
    return {
      kind: 'fs.write',
      tool,
      path:
        stringArg(args.path) ??
        stringArg(args.file_path) ??
        stringArg(args.filePath),
    }
  }
  if (NETWORK_TOOLS.has(tool)) {
    return {
      kind: 'network.connect',
      tool,
      target:
        stringArg(args.url) ??
        stringArg(args.href) ??
        stringArg(args.query) ??
        stringArg(args.target),
    }
  }

  return { kind: 'tool.call', tool }
}

function formatDecision(decision: Decision): string {
  const prefix =
    decision.kind === 'deny'
      ? '🚨 [SCG] 已阻止：'
      : '🛡️ [SCG] 需要审批：'
  const policies =
    decision.policyIds.length > 0 ? decision.policyIds.join(', ') : 'default'
  return `${prefix}${decision.reason}（策略: ${policies}）`
}

function setupAudit(config: SCGConfig): {
  log: EventLog
  error: Error | null
} {
  if (config.auditPath === null) {
    return { log: new EventLog(), error: null }
  }

  const auditPath = path.resolve(
    config.auditPath ?? path.join(process.cwd(), '.scg', 'audit.jsonl'),
  )

  try {
    const store = new JsonlEventStore(auditPath)
    const log = new EventLog(store.load(), {
      sink: (event) => store.append(event),
    })
    const verification = log.verify(store.loadHead() ?? undefined)
    if (!verification.ok) {
      throw new Error(
        `audit log integrity check failed at seq ${verification.seq ?? '?'}: ${verification.error}`,
      )
    }
    return { log, error: null }
  } catch (error) {
    return {
      log: new EventLog(),
      error: error instanceof Error ? error : new Error(String(error)),
    }
  }
}

function setupEngine(config: SCGConfig): {
  engine: PolicyEngine | null
  error: Error | null
} {
  try {
    return {
      engine: new CedarPolicyEngine({
        policyPath: config.policyPath
          ? path.resolve(config.policyPath)
          : undefined,
      }),
      error: null,
    }
  } catch (error) {
    return {
      engine: null,
      error: error instanceof Error ? error : new Error(String(error)),
    }
  }
}

/**
 * 通过 DSH 官方的 session-mode 写路径切换文件沙箱模式。
 * 与 @deepseek-ai/dsh-sandbox-policy 的 setSandboxMode 完全一致：
 * session.append('sandbox/mode', { mode })。
 */
function appendSandboxMode(exec: any, mode: 'read-only'): boolean {
  const session = exec?.agent?.session
  if (!session || typeof session.append !== 'function') return false
  try {
    session.append('sandbox/mode', { mode })
    return true
  } catch {
    return false
  }
}

export function apply(ctx: any, config: SCGConfig = {}) {
  const enabled = config.enabled ?? true
  const mode: 'enforce' | 'audit' =
    config.mode ?? (config.blockOnHigh === false ? 'audit' : 'enforce')
  const failClosed = config.failClosed ?? true
  const lockdownOnTaint = config.lockdownOnTaint ?? true
  const enforce = mode === 'enforce'
  const networkIsolation = config.networkIsolation ?? 'proxy'
  const unmonitoredTools = config.unmonitoredTools ?? 'allow'
  let netnsReady = false

  if (!enabled) {
    ctx.logger?.info?.('[SCG-Guard] 插件已禁用')
    return
  }

  const { engine, error: engineError } = setupEngine(config)
  const { log, error: auditError } = setupAudit(config)
  const sessions = new Map<string, SessionState>()
  const taintedSessions = new Set<string>()
  const pendingAsks = new Map<string, PendingAsk>()
  let egressProxy: EgressProxyHandle | null = null
  let egressProxyUrl = config.egressProxyUrl
  let egressProxyError: Error | null = null
  let egressProxyReady: Promise<void> | null = null
  let shellPatchInstalled = false

  function setupEgressProxy() {
    if (
      !enforce ||
      networkIsolation === 'off' ||
      config.egressProxy === false ||
      egressProxyUrl
    ) {
      return
    }

    const proxyPromise = startEgressProxy({
      allowlist: config.egressAllowlist,
      allowPrivate: config.egressAllowPrivate ?? false,
      onBlocked: (attempt) => {
        try {
          log.append('egress-proxy', 'egress.blocked', {
            host: attempt.host,
            port: attempt.port,
            protocol: attempt.protocol,
            reason: 'tainted session egress blocked',
          })
        } catch {
          // 审计写入失败不应让代理崩溃
        }
        ctx.logger?.warn?.(
          `[SCG-Guard] 阻断外联 ${attempt.host}:${attempt.port}`,
        )
      },
    })
      .then((handle) => {
        egressProxy = handle
        egressProxyUrl = handle.url
        ctx.logger?.info?.(`[SCG-Guard] egress proxy 已启动: ${handle.url}`)
      })
      .catch((error) => {
        egressProxyError =
          error instanceof Error ? error : new Error(String(error))
        ctx.logger?.warn?.(
          `[SCG-Guard] egress proxy 启动失败: ${egressProxyError.message}`,
        )
      })
    egressProxyReady = proxyPromise.then(() => undefined)
  }

  /**
   * 包装 ctx.shell.resolve：只对已污染会话注入代理环境变量。
   * HTTP(S)_PROXY 影响 curl/wget/pip/git/python-requests 等 proxy-aware 客户端；
   * raw socket 不受影响（已记录为剩余缺口）。
   */
  function patchShell(target: any) {
    const shell = target?.shell
    if (!shell || typeof shell.resolve !== 'function') return
    if (shell.__scgEgressPatched) return

    const original = shell.resolve.bind(shell)
    shell.resolve = (request: any) => {
      const spec = original(request)
      const sessionId = String(request?.dshEnv?.DSH_SESSION_ID ?? '')
      const proxyUrl = egressProxyUrl

      if (enforce && sessionId && taintedSessions.has(sessionId)) {
        if (
          netnsReady &&
          typeof spec?.command === 'string' &&
          spec.command.length > 0
        ) {
          return { ...spec, command: buildNetnsCommand(spec.command) }
        }
        if (networkIsolation !== 'off' && proxyUrl) {
          return {
            ...spec,
            env: {
              ...(spec?.env ?? {}),
              HTTP_PROXY: proxyUrl,
              HTTPS_PROXY: proxyUrl,
              ALL_PROXY: proxyUrl,
              http_proxy: proxyUrl,
              https_proxy: proxyUrl,
              all_proxy: proxyUrl,
              NO_PROXY: '127.0.0.1,localhost,::1',
              no_proxy: '127.0.0.1,localhost,::1',
            },
          }
        }
      }
      return spec
    }
    shell.__scgEgressPatched = true
    shellPatchInstalled = true
  }

  setupEgressProxy()

  if (enforce && networkIsolation === 'netns' && process.platform === 'linux') {
    probeNetnsSupport()
      .then((supported) => {
        netnsReady = supported
        ctx.logger?.[supported ? 'info' : 'warn']?.(
          `[SCG-Guard] Linux netns egress isolation ${
            supported ? 'enabled' : 'unavailable; falling back to egress proxy'
          }`,
        )
      })
      .catch(() => {
        netnsReady = false
      })
  }

  if (typeof ctx.inject === 'function') {
    ctx.inject(['shell'], (shellCtx: any) => patchShell(shellCtx))
  } else if (ctx.shell) {
    patchShell(ctx)
  }
  ctx.effect?.(() => () => {
    void egressProxy?.close()
  })

  ctx.logger?.info?.(
    `[SCG-Guard] 已加载（mode=${mode}, engine=${engine ? 'cedar' : 'unavailable'}）`,
  )

  try {
    log.append('system', 'runtime.start', {
      plugin: 'dsh-scg-guard',
      mode,
      engine: engine ? 'cedar' : 'unavailable',
      failClosed,
    })
  } catch (error) {
    ctx.logger?.warn?.(
      `[SCG-Guard] 审计启动事件写入失败: ${
        error instanceof Error ? error.message : String(error)
      }`,
    )
  }
  if (engineError) {
    ctx.logger?.warn?.(`[SCG-Guard] 策略引擎初始化失败: ${engineError.message}`)
  }
  if (auditError) {
    ctx.logger?.warn?.(`[SCG-Guard] 审计日志初始化失败: ${auditError.message}`)
  }

  function sweepPendingAsks(now: number) {
    for (const [callId, pending] of pendingAsks) {
      if (pending.expiresAt <= now) pendingAsks.delete(callId)
    }
    while (pendingAsks.size >= MAX_PENDING_ASKS) {
      const oldest = pendingAsks.keys().next().value
      if (oldest === undefined) break
      pendingAsks.delete(oldest)
    }
  }

  /**
   * Observe DSH's one-shot approval outcome for an ask SCG produced.
   *
   * The approval is bound to the exact tool call (`callId`) and to SCG's
   * action fingerprint. We deliberately do NOT turn an observed grant into a
   * reusable `SessionState.approvals` entry: DSH already executed that call,
   * and leaving a grant behind would let an identical action run again without
   * a prompt. Grants for programmatic pre-authorization must be seeded through
   * `approveAction()` and are consumed exactly once by `consumeApproval()`.
   */
  function recordApprovalOutcome(req: any, outcome: unknown) {
    const callId = req?.callId !== undefined ? String(req.callId) : ''
    if (!callId) return
    const pending = pendingAsks.get(callId)
    if (!pending) return
    pendingAsks.delete(callId)

    // A callId is unique, but bind the result to the session that produced the
    // ask as well. A mismatch is an audit integrity event, not a grant.
    const agentId =
      req?.agent?.id !== undefined ? String(req.agent.id) : ''
    if (agentId && agentId !== pending.sessionId) {
      log.append('system', 'runtime.error', {
        error: 'approval callId/session mismatch',
        callId,
        expected: pending.sessionId,
        actual: agentId,
      })
      return
    }

    if (outcome !== 'allowed-once') {
      log.append(pending.sessionId, 'approval.rejected', {
        actionHash: pending.actionHash,
        callId,
        tool: pending.tool,
        outcome: String(outcome),
      })
      return
    }

    log.append(pending.sessionId, 'approval.granted', {
      actionHash: pending.actionHash,
      callId,
      tool: pending.tool,
      source: 'dsh-approval',
      // Informational: DSH approval is scoped to this call. SCG does not
      // retain it as a reusable grant.
      oneShot: true,
      consumedBy: 'dsh',
    })
  }

  function getSession(sessionId: string, cwd: string): SessionState {
    const existing = sessions.get(sessionId)
    if (existing) {
      existing.cwd = cwd
      return existing
    }
    const created = createSessionState(sessionId, cwd)
    sessions.set(sessionId, created)
    return created
  }

  function deny(reason: string) {
    return { kind: 'deny' as const, reason }
  }

  // Observe DSH's approval waterfall. `global` makes the listener independent
  // of agent scoping; `prepend` keeps us outermost so `next()` resolves the
  // real answerer and we only record its outcome. Never let observation change
  // the approval result.
  ctx.on(
    'approval/request',
    async (req: any, next: any) => {
      const proceed =
        typeof next === 'function' ? next : async () => 'unavailable' as const
      let outcome: unknown
      try {
        outcome = await proceed()
      } catch {
        outcome = 'unavailable'
      }
      try {
        recordApprovalOutcome(req, outcome)
      } catch {
        // Approval auditing must not alter approval semantics.
      }
      return outcome
    },
    { prepend: true, global: true },
  )

  ctx.on('tools/pre-execute', async (exec: any, next: any) => {
    const proceed =
      typeof next === 'function' ? next : async () => ({ kind: 'allow' as const })

    const toolName = String(exec?.name ?? '')
    if (!MONITORED_TOOLS.has(toolName)) {
      try {
        log.append('system', 'tool.unmonitored', { tool: toolName })
      } catch {
        // Logging an unmonitored tool must not break the tool call.
      }
      if (unmonitoredTools === 'deny' && enforce) {
        return deny(`🚨 [SCG] 未监控工具默认拒绝：${toolName}`)
      }
      return proceed()
    }

    if (!engine) {
      if (failClosed) {
        return deny(
          `🚨 [SCG] 策略引擎不可用，已按 fail-closed 阻止：${engineError?.message ?? 'unknown error'}`,
        )
      }
      return proceed()
    }

    // A corrupt/unavailable audit log means decisions cannot be recorded.
    // In enforce mode this is fail-closed.
    if (auditError && failClosed) {
      return deny(
        `🚨 [SCG] 审计不可用，已按 fail-closed 阻止：${auditError.message}`,
      )
    }

    const action = buildAction(exec)
    const args = readArgs(exec)
    const sessionId = readSessionId(exec)
    const cwd = readCwd(exec, args)
    const state = getSession(sessionId, cwd)

    let decision: Decision
    try {
      decision = engine.evaluate(action, state)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      log.append(
        sessionId,
        'runtime.error',
        redactDeep({
          action,
          error: message,
        }) as Record<string, unknown>,
      )
      if (failClosed) {
        return deny(`🚨 [SCG] 策略评估失败，已按 fail-closed 阻止：${message}`)
      }
      return proceed()
    }

    // `permit-approved` is a one-shot grant. Consume it now; if it vanished
    // (expired or raced with another call), do not execute on a stale allow.
    if (
      mode === 'enforce' &&
      decision.kind === 'allow' &&
      decision.policyIds.includes('permit-approved')
    ) {
      const consumed = consumeApproval(action, state)
      if (!consumed) {
        // The grant expired or was raced away between evaluation and
        // consumption. Fail closed and let `decision.made` record the final
        // deny instead of leaving a stale allow in the audit.
        decision = {
          ...decision,
          kind: 'deny',
          reason:
            'one-shot approval expired or was already consumed before execution',
          policyIds: [...decision.policyIds, 'deny-stale-approval'],
        }
      }
      try {
        log.append(sessionId, 'approval.consumed', {
          actionHash: decision.actionHash,
          consumed,
        })
      } catch {
        // A failing audit sink is handled by the surrounding pipeline.
      }
    }

    // Fail-closed if a tainted/secret-reading action could reach the network
    // while the configured isolation layer is unavailable.
    const egressExpected =
      enforce &&
      networkIsolation !== 'off' &&
      config.egressProxy !== false
    const needsEgress =
      action.kind === 'process.exec' || action.kind === 'network.connect'
    if (
      egressExpected &&
      needsEgress &&
      (state.taintSources.length > 0 || decision.risk.readsSecret) &&
      !netnsReady
    ) {
      if (egressProxyReady) await egressProxyReady
      if (egressProxyError || !egressProxyUrl) {
        return deny(
          `🚨 [SCG] 网络隔离不可用，已按 fail-closed 阻止：${
            egressProxyError?.message ?? 'egress proxy unavailable'
          }`,
        )
      }
      if (!shellPatchInstalled) {
        return deny(
          '🚨 [SCG] shell 环境隔离不可用，已按 fail-closed 阻止',
        )
      }
    }

    const willExecute = mode === 'audit' || decision.kind !== 'deny'

    log.append(
      sessionId,
      'decision.made',
      redactDeep({
        action,
        state: {
          sessionId,
          cwd,
          taintSources: state.taintSources,
          approvals: state.approvals,
        },
        decision: {
          kind: decision.kind,
          reason: decision.reason,
          policyIds: decision.policyIds,
          risk: decision.risk,
          actionHash: decision.actionHash,
          latencyMs: decision.latencyMs,
        },
        enforced: mode === 'enforce',
      }) as Record<string, unknown>,
    )

    // Remember which exact action this ask belongs to. DSH returns the same
    // `callId` in `approval/request`, which lets us bind the human decision to
    // the action fingerprint without ambiguity.
    if (mode === 'enforce' && decision.kind === 'ask') {
      const callId = exec?.callId !== undefined ? String(exec.callId) : ''
      if (callId) {
        const now = Date.now()
        sweepPendingAsks(now)
        pendingAsks.set(callId, {
          sessionId,
          actionHash: decision.actionHash,
          tool: action.tool,
          expiresAt: now + DEFAULT_APPROVAL_TTL_MS,
        })
      } else {
        try {
          log.append(sessionId, 'runtime.error', {
            error: 'approval binding unavailable: missing callId',
            actionHash: decision.actionHash,
            tool: action.tool,
          })
        } catch {
          // A missing binding must not change the ask itself.
        }
      }
    }

    if (willExecute) {
      const source = markTaintedFromAction(state, action)
      if (source) {
        const hasSession = Boolean(exec?.agent?.session)
        const sandboxLocked =
          mode === 'enforce' &&
          lockdownOnTaint &&
          hasSession &&
          appendSandboxMode(exec, 'read-only')

        if (
          mode === 'enforce' &&
          lockdownOnTaint &&
          hasSession &&
          !sandboxLocked
        ) {
          try {
            log.append(sessionId, 'runtime.error', {
              error: 'sandbox lockdown unavailable',
              actionHash: decision.actionHash,
            })
          } catch {
            // The denial below is the fail-closed behavior.
          }
          return deny(
            '🚨 [SCG] 文件沙箱锁定失败，已按 fail-closed 阻止',
          )
        }

        taintedSessions.add(sessionId)
        log.append(sessionId, 'session.tainted', {
          source,
          actionHash: decision.actionHash,
          ...(sandboxLocked ? { sandboxMode: 'read-only' } : {}),
          egressProxy: Boolean(egressProxyUrl),
          networkIsolation: netnsReady ? 'netns' : networkIsolation,
        })
        if (sandboxLocked) {
          ctx.logger?.warn?.(
            `[SCG-Guard] 会话 ${sessionId} 接触敏感数据，文件沙箱已切换为 read-only`,
          )
        }
      }
    }

    if (mode === 'audit') {
      ctx.logger?.warn?.(
        `[SCG-Guard] audit-only: ${decision.kind} ${decision.actionHash.slice(0, 12)}`,
      )
      return proceed()
    }

    if (decision.kind === 'allow') {
      return proceed()
    }

    return {
      kind: decision.kind,
      reason: formatDecision(decision),
    }
  })

  return {
    /**
     * 为某个会话登记一次性预授权。控制器/headless 部署可在确认后调用；
     * 授权绑定 action fingerprint，并在下一次精确匹配的动作放行时被消费。
     * DSH 交互式 `ask` 不需要调用——它由 DSH 自己的审批流完成。
     */
    approve(
      sessionId: string,
      action: AgentAction,
      options: { ttlMs?: number; approvedBy?: string } = {},
    ) {
      const state = getSession(sessionId, process.cwd())
      const approval = approveAction(state, action, options)
      try {
        log.append(sessionId, 'approval.granted', {
          actionHash: approval.actionHash,
          expiresAt: approval.expiresAt,
          approvedBy: approval.approvedBy ?? 'api',
          source: 'api',
          oneShot: true,
        })
      } catch {
        // Auditing a grant must not prevent the caller from receiving it.
      }
      return approval
    },
  }
}

/**
 * 兼容旧 API：只回答"是否危险"，不产生完整决策。
 * 新代码应直接使用 @scg/core 的 CedarPolicyEngine。
 */
export function evaluateDangerousCommand(command: string): {
  isDangerous: boolean
  reason?: string
} {
  const risk = classifyAction(
    { kind: 'process.exec', tool: 'bash', command },
    createSessionState('legacy', process.cwd()),
  )
  const dangerous = risk.destructive || risk.taintedEgress
  return {
    isDangerous: dangerous,
    reason: dangerous ? risk.reasons[0] : undefined,
  }
}
