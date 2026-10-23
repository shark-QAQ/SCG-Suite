import { readFileSync } from 'node:fs'
import * as cedar from '@cedar-policy/cedar-wasm/nodejs'
import type {
  AuthorizationAnswer,
  PolicySet,
} from '@cedar-policy/cedar-wasm/nodejs'
import { classifyAction } from './classify.js'
import { actionFingerprint } from './fingerprint.js'
import type {
  AgentAction,
  Approval,
  Decision,
  DecisionKind,
  PolicyEngine,
  SessionState,
} from './types.js'

export class PolicyEngineError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'PolicyEngineError'
  }
}

export interface CedarPolicyEngineOptions {
  /** 自定义策略文件路径（JSON: policyId -> Cedar policy text）。 */
  policyPath?: string | URL
  /** 直接传入策略集合，便于测试与策略编译。 */
  policySet?: Record<string, string>
}

const DEFAULT_POLICY_PATH = new URL(
  '../policies/agent-guard.json',
  import.meta.url,
)

const ACTION_NAMES: Record<AgentAction['kind'], string> = {
  'process.exec': 'Exec',
  'fs.read': 'Read',
  'fs.write': 'Write',
  'network.connect': 'Network',
  'tool.call': 'Tool',
}

const REASON_BY_POLICY: Record<string, string> = {
  'permit-low-risk': 'low-risk action permitted',
  'permit-approved': 'approved by a human for this exact action',
  'ask-medium-risk': 'medium-risk action requires approval',
  'ask-high-risk': 'high-risk action requires approval',
  'ask-destructive': 'destructive action requires approval',
  'deny-tainted-egress': 'session touched sensitive data and this action can exfiltrate it',
  'deny-critical': 'critical-risk action is blocked',
}

/** 默认一次性授权有效期。 */
export const DEFAULT_APPROVAL_TTL_MS = 10 * 60 * 1000

function pendingApprovalIndex(
  action: AgentAction,
  state: SessionState,
  now: number,
): number {
  const fingerprint = actionFingerprint(action)
  return state.approvals.findIndex(
    (approval) =>
      approval.actionHash === fingerprint &&
      (approval.expiresAt === undefined || approval.expiresAt > now),
  )
}

function isApproved(action: AgentAction, state: SessionState): boolean {
  return pendingApprovalIndex(action, state, Date.now()) !== -1
}

/**
 * 为某个具体动作登记一次性授权。
 *
 * 授权绑定 action fingerprint：同一指纹的其他动作（哪怕只差一个参数）不会
 * 命中。授权应通过 {@link consumeApproval} 消费，避免重复放行。
 */
export function approveAction(
  state: SessionState,
  action: AgentAction,
  options: {
    ttlMs?: number
    approvedBy?: string
  } = {},
): Approval {
  const now = Date.now()
  const ttlMs = options.ttlMs ?? DEFAULT_APPROVAL_TTL_MS
  const fingerprint = actionFingerprint(action)

  // Drop expired entries and any previous grant for the same fingerprint,
  // mutating in place so callers holding the array keep observing it.
  for (let index = state.approvals.length - 1; index >= 0; index -= 1) {
    const approval = state.approvals[index]
    const expired =
      approval.expiresAt !== undefined && approval.expiresAt <= now
    if (expired || approval.actionHash === fingerprint) {
      state.approvals.splice(index, 1)
    }
  }

  const approval: Approval = {
    actionHash: fingerprint,
    approvedAt: now,
    expiresAt: now + ttlMs,
    ...(options.approvedBy !== undefined
      ? { approvedBy: options.approvedBy }
      : {}),
  }
  state.approvals.push(approval)
  return approval
}

/**
 * 消费（移除）某个动作的一次性授权。
 *
 * 返回 true 表示本次放行确实用掉了一条未过期的授权；返回 false 表示没有
 * 可用授权。调用方应在授权生效的决策后立即消费，确保"一次授权只放行一次"。
 */
export function consumeApproval(
  action: AgentAction,
  state: SessionState,
): boolean {
  const index = pendingApprovalIndex(action, state, Date.now())
  if (index === -1) return false
  state.approvals.splice(index, 1)
  return true
}

function decisionKind(answer: AuthorizationAnswer): {
  kind: DecisionKind
  policyIds: string[]
} {
  if (answer.type === 'failure') {
    throw new PolicyEngineError(
      `Cedar evaluation failed: ${answer.errors.map((error) => error.message).join('; ')}`,
    )
  }

  const policyIds = [...answer.response.diagnostics.reason]
  if (answer.response.decision === 'allow') {
    return { kind: 'allow', policyIds }
  }
  if (policyIds.some((id) => id.startsWith('deny-'))) {
    return { kind: 'deny', policyIds }
  }
  if (policyIds.some((id) => id.startsWith('ask-'))) {
    return { kind: 'ask', policyIds }
  }
  return { kind: 'deny', policyIds }
}

function explain(
  kind: DecisionKind,
  policyIds: string[],
  riskReasons: string[],
): string {
  const policyReasons = policyIds
    .map((id) => REASON_BY_POLICY[id])
    .filter((reason): reason is string => Boolean(reason))

  const unique = [...new Set(policyReasons)]
  if (unique.length === 0) {
    unique.push(
      kind === 'allow'
        ? 'no risk detected'
        : 'no policy permitted this action (fail-closed)',
    )
  }

  const risk = riskReasons.length > 0 ? ` | evidence: ${riskReasons.join(', ')}` : ''
  return `${unique.join('; ')}${risk}`
}

/**
 * Cedar WASM 策略引擎。
 *
 * 策略以 policy id -> Cedar 文本的 JSON 文件维护；Cedar 负责
 * allow/deny 判定，TS 层把 `ask-*` 与 `deny-*` 映射为三级决策。
 */
export class CedarPolicyEngine implements PolicyEngine {
  private readonly policySet: PolicySet

  constructor(options: CedarPolicyEngineOptions = {}) {
    let policies: Record<string, string>
    if (options.policySet) {
      policies = options.policySet
    } else {
      const raw = readFileSync(
        options.policyPath ?? DEFAULT_POLICY_PATH,
        'utf8',
      )
      policies = JSON.parse(raw) as Record<string, string>
    }

    const check = cedar.checkParsePolicySet({ staticPolicies: policies })
    if (check.type === 'failure') {
      throw new PolicyEngineError(
        `invalid Cedar policy set: ${check.errors
          .map((error) => error.message)
          .join('; ')}`,
      )
    }
    this.policySet = { staticPolicies: policies }
  }

  evaluate(action: AgentAction, state: SessionState): Decision {
    const started = performance.now()
    const risk = classifyAction(action, state)
    const approved = isApproved(action, state)

    let answer: AuthorizationAnswer
    try {
      answer = cedar.isAuthorized({
        principal: { type: 'Agent', id: 'agent' },
        action: { type: 'Action', id: ACTION_NAMES[action.kind] },
        resource: { type: 'Resource', id: 'resource' },
        context: {
          risk_level: risk.level,
          destructive: risk.destructive,
          network: risk.network,
          reads_secret: risk.readsSecret,
          writes_outside_workspace: risk.writesOutsideWorkspace,
          session_tainted: risk.sessionTainted,
          tainted_egress: risk.taintedEgress,
          approved,
          tool: action.tool,
          action_kind: action.kind,
        },
        policies: this.policySet,
        entities: [],
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      throw new PolicyEngineError(`Cedar evaluation threw: ${message}`)
    }

    const { kind, policyIds } = decisionKind(answer)

    return {
      kind,
      reason: explain(kind, policyIds, risk.reasons),
      policyIds,
      risk,
      actionHash: actionFingerprint(action),
      latencyMs: Number((performance.now() - started).toFixed(3)),
    }
  }
}
