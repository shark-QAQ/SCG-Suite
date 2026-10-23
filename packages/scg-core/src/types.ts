/** 运行时动作的种类。 */
export type ActionKind =
  | 'process.exec'
  | 'fs.read'
  | 'fs.write'
  | 'network.connect'
  | 'tool.call'

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'

/** 会话中已观察到的敏感数据来源。 */
export interface TaintSource {
  kind: 'secret' | 'sensitive-file' | 'user-input'
  id: string
  path?: string
  hash?: string
}

/** 一次性人工授权。 */
export interface Approval {
  actionHash: string
  approvedAt: number
  expiresAt?: number
  approvedBy?: string
}

/** 每个 Agent 会话的运行时状态。 */
export interface SessionState {
  sessionId: string
  cwd: string
  taintSources: TaintSource[]
  approvals: Approval[]
}

/** 从 DSH 工具调用归一化出来的动作。 */
export interface AgentAction {
  kind: ActionKind
  tool: string
  command?: string
  path?: string
  target?: string
  metadata?: Record<string, unknown>
}

/** 分类器产出的风险画像。 */
export interface ActionRisk {
  level: RiskLevel
  destructive: boolean
  network: boolean
  readsSecret: boolean
  writesOutsideWorkspace: boolean
  /** 会话此前是否接触过敏感数据。 */
  sessionTainted: boolean
  /** 敏感数据 + 可外传动作，构成数据外泄路径。 */
  taintedEgress: boolean
  reasons: string[]
}

export type DecisionKind = 'allow' | 'ask' | 'deny'

export interface Decision {
  kind: DecisionKind
  reason: string
  policyIds: string[]
  risk: ActionRisk
  actionHash: string
  latencyMs: number
}

/** 可替换的策略引擎契约。 */
export interface PolicyEngine {
  evaluate(action: AgentAction, state: SessionState): Decision
}

export function createSessionState(
  sessionId: string,
  cwd: string,
): SessionState {
  return {
    sessionId,
    cwd,
    taintSources: [],
    approvals: [],
  }
}
