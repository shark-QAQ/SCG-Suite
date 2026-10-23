export type ScgEventType =
  | 'runtime.start'
  | 'decision.made'
  | 'session.tainted'
  | 'egress.blocked'
  | 'tool.unmonitored'
  | 'approval.granted'
  | 'approval.rejected'
  | 'approval.consumed'
  | 'runtime.error'

/** 追加写、哈希链保护的审计事件。 */
export interface ScgEvent {
  v: 1
  seq: number
  ts: string
  sessionId: string
  type: ScgEventType
  payload: Record<string, unknown>
  prevHash: string
  hash: string
}

export interface ReplayMismatch {
  seq: number
  expected: string
  actual: string
  reason: string
}

export interface ReplayReport {
  total: number
  matched: number
  mismatches: ReplayMismatch[]
}

export interface DecisionLike {
  kind: string
  reason?: string
}

/** 回放时基于事件 payload 重新计算决策。 */
export type DecisionReplayCallback = (
  payload: Record<string, unknown>,
) => DecisionLike
