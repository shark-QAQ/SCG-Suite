import type {
  DecisionLike,
  DecisionReplayCallback,
  ReplayMismatch,
  ReplayReport,
  ScgEvent,
} from './types.js'

function recordedDecision(
  payload: Record<string, unknown>,
): DecisionLike | null {
  const decision = payload.decision
  if (decision === null || typeof decision !== 'object') return null
  const record = decision as Record<string, unknown>
  if (typeof record.kind !== 'string') return null
  return {
    kind: record.kind,
    reason: typeof record.reason === 'string' ? record.reason : undefined,
  }
}

/**
 * 对 `decision.made` 事件做确定性回放：用当前策略重新计算，
 * 与录制时的决策逐条比较。策略变更后的差异会出现在 mismatches 中。
 */
export function replayDecisions(
  events: readonly ScgEvent[],
  decide: DecisionReplayCallback,
): ReplayReport {
  const mismatches: ReplayMismatch[] = []
  let total = 0

  for (const event of events) {
    if (event.type !== 'decision.made') continue
    total += 1

    const expected = recordedDecision(event.payload)
    if (!expected) {
      mismatches.push({
        seq: event.seq,
        expected: '<missing>',
        actual: '<skipped>',
        reason: 'recorded decision payload is malformed',
      })
      continue
    }

    const actual = decide(event.payload)
    if (actual.kind !== expected.kind) {
      mismatches.push({
        seq: event.seq,
        expected: expected.kind,
        actual: actual.kind,
        reason: actual.reason ?? '',
      })
    }
  }

  return {
    total,
    matched: total - mismatches.length,
    mismatches,
  }
}
