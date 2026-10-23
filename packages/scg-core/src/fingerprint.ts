import { createHash } from 'node:crypto'
import type { AgentAction } from './types.js'

/** 稳定序列化：对象键排序，保证同一输入得到同一哈希。 */
export function stableStringify(value: unknown): string {
  if (value === undefined) return 'null'
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`
  }
  const record = value as Record<string, unknown>
  const keys = Object.keys(record).sort()
  return `{${keys
    .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
    .join(',')}}`
}

export function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex')
}

/** 动作指纹用于绑定一次性审批，避免"批准 A 却执行 B"。 */
export function actionFingerprint(action: AgentAction): string {
  return sha256(
    stableStringify({
      kind: action.kind,
      tool: action.tool,
      command: action.command ?? null,
      path: action.path ?? null,
      target: action.target ?? null,
    }),
  )
}
