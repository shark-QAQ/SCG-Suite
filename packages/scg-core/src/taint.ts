import { commandReadsSecret, isSecretPath } from './classify.js'
import { sha256 } from './fingerprint.js'
import type { AgentAction, SessionState, TaintSource } from './types.js'

/**
 * 在动作被允许/进入审批后，把敏感数据接触记录到会话中。
 * 这是污染感知策略的基础：后续 egress 会被 deny。
 */
export function markTaintedFromAction(
  state: SessionState,
  action: AgentAction,
): TaintSource | null {
  let source: TaintSource | null = null

  if (action.kind === 'fs.read' && isSecretPath(action.path ?? '')) {
    const path = action.path ?? ''
    source = {
      kind: 'secret',
      id: sha256(`fs.read:${path}`),
      path,
      hash: sha256(path),
    }
  } else if (
    action.kind === 'process.exec' &&
    commandReadsSecret(action.command ?? '')
  ) {
    const command = action.command ?? ''
    source = {
      kind: 'secret',
      id: sha256(`process.exec:${command}`),
      hash: sha256(command),
    }
  }

  if (!source) return null
  if (state.taintSources.some((existing) => existing.id === source.id)) {
    return null
  }

  state.taintSources.push(source)
  return source
}
