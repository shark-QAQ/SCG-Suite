import {
  GENESIS_HASH,
  pruneUndefined,
  sha256,
  stableStringify,
} from './hash.js'
import type { ScgEvent, ScgEventType } from './types.js'

export class EventChainError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EventChainError'
  }
}

export interface EventLogOptions {
  /** 每次追加时同步写出（例如写 JSONL 文件）。 */
  sink?: (event: ScgEvent) => void
}

export interface VerifyResult {
  ok: boolean
  seq?: number
  error?: string
}

/** Optional sidecar anchor used to detect a truncated tail. */
export interface ExpectedHead {
  seq: number
  hash: string
}

function computeHash(event: Omit<ScgEvent, 'hash'>): string {
  return sha256(`${event.prevHash}\n${stableStringify(event)}`)
}

/** 追加写的事件日志，每条事件通过 prevHash + 内容哈希形成链。 */
export class EventLog {
  private readonly entries: ScgEvent[] = []
  private readonly sink?: (event: ScgEvent) => void

  constructor(initial: readonly ScgEvent[] = [], options: EventLogOptions = {}) {
    this.sink = options.sink
    for (const event of initial) {
      this.verifyEvent(event, this.entries.length)
      this.entries.push(event)
    }
  }

  get size(): number {
    return this.entries.length
  }

  get lastHash(): string {
    return this.entries.at(-1)?.hash ?? GENESIS_HASH
  }

  all(): readonly ScgEvent[] {
    return this.entries
  }

  append(
    sessionId: string,
    type: ScgEventType,
    payload: Record<string, unknown>,
    ts: string = new Date().toISOString(),
  ): ScgEvent {
    const seq = this.entries.length + 1
    const base: Omit<ScgEvent, 'hash'> = {
      v: 1,
      seq,
      ts,
      sessionId,
      type,
      payload: pruneUndefined(payload),
      prevHash: this.lastHash,
    }
    const event: ScgEvent = { ...base, hash: computeHash(base) }
    this.entries.push(event)
    this.sink?.(event)
    return event
  }

  verify(expectedHead?: ExpectedHead): VerifyResult {
    let prevHash = GENESIS_HASH
    for (const [index, event] of this.entries.entries()) {
      if (event.seq !== index + 1) {
        return { ok: false, seq: event.seq, error: `unexpected sequence ${event.seq}` }
      }
      if (event.prevHash !== prevHash) {
        return { ok: false, seq: event.seq, error: 'prevHash mismatch' }
      }
      const { hash, ...base } = event
      if (computeHash(base) !== hash) {
        return { ok: false, seq: event.seq, error: 'hash mismatch' }
      }
      prevHash = hash
    }

    if (expectedHead !== undefined) {
      const last = this.entries.at(-1)
      if (
        last === undefined ||
        last.seq !== expectedHead.seq ||
        last.hash !== expectedHead.hash
      ) {
        return {
          ok: false,
          seq: last?.seq,
          error: 'head mismatch: audit log was truncated or replaced',
        }
      }
    }

    return { ok: true }
  }

  private verifyEvent(event: ScgEvent, index: number): void {
    if (event.v !== 1) {
      throw new EventChainError(`unsupported event version: ${event.v}`)
    }
    if (event.seq !== index + 1) {
      throw new EventChainError(
        `event sequence ${event.seq} does not match position ${index + 1}`,
      )
    }
    const expectedPrev = index === 0 ? GENESIS_HASH : this.entries[index - 1].hash
    if (event.prevHash !== expectedPrev) {
      throw new EventChainError(`event ${event.seq} prevHash mismatch`)
    }
    const { hash, ...base } = event
    if (computeHash(base) !== hash) {
      throw new EventChainError(`event ${event.seq} hash mismatch`)
    }
  }
}
