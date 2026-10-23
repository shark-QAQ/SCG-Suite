import { createHash } from 'node:crypto'

/**
 * Recursively remove object properties whose value is undefined.
 *
 * JSON.stringify drops those keys, so keeping them in memory (and in the
 * hash input) makes a reloaded chain hash differently. Arrays keep `null`
 * placeholders to match JSON.stringify semantics.
 */
export function pruneUndefined<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((entry) =>
      entry === undefined ? null : pruneUndefined(entry),
    ) as T
  }
  if (value !== null && typeof value === 'object') {
    const result: Record<string, unknown> = {}
    for (const [key, entry] of Object.entries(
      value as Record<string, unknown>,
    )) {
      if (entry === undefined) continue
      result[key] = pruneUndefined(entry)
    }
    return result as T
  }
  return value
}

/** 稳定序列化：对象键排序，保证同一 payload 得到同一哈希。 */
export function stableStringify(value: unknown): string {
  if (value === undefined) return 'null'
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`
  }
  const record = value as Record<string, unknown>
  const keys = Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
  return `{${keys
    .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
    .join(',')}}`
}

export function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex')
}

export const GENESIS_HASH = '0'.repeat(64)
