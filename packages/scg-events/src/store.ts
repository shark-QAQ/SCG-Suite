import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs'
import { dirname } from 'node:path'
import type { ExpectedHead } from './log.js'
import type { ScgEvent } from './types.js'

/** JSONL 审计存储：一行一个事件，便于追加写、grep 和导出。 */
export class JsonlEventStore {
  constructor(readonly filePath: string) {}

  get headPath(): string {
    return `${this.filePath}.head`
  }

  load(): ScgEvent[] {
    if (!existsSync(this.filePath)) return []
    const content = readFileSync(this.filePath, 'utf8')
    const events: ScgEvent[] = []

    for (const [index, line] of content.split(/\r?\n/).entries()) {
      if (!line.trim()) continue
      try {
        events.push(JSON.parse(line) as ScgEvent)
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        throw new Error(`invalid JSONL at line ${index + 1}: ${message}`)
      }
    }
    return events
  }

  loadHead(): ExpectedHead | null {
    if (!existsSync(this.headPath)) return null
    try {
      const parsed = JSON.parse(readFileSync(this.headPath, 'utf8')) as ExpectedHead
      if (
        Number.isInteger(parsed.seq) &&
        parsed.seq > 0 &&
        typeof parsed.hash === 'string'
      ) {
        return parsed
      }
    } catch {
      // A corrupt sidecar is treated as absent; the chain itself is still checked.
    }
    return null
  }

  append(event: ScgEvent): void {
    mkdirSync(dirname(this.filePath), { recursive: true })
    appendFileSync(this.filePath, `${JSON.stringify(event)}\n`, 'utf8')
    // The sidecar detects accidental truncation of the JSONL tail.
    writeFileSync(
      this.headPath,
      JSON.stringify({ seq: event.seq, hash: event.hash }),
      'utf8',
    )
  }
}
