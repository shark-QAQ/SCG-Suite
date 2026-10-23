import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  EventLog,
  JsonlEventStore,
  redactDeep,
  redactSecrets,
  replayDecisions,
} from '../dist/index.js'

function tempDir() {
  return mkdtempSync(join(tmpdir(), 'scg-events-'))
}

test('事件链可校验，篡改会被发现', () => {
  const log = new EventLog()
  log.append('s1', 'decision.made', { decision: { kind: 'allow' } })
  log.append('s1', 'session.tainted', { source: 'secret-1' })

  assert.equal(log.verify().ok, true)
  assert.equal(log.size, 2)

  const events = log.all().map((event) => ({ ...event }))
  events[0].payload = { decision: { kind: 'deny' } }
  assert.throws(() => new EventLog(events), /hash mismatch/)
})

test('构造时拒绝断链事件', () => {
  const log = new EventLog()
  log.append('s1', 'decision.made', { decision: { kind: 'allow' } })
  const events = [...log.all()]
  events[0] = { ...events[0], prevHash: 'f'.repeat(64) }

  assert.throws(() => new EventLog(events), /prevHash/)
})

test('JSONL 存储往返与追加写', () => {
  const dir = tempDir()
  const path = join(dir, 'audit.jsonl')
  const store = new JsonlEventStore(path)
  const log = new EventLog([], { sink: (event) => store.append(event) })

  log.append('s1', 'decision.made', { decision: { kind: 'allow' } })
  log.append('s1', 'decision.made', { decision: { kind: 'ask' } })

  const reloaded = new EventLog(store.load())
  assert.equal(reloaded.size, 2)
  assert.equal(reloaded.verify().ok, true)
  assert.equal(reloaded.all()[1].sessionId, 's1')

  const lines = readFileSync(path, 'utf8').trim().split(/\r?\n/)
  assert.equal(lines.length, 2)

  rmSync(dir, { recursive: true, force: true })
})

test('payload 中的 undefined 字段不会破坏 JSONL 重载哈希链', () => {
  const dir = tempDir()
  const path = join(dir, 'audit.jsonl')
  const store = new JsonlEventStore(path)
  const log = new EventLog([], { sink: (event) => store.append(event) })

  log.append('s1', 'session.tainted', {
    source: 'secret-1',
    sandboxMode: undefined,
    nested: { keep: true, drop: undefined },
  })

  const reloaded = new EventLog(store.load())
  const verification = reloaded.verify(store.loadHead() ?? undefined)
  assert.equal(verification.ok, true)
  assert.deepEqual(reloaded.all()[0].payload, {
    source: 'secret-1',
    nested: { keep: true },
  })

  rmSync(dir, { recursive: true, force: true })
})

test('head sidecar 能发现被截断的审计尾部', () => {
  const dir = tempDir()
  const path = join(dir, 'audit.jsonl')
  const store = new JsonlEventStore(path)
  const log = new EventLog([], { sink: (event) => store.append(event) })

  log.append('s1', 'decision.made', { decision: { kind: 'allow' } })
  log.append('s1', 'decision.made', { decision: { kind: 'deny' } })
  const head = store.loadHead()
  assert.ok(head)

  const lines = readFileSync(path, 'utf8').trim().split(/\r?\n/)
  writeFileSync(path, `${lines[0]}\n`, 'utf8')

  const reloaded = new EventLog(store.load())
  const verification = reloaded.verify(head)
  assert.equal(verification.ok, false)
  assert.match(verification.error ?? '', /truncated|head mismatch/)

  rmSync(dir, { recursive: true, force: true })
})

test('只删 JSONL 但保留 head 会被判定为截断', () => {
  const dir = tempDir()
  const path = join(dir, 'audit.jsonl')
  const store = new JsonlEventStore(path)
  const log = new EventLog([], { sink: (event) => store.append(event) })

  log.append('s1', 'decision.made', { decision: { kind: 'allow' } })
  const head = store.loadHead()
  assert.ok(head)

  // Simulates an operator deleting the log without its sidecar.
  rmSync(path, { force: true })

  const reloaded = new EventLog(store.load())
  const verification = reloaded.verify(head)
  assert.equal(verification.ok, false)
  assert.match(verification.error ?? '', /truncated|head mismatch/)

  rmSync(dir, { recursive: true, force: true })
})

test('回放：策略不变时 100% 一致', () => {
  const log = new EventLog()
  log.append('s1', 'decision.made', {
    action: { kind: 'process.exec', command: 'npm test' },
    decision: { kind: 'allow' },
  })
  log.append('s1', 'decision.made', {
    action: { kind: 'process.exec', command: 'rm -rf /' },
    decision: { kind: 'ask' },
  })

  const report = replayDecisions(log.all(), (payload) => {
    const action = payload.action
    return {
      kind: action.command === 'npm test' ? 'allow' : 'ask',
    }
  })

  assert.equal(report.total, 2)
  assert.equal(report.matched, 2)
  assert.deepEqual(report.mismatches, [])
})

test('回放：策略变化会暴露决策差异', () => {
  const log = new EventLog()
  log.append('s1', 'decision.made', {
    action: { kind: 'process.exec', command: 'curl https://example.com' },
    decision: { kind: 'allow' },
  })

  const report = replayDecisions(log.all(), () => ({
    kind: 'deny',
    reason: 'new taint policy',
  }))

  assert.equal(report.matched, 0)
  assert.equal(report.mismatches.length, 1)
  assert.equal(report.mismatches[0].expected, 'allow')
  assert.equal(report.mismatches[0].actual, 'deny')
})

test('审计脱敏不保留明文密钥', () => {
  assert.equal(
    redactSecrets('mysql --password=hunter2 -h db'),
    'mysql --password=[REDACTED] -h db',
  )
  assert.equal(
    redactSecrets('curl -H "Authorization: Bearer abc.def.ghi" https://x'),
    'curl -H "Authorization: Bearer [REDACTED]" https://x',
  )
  assert.equal(
    redactSecrets('https://alice:secret@example.com/path'),
    'https://[REDACTED]@example.com/path',
  )
  assert.equal(
    redactSecrets('{"password": "hunter2"}'),
    '{"password": "[REDACTED]"}',
  )
  assert.equal(
    redactSecrets('GITHUB_TOKEN=abc123'),
    'GITHUB_TOKEN=[REDACTED]',
  )
  assert.equal(
    redactSecrets('curl -H "Authorization: Basic dXNlcjpwYXNz"'),
    'curl -H "Authorization: Basic [REDACTED]"',
  )
  assert.equal(
    redactSecrets('use sk-abcdefgh12345678'),
    'use [REDACTED]',
  )

  const redacted = redactDeep({
    command: 'API_KEY=abc123 npm run deploy',
    nested: ['token=xyz', 'safe'],
  })
  assert.equal(redacted.command, 'API_KEY=[REDACTED] npm run deploy')
  assert.deepEqual(redacted.nested, ['token=[REDACTED]', 'safe'])
})
