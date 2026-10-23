import { execSync, spawn } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs'
import net from 'node:net'
import { join } from 'node:path'

import { defaultDshHome, findDshBin, repoRoot, setupDshHome } from './dsh-home.mjs'

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function findFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      const port = typeof address === 'object' && address ? address.port : 0
      server.close(() => resolve(port))
    })
  })
}

/** A Windows DSH child can outlive its parent; clean up by port owner. */
function killPortOwner(port) {
  if (process.platform !== 'win32') return
  try {
    const lines = execSync('netstat -ano', { encoding: 'utf8' }).split(/\r?\n/)
    const pids = new Set()
    for (const line of lines) {
      if (!line.includes(`:${port}`) || !line.includes('LISTENING')) continue
      const pid = line.trim().split(/\s+/).pop()
      if (/^\d+$/.test(pid)) pids.add(pid)
    }
    for (const pid of pids) {
      try {
        execSync(`taskkill /F /T /PID ${pid}`, { stdio: 'ignore' })
      } catch {
        // already gone
      }
    }
  } catch {
    // best effort
  }
}

const { home } = setupDshHome(defaultDshHome())
const dsh = findDshBin()

if (!dsh) {
  console.warn(
    'DSH CLI not found. Install DSH Desktop, or set DSH_BIN=/path/to/@deepseek-ai/dsh/lib/bin.js.',
  )
  process.exit(process.env.SCG_REQUIRE_DSH === '1' ? 1 : 0)
}

const auditPath = join(repoRoot, '.scg', 'audit.jsonl')
// Preserve audit-desktop.jsonl written by the running Desktop app.
mkdirSync(join(repoRoot, '.scg'), { recursive: true })
// Remove the head sidecar too: a stale sidecar with a missing JSONL is
// correctly treated as a truncated log, which would fail closed.
rmSync(auditPath, { force: true })
rmSync(`${auditPath}.head`, { force: true })

const port = await findFreePort()
killPortOwner(port)

const child = spawn(
  dsh.command,
  [...dsh.args, '--profile', 'web', '--port', String(port)],
  {
    cwd: repoRoot,
    env: { ...process.env, ...dsh.env, DSH_HOME: home },
    stdio: ['ignore', 'pipe', 'pipe'],
  },
)

let output = ''
child.stdout.on('data', (chunk) => {
  output += String(chunk)
})
child.stderr.on('data', (chunk) => {
  output += String(chunk)
})

const deadline = Date.now() + 30_000
let startupEvent = null

while (Date.now() < deadline) {
  if (existsSync(auditPath)) {
    const lines = readFileSync(auditPath, 'utf8')
      .split(/\r?\n/)
      .filter(Boolean)
    for (const line of lines) {
      try {
        const event = JSON.parse(line)
        if (event.type === 'runtime.start') {
          startupEvent = event
          break
        }
      } catch {
        // ignore partial writes while DSH is starting
      }
    }
    if (startupEvent) break
  }
  await sleep(500)
}

if (process.platform === 'win32') {
  spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], {
    stdio: 'ignore',
  })
} else {
  child.kill('SIGTERM')
}
await sleep(700)
killPortOwner(port)

if (!startupEvent) {
  console.error('DSH did not load dsh-scg-guard within 30s.')
  if (output.trim()) console.error(output.trim().slice(-2000))
  process.exit(1)
}

console.log(`DSH loaded plugin: ${JSON.stringify(startupEvent.payload)}`)
console.log(`audit: ${auditPath}`)

if (startupEvent.payload?.engine !== 'cedar') {
  console.error('Plugin loaded, but the Cedar policy engine was unavailable.')
  process.exit(1)
}

process.exit(0)
