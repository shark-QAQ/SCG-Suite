/**
 * Zero-dependency live audit console.
 *
 *   pnpm console
 *   → http://127.0.0.1:4173
 *
 * Serves a static UI plus:
 *   GET /api/state   current audit events + replay + benchmark
 *   GET /api/stream  SSE tail of the newest audit JSONL
 */
import { createServer } from 'node:http'
import {
  closeSync,
  existsSync,
  openSync,
  readFileSync,
  readSync,
  statSync,
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(here, '..', '..')
const publicDir = join(here, 'public')
const port = Number(process.env.PORT ?? 4173)

const auditCandidates = [
  process.env.SCG_AUDIT_PATH,
  join(repoRoot, '.scg', 'audit.jsonl'),
  join(repoRoot, 'demo', 'out', 'audit.jsonl'),
].filter(Boolean)

function currentAudit() {
  const existing = auditCandidates.filter((path) => existsSync(path))
  if (existing.length === 0) return auditCandidates[1]
  existing.sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)
  return existing[0]
}

function readEvents(path) {
  if (!existsSync(path)) return []
  return readFileSync(path, 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .flatMap((line) => {
      try {
        return [JSON.parse(line)]
      } catch {
        return []
      }
    })
}

function readJson(path) {
  if (!existsSync(path)) return null
  try {
    return JSON.parse(readFileSync(path, 'utf8'))
  } catch {
    return null
  }
}

function sendJson(res, value) {
  res.writeHead(200, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  })
  res.end(JSON.stringify(value))
}

const clients = new Set()
function broadcast(event) {
  const payload = `data: ${JSON.stringify(event)}\n\n`
  for (const client of clients) client.write(payload)
}

let watchPath = currentAudit()
let offset = existsSync(watchPath) ? statSync(watchPath).size : 0

setInterval(() => {
  const path = currentAudit()
  if (path !== watchPath) {
    watchPath = path
    offset = 0
  }
  if (!existsSync(path)) return

  const size = statSync(path).size
  if (size < offset) offset = 0
  if (size === offset) return

  const fd = openSync(path, 'r')
  const chunk = Buffer.alloc(size - offset)
  readSync(fd, chunk, 0, chunk.length, offset)
  closeSync(fd)
  offset = size

  for (const line of chunk.toString('utf8').split(/\r?\n/)) {
    if (!line.trim()) continue
    try {
      broadcast(JSON.parse(line))
    } catch {
      // ignore partial writes
    }
  }
}, 500)

const assets = {
  '/': 'index.html',
  '/index.html': 'index.html',
  '/app.js': 'app.js',
  '/styles.css': 'styles.css',
}

const server = createServer((req, res) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)

  if (url.pathname === '/api/state') {
    const auditPath = currentAudit()
    const isDemoAudit = auditPath
      .replace(/\\/g, '/')
      .includes('/demo/out/')
    sendJson(res, {
      auditPath,
      events: readEvents(auditPath),
      replay: isDemoAudit
        ? readJson(join(repoRoot, 'demo', 'out', 'replay.json'))
        : null,
      bench: readJson(join(repoRoot, 'benchmark', 'out', 'report.json')),
    })
    return
  }

  if (url.pathname === '/api/stream') {
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
    })
    res.write(
      `event: hello\ndata: ${JSON.stringify({ auditPath: currentAudit() })}\n\n`,
    )
    clients.add(res)
    req.on('close', () => clients.delete(res))
    return
  }

  const asset = assets[url.pathname]
  if (!asset) {
    res.writeHead(404, { 'content-type': 'text/plain' })
    res.end('not found')
    return
  }

  const type = asset.endsWith('.css')
    ? 'text/css'
    : asset.endsWith('.js')
      ? 'text/javascript'
      : 'text/html'
  res.writeHead(200, {
    'content-type': `${type}; charset=utf-8`,
    'cache-control': 'no-store',
  })
  res.end(readFileSync(join(publicDir, asset)))
})

server.listen(port, '127.0.0.1', () => {
  console.log(`SCG console: http://127.0.0.1:${port}`)
  console.log(`audit: ${currentAudit()}`)
})
