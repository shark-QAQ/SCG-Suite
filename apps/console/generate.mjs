/**
 * 生成自包含的静态审计控制台（无服务器、无外部资源）。
 *
 *   pnpm dashboard
 *   → demo/out/dashboard.html
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { EventLog } from '../../packages/scg-events/dist/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(here, '..', '..')
const outDir = join(repoRoot, 'demo', 'out')
const auditPath = process.argv[2]
  ? resolve(process.argv[2])
  : join(outDir, 'audit.jsonl')
const replayPath = join(outDir, 'replay.json')
const benchPath = join(repoRoot, 'benchmark', 'out', 'report.json')

if (!existsSync(auditPath)) {
  console.error(`audit log not found: ${auditPath}`)
  console.error('run `pnpm demo` first')
  process.exit(1)
}

const events = readFileSync(auditPath, 'utf8')
  .split(/\r?\n/)
  .filter(Boolean)
  .map((line) => JSON.parse(line))

let chainValid = true
let chainError = ''
try {
  const log = new EventLog(events)
  const result = log.verify()
  chainValid = result.ok
  if (!result.ok) chainError = result.error ?? 'invalid'
} catch (error) {
  chainValid = false
  chainError = error instanceof Error ? error.message : String(error)
}

const replay = existsSync(replayPath)
  ? JSON.parse(readFileSync(replayPath, 'utf8'))
  : null
const bench = existsSync(benchPath)
  ? JSON.parse(readFileSync(benchPath, 'utf8'))
  : null

const decisions = events.filter((event) => event.type === 'decision.made')
const denies = decisions.filter(
  (event) => event.payload?.decision?.kind === 'deny',
)
const allows = decisions.filter(
  (event) => event.payload?.decision?.kind === 'allow',
).length

const latencies = decisions
  .map((event) => Number(event.payload?.decision?.latencyMs ?? 0))
  .sort((a, b) => a - b)
const p95 =
  latencies.length > 0
    ? latencies[Math.min(latencies.length - 1, Math.floor(latencies.length * 0.95))]
    : 0

const escapeHtml = (value) =>
  String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')

function actionLabel(action) {
  if (!action) return 'unknown action'
  if (action.kind === 'process.exec') return `$ ${action.command ?? ''}`
  if (action.kind === 'fs.read') return `read ${action.path ?? ''}`
  if (action.kind === 'fs.write') return `write ${action.path ?? ''}`
  if (action.kind === 'network.connect') return `network ${action.target ?? ''}`
  return `${action.kind} ${action.tool ?? ''}`
}

function badge(kind) {
  const label =
    kind === 'deny' ? 'DENY' : kind === 'ask' ? 'ASK' : 'ALLOW'
  return `<span class="badge ${kind}">${label}</span>`
}

function riskPill(level) {
  return `<span class="risk ${level}">${level}</span>`
}

const timeline = decisions
  .map((event) => {
    const decision = event.payload.decision
    const action = event.payload.action
    const policies = (decision.policyIds ?? [])
      .map((id) => `<code>${escapeHtml(id)}</code>`)
      .join(' ')
    return `
      <article class="event ${decision.kind}">
        <div class="event-head">
          <span class="seq">#${event.seq}</span>
          ${badge(decision.kind)}
          ${riskPill(decision.risk?.level ?? 'low')}
          <span class="latency">${Number(decision.latencyMs ?? 0).toFixed(2)} ms</span>
        </div>
        <div class="command">${escapeHtml(actionLabel(action))}</div>
        <div class="reason">${escapeHtml(decision.reason ?? '')}</div>
        <div class="policies">${policies}</div>
      </article>`
  })
  .join('')

const taintedSource = decisions
  .flatMap((event) => event.payload?.state?.taintSources ?? [])
  .find(Boolean)
const blockedEgress = denies.find((event) =>
  (event.payload?.decision?.policyIds ?? []).includes('deny-tainted-egress'),
)
const secretPath =
  taintedSource?.path ??
  decisions
    .map((event) => event.payload?.action)
    .find((action) => action?.kind === 'fs.read' && action?.path?.includes('.env'))
    ?.path ??
  'secret'

const taintChain = blockedEgress
  ? `
    <div class="chain-row">
      <div class="node secret"><small>SECRET</small>${escapeHtml(secretPath)}</div>
      <div class="arrow">read</div>
      <div class="node taint"><small>SESSION</small>tainted</div>
      <div class="arrow">egress</div>
      <div class="node blocked"><small>BLOCKED</small>${escapeHtml(actionLabel(blockedEgress.payload.action))}</div>
    </div>`
  : '<p class="muted">No tainted egress attempt recorded.</p>'

function replayBlock(report, label) {
  if (!report) return ''
  const percent = report.total > 0 ? Math.round((report.matched / report.total) * 100) : 100
  const mismatches = (report.mismatches ?? [])
    .map(
      (mismatch) =>
        `<li>seq ${mismatch.seq}: recorded <code>${escapeHtml(mismatch.expected)}</code> → replayed <code>${escapeHtml(mismatch.actual)}</code></li>`,
    )
    .join('')
  return `
    <div class="replay-row">
      <div class="replay-head">
        <span>${escapeHtml(label)}</span>
        <strong>${report.matched}/${report.total} matched</strong>
      </div>
      <div class="bar"><span style="width:${percent}%"></span></div>
      ${mismatches ? `<ul class="mismatches">${mismatches}</ul>` : ''}
    </div>`
}

const benchBlock = bench
  ? `
    <div class="bench-metrics">
      <div><small>ATTACKS BLOCKED</small><strong>${bench.attacks.blocked}/${bench.attacks.total}</strong></div>
      <div><small>HARD FALSE POSITIVES</small><strong>${bench.benign.denied}/${bench.benign.total}</strong></div>
      <div><small>P95 DECISION</small><strong>${bench.latency.p95.toFixed(2)} ms</strong></div>
      <div><small>KNOWN GAPS</small><strong>${bench.knownGaps.missed}/${bench.knownGaps.total}</strong></div>
    </div>
    <p class="muted">Known gaps are reported separately; they are the reason Phase 1 must wire ctx.sandbox.</p>`
  : '<p class="muted">Run <code>pnpm bench</code> to populate this panel.</p>'

const html = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SCG Runtime — Audit Replay</title>
<style>
  :root {
    --bg: #080d18;
    --panel: #101a2c;
    --panel-2: #0c1423;
    --line: #1f3050;
    --text: #e2ecff;
    --muted: #8194b5;
    --green: #34d399;
    --amber: #fbbf24;
    --red: #fb7185;
    --blue: #60a5fa;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: radial-gradient(circle at 20% -10%, #14213d 0, transparent 40%),
                radial-gradient(circle at 100% 0, #1b1230 0, transparent 35%),
                var(--bg);
    color: var(--text);
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    min-height: 100vh;
  }
  header {
    padding: 32px 40px 24px;
    border-bottom: 1px solid var(--line);
    display: flex;
    align-items: center;
    gap: 20px;
    flex-wrap: wrap;
  }
  .brand { font-size: 24px; font-weight: 800; letter-spacing: -0.03em; }
  .brand span { color: var(--blue); }
  .subtitle { color: var(--muted); }
  .chain {
    margin-left: auto;
    font: 12px var(--mono);
    padding: 8px 12px;
    border-radius: 999px;
    border: 1px solid var(--line);
  }
  .chain.valid { color: var(--green); border-color: #145c43; background: #07261c; }
  .chain.invalid { color: var(--red); border-color: #6b1d2c; background: #2a0b12; }
  main { max-width: 1180px; margin: 0 auto; padding: 28px 32px 60px; }
  .metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 22px; }
  .metric {
    background: linear-gradient(180deg, var(--panel), var(--panel-2));
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 16px 18px;
  }
  .metric label { display: block; color: var(--muted); font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase; }
  .metric strong { font-size: 26px; font-weight: 700; }
  .metric.deny strong { color: var(--red); }
  .metric.allow strong { color: var(--green); }
  .grid { display: grid; grid-template-columns: 1.4fr 1fr; gap: 18px; align-items: start; }
  .panel {
    background: rgba(16, 26, 44, 0.86);
    border: 1px solid var(--line);
    border-radius: 16px;
    padding: 20px;
    margin-bottom: 18px;
  }
  .panel h2 { margin: 0 0 14px; font-size: 13px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--muted); }
  .event {
    border: 1px solid var(--line);
    border-left: 3px solid var(--green);
    background: var(--panel-2);
    border-radius: 10px;
    padding: 14px 16px;
    margin-bottom: 10px;
  }
  .event.deny { border-left-color: var(--red); }
  .event.ask { border-left-color: var(--amber); }
  .event-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
  .seq { font: 12px var(--mono); color: var(--muted); }
  .badge { font: 700 10px var(--mono); letter-spacing: 0.08em; padding: 4px 8px; border-radius: 6px; }
  .badge.deny { color: var(--red); background: #2a0b12; border: 1px solid #6b1d2c; }
  .badge.ask { color: var(--amber); background: #2a1d06; border: 1px solid #6b541d; }
  .badge.allow { color: var(--green); background: #07261c; border: 1px solid #145c43; }
  .risk { font: 10px var(--mono); color: var(--muted); border: 1px solid var(--line); border-radius: 999px; padding: 2px 8px; }
  .risk.critical { color: var(--red); border-color: #6b1d2c; }
  .risk.high { color: var(--amber); border-color: #6b541d; }
  .latency { margin-left: auto; font: 11px var(--mono); color: var(--muted); }
  .command { font: 13px var(--mono); color: var(--text); white-space: pre-wrap; word-break: break-word; }
  .reason { color: var(--muted); margin-top: 6px; }
  .policies { margin-top: 8px; display: flex; gap: 6px; flex-wrap: wrap; }
  .policies code, .mismatches code { font: 11px var(--mono); color: var(--blue); background: #0a1628; border: 1px solid var(--line); border-radius: 5px; padding: 2px 6px; }
  .chain-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin: 8px 0 20px; }
  .node { border: 1px solid var(--line); background: var(--panel-2); border-radius: 10px; padding: 10px 12px; font: 12px var(--mono); }
  .node small { display: block; color: var(--muted); font-size: 9px; letter-spacing: 0.1em; }
  .node.secret { border-color: #6b541d; color: var(--amber); }
  .node.taint { border-color: #6b541d; color: var(--amber); }
  .node.blocked { border-color: #6b1d2c; color: var(--red); }
  .arrow { color: var(--muted); font: 11px var(--mono); }
  .replay-row { margin-bottom: 16px; }
  .replay-head { display: flex; justify-content: space-between; gap: 10px; color: var(--muted); }
  .replay-head strong { color: var(--text); font: 12px var(--mono); }
  .bar { height: 7px; background: #07101d; border: 1px solid var(--line); border-radius: 999px; margin-top: 8px; overflow: hidden; }
  .bar span { display: block; height: 100%; background: linear-gradient(90deg, var(--green), var(--blue)); }
  .layers { display: grid; gap: 10px; }
  .layer { display: flex; gap: 10px; align-items: flex-start; border: 1px solid var(--line); background: var(--panel-2); border-radius: 10px; padding: 10px 12px; }
  .layer strong { display: block; font-size: 12px; }
  .layer small { color: var(--muted); }
  .dot { width: 9px; height: 9px; border-radius: 50%; margin-top: 5px; flex: none; }
  .dot.l1 { background: var(--green); }
  .dot.l2 { background: var(--amber); }
  .dot.l3 { background: var(--blue); }
  .mismatches { margin: 10px 0 0; padding-left: 18px; color: var(--muted); }
  .mismatches li { margin: 4px 0; }
  .bench-metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
  .bench-metrics small { display: block; color: var(--muted); font-size: 10px; letter-spacing: 0.08em; }
  .bench-metrics strong { font-size: 20px; }
  .muted { color: var(--muted); }
  footer { color: var(--muted); font: 11px var(--mono); padding: 0 32px 40px; max-width: 1180px; margin: 0 auto; }
  @media (max-width: 900px) {
    .grid, .metrics, .bench-metrics { grid-template-columns: 1fr 1fr; }
  }
  @media (max-width: 560px) {
    .grid, .metrics, .bench-metrics { grid-template-columns: 1fr; }
    header { padding: 24px 20px; }
    main { padding: 20px; }
  }
</style>
</head>
<body>
<header>
  <div class="brand">SCG<span>Runtime</span></div>
  <div class="subtitle">The Rogue Coding Agent · audit replay</div>
  <div class="chain ${chainValid ? 'valid' : 'invalid'}">hash chain ${chainValid ? 'VALID' : `BROKEN: ${escapeHtml(chainError)}`}</div>
</header>
<main>
  <section class="metrics">
    <div class="metric"><label>decisions</label><strong>${decisions.length}</strong></div>
    <div class="metric deny"><label>denied</label><strong>${denies.length}</strong></div>
    <div class="metric allow"><label>allowed</label><strong>${allows}</strong></div>
    <div class="metric"><label>p95 decision</label><strong>${p95.toFixed(2)} ms</strong></div>
  </section>

  <section class="grid">
    <div>
      <div class="panel">
        <h2>Decision timeline</h2>
        ${timeline || '<p class="muted">No decision events.</p>'}
      </div>
    </div>
    <div>
      <div class="panel">
        <h2>Taint chain</h2>
        ${taintChain}
      </div>
      <div class="panel">
        <h2>Defense in depth</h2>
        <div class="layers">
          <div class="layer"><span class="dot l1"></span><div><strong>L1 · Cedar policy</strong><small>tool call allow / ask / deny</small></div></div>
          <div class="layer"><span class="dot l2"></span><div><strong>L2 · DSH sandbox</strong><small>taint → read-only file effects</small></div></div>
          <div class="layer"><span class="dot l2"></span><div><strong>L2.5 · Egress proxy</strong><small>proxy-aware egress blocked</small></div></div>
          <div class="layer"><span class="dot l3"></span><div><strong>L3 · Hash-chain audit</strong><small>deterministic replay</small></div></div>
        </div>
      </div>
      <div class="panel">
        <h2>Deterministic replay</h2>
        ${replayBlock(replay?.same, 'with recorded approvals')}
        ${replayBlock(replay?.withoutApprovals, 'after approvals revoked')}
        ${replay ? '' : '<p class="muted">Run <code>pnpm demo</code> to populate replay data.</p>'}
      </div>
    </div>
  </section>

  <section class="panel">
    <h2>SCG-Bench v0.1</h2>
    ${benchBlock}
  </section>
</main>
<footer>
  generated ${escapeHtml(new Date().toISOString())} · audit ${escapeHtml(auditPath)}<br>
  SCG Runtime · DSH adapter · Cedar WASM · hash-chained audit
</footer>
</body>
</html>
`

writeFileSync(join(outDir, 'dashboard.html'), html)
console.log(`dashboard: ${join(outDir, 'dashboard.html')}`)
