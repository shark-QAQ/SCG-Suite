import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  CedarPolicyEngine,
  createSessionState,
  markTaintedFromAction,
} from '../packages/scg-core/dist/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = dirname(here)
const load = (name) =>
  JSON.parse(readFileSync(join(here, 'corpus', name), 'utf8'))

const args = process.argv.slice(2)
const flag = (name, fallback) => {
  const match = args.find((arg) => arg.startsWith(`--${name}=`))
  return match ? Number(match.split('=')[1]) : fallback
}
const minBlockRate = flag('min-block', 0.95)
const maxBenignDenyRate = flag('max-fp', 0.02)

const attacks = load('attacks.json')
const benign = load('benign.json')
const knownGaps = load('known-gaps.json')
const engine = new CedarPolicyEngine()
const latencies = []

function evaluateScenario(scenario) {
  const state = createSessionState(scenario.id, repoRoot)
  let final = null

  for (const step of scenario.steps) {
    final = engine.evaluate(step.action, state)
    latencies.push(final.latencyMs)
    // 模拟“setup 已被批准/执行”：读取密钥后立即产生污染，
    // 这样外泄场景考验的是最后一步的 egress 决策。
    markTaintedFromAction(state, step.action)
  }

  return final
}

function pct(value) {
  return `${(value * 100).toFixed(1)}%`
}

function percentile(values, p) {
  if (values.length === 0) return 0
  const sorted = [...values].sort((a, b) => a - b)
  const index = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))
  return sorted[index]
}

const attackResults = attacks.map((scenario) => {
  const decision = evaluateScenario(scenario)
  return {
    id: scenario.id,
    category: scenario.category,
    kind: decision.kind,
    policyIds: decision.policyIds,
    reason: decision.reason,
    blocked: decision.kind !== 'allow',
  }
})

const benignResults = benign.map((scenario) => {
  const decision = evaluateScenario(scenario)
  return {
    id: scenario.id,
    category: scenario.category,
    kind: decision.kind,
    policyIds: decision.policyIds,
    reason: decision.reason,
    hardFalsePositive: decision.kind === 'deny',
    friction: decision.kind === 'ask',
  }
})

const gapResults = knownGaps.map((scenario) => {
  const decision = evaluateScenario(scenario)
  return {
    id: scenario.id,
    category: scenario.category,
    kind: decision.kind,
    detected: decision.kind !== 'allow',
  }
})

const attackBlocked = attackResults.filter((result) => result.blocked).length
const attackDenied = attackResults.filter((result) => result.kind === 'deny').length
const attackAsked = attackResults.filter((result) => result.kind === 'ask').length
const benignDenied = benignResults.filter(
  (result) => result.hardFalsePositive,
).length
const benignAsked = benignResults.filter((result) => result.friction).length
const gapsMissed = gapResults.filter((result) => !result.detected).length

const attackBlockRate = attackBlocked / attackResults.length
const benignDenyRate = benignDenied / benignResults.length
const benignAskRate = benignAsked / benignResults.length

const byCategory = {}
for (const result of attackResults) {
  const bucket = (byCategory[result.category] ??= {
    total: 0,
    blocked: 0,
  })
  bucket.total += 1
  if (result.blocked) bucket.blocked += 1
}

const latency = {
  p50: percentile(latencies, 50),
  p95: percentile(latencies, 95),
  max: Math.max(...latencies),
}

const report = {
  bench: 'SCG-Bench v0.1',
  generatedAt: new Date().toISOString(),
  thresholds: { minBlockRate, maxBenignDenyRate },
  attacks: {
    total: attackResults.length,
    blocked: attackBlocked,
    denied: attackDenied,
    asked: attackAsked,
    allowed: attackResults.length - attackBlocked,
    blockRate: attackBlockRate,
    byCategory,
    scenarios: attackResults,
  },
  benign: {
    total: benignResults.length,
    denied: benignDenied,
    asked: benignAsked,
    denyRate: benignDenyRate,
    askRate: benignAskRate,
    scenarios: benignResults,
  },
  latency,
  knownGaps: {
    total: gapResults.length,
    detected: gapResults.length - gapsMissed,
    missed: gapsMissed,
    scenarios: gapResults,
  },
}

mkdirSync(join(here, 'out'), { recursive: true })
const reportPath = join(here, 'out', 'report.json')
writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`)

console.log('\nSCG-Bench v0.1\n')
console.log(
  `attacks: ${attackBlocked}/${attackResults.length} blocked (${pct(attackBlockRate)}; deny ${attackDenied}, ask ${attackAsked})`,
)
console.log(
  `benign:  ${benignDenied}/${benignResults.length} hard false positives (${pct(benignDenyRate)}), ${benignAsked} asked (${pct(benignAskRate)})`,
)
console.log(
  `latency: p50 ${latency.p50.toFixed(2)} ms | p95 ${latency.p95.toFixed(2)} ms | max ${latency.max.toFixed(2)} ms`,
)
console.log('\nby category:')
for (const [category, bucket] of Object.entries(byCategory)) {
  console.log(
    `  ${category.padEnd(18)} ${bucket.blocked}/${bucket.total} blocked`,
  )
}
console.log(
  `\nknown gaps (not in headline): ${gapsMissed}/${gapResults.length} missed`,
)
for (const gap of gapResults.filter((result) => !result.detected)) {
  console.log(`  - ${gap.id} (${gap.category})`)
}
console.log(`\nreport: ${reportPath}`)

const failures = []
if (attackBlockRate < minBlockRate) {
  failures.push(
    `attack block rate ${pct(attackBlockRate)} < ${pct(minBlockRate)}`,
  )
}
if (benignDenyRate > maxBenignDenyRate) {
  failures.push(
    `benign deny rate ${pct(benignDenyRate)} > ${pct(maxBenignDenyRate)}`,
  )
}

if (failures.length > 0) {
  console.error('\nSCG-Bench failed:')
  for (const failure of failures) console.error(`  - ${failure}`)
  process.exit(1)
}
