import { execSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const guardVersion = JSON.parse(
  readFileSync(resolve(repoRoot, 'dsh-scg-guard', 'package.json'), 'utf8'),
).version
const skipDsh = process.argv.includes('--skip-dsh')

const steps = [
  ['Isolation check', 'pnpm check:isolation'],
  ['TypeScript tests', 'pnpm test'],
  ['SCG-Bench', 'pnpm bench'],
  ['Rogue Agent policy demo', 'pnpm demo'],
  ['Static dashboard', 'node apps/console/generate.mjs'],
  ['Self-contained bundle', 'pnpm pack:bundle'],
]

if (!skipDsh) {
  steps.push(['Real DSH load', 'pnpm dsh:verify'])
  steps.push(['Headless E2E (mock model)', 'pnpm e2e'])
}

console.log('SCG Runtime — full demo')
console.log(`repo: ${repoRoot}`)
console.log(skipDsh ? 'DSH steps: skipped (--skip-dsh)' : 'DSH steps: enabled')

try {
  for (const [label, command] of steps) {
    console.log(`\n${'='.repeat(64)}\n${label}\n${'='.repeat(64)}`)
    execSync(command, { cwd: repoRoot, stdio: 'inherit' })
  }
} catch (error) {
  console.error('\nDemo failed. Fix the failing step above and rerun.')
  process.exit(1)
}

console.log(`\n${'='.repeat(64)}\nArtifacts\n${'='.repeat(64)}`)
console.log('static dashboard : demo/out/dashboard.html')
console.log('benchmark report : benchmark/out/report.json')
console.log(
  `bundle tarball   : dsh-scg-guard/dsh-scg-guard-${guardVersion}.tgz`,
)
if (!skipDsh) {
  console.log('live audit log   : .scg/audit.jsonl')
}
console.log('\nNext: run `pnpm console` and open http://127.0.0.1:4173')
console.log('Python tests: cd SCG && uv run pytest -q')
