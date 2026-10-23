import { execSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

import { repoRoot } from './dsh-home.mjs'

const root = resolve(repoRoot)
const normalize = (value) =>
  resolve(value).replace(/\\/g, '/').toLowerCase()
const rootPrefix = `${normalize(root)}/`

const problems = []

// 1. pnpm store must live inside the repository.
const storePath = execSync('pnpm store path', {
  cwd: root,
  encoding: 'utf8',
  stdio: ['ignore', 'pipe', 'ignore'],
}).trim()
if (!normalize(storePath).startsWith(rootPrefix)) {
  problems.push(`pnpm store is outside the repo: ${storePath}`)
}

// 2. Every node_modules/.modules.yaml must point at the repo-local store.
function walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules') {
      const modulesFile = join(dir, entry.name, '.modules.yaml')
      if (existsSync(modulesFile)) {
        const text = readFileSync(modulesFile, 'utf8')
        const match = text.match(/"storeDir":\s*"([^"]+)"/)
        if (match) {
          const storeDir = match[1].replace(/\\\\/g, '\\')
          if (!normalize(storeDir).startsWith(rootPrefix)) {
            problems.push(
              `node_modules points outside the repo: ${modulesFile} -> ${storeDir}`,
            )
          }
        }
      }
      continue
    }
    if (
      entry.isDirectory() &&
      !['.git', '.cache', '.dsh-home', '.venv', 'demo'].includes(entry.name)
    ) {
      walk(join(dir, entry.name))
    }
  }
}
walk(root)

// 3. A project-local DSH_HOME, when set, must not be ~/.dsh.
if (process.env.DSH_HOME) {
  const dshHome = normalize(process.env.DSH_HOME)
  const userDsh = normalize(join(process.env.USERPROFILE ?? '', '.dsh'))
  if (dshHome === userDsh) {
    problems.push('DSH_HOME points at the user DSH home (~/.dsh)')
  } else if (!dshHome.startsWith(rootPrefix)) {
    problems.push(`DSH_HOME is outside the repo: ${process.env.DSH_HOME}`)
  }
}

if (problems.length > 0) {
  console.error('Isolation check failed:')
  for (const problem of problems) console.error(`  - ${problem}`)
  process.exit(1)
}

console.log(`Isolation OK`)
console.log(`  repo:  ${root}`)
console.log(`  store: ${storePath}`)
