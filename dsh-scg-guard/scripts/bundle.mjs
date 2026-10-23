import { copyFileSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '..')

// The bundled core resolves ../policies/agent-guard.json relative to dist/index.js.
mkdirSync(join(root, 'policies'), { recursive: true })
copyFileSync(
  join(root, '..', 'packages', 'scg-core', 'policies', 'agent-guard.json'),
  join(root, 'policies', 'agent-guard.json'),
)

await build({
  entryPoints: [join(root, 'src', 'index.ts')],
  outfile: join(root, 'dist', 'index.js'),
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  sourcemap: true,
  external: ['@cedar-policy/cedar-wasm', '@cedar-policy/cedar-wasm/nodejs'],
  logLevel: 'info',
})
