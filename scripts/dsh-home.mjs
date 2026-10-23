import {
  existsSync,
  mkdirSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
export const pluginDir = join(repoRoot, 'dsh-scg-guard')

export function defaultDshHome() {
  return join(repoRoot, '.dsh-home')
}

/**
 * 在项目内创建一个可复现的 DSH web profile：
 * - 不修改 ~/.dsh
 * - 通过 junction/symlink 链接当前插件
 * - 把插件加入 dsh.profile.bundles（否则只会安装、不会启用）
 */
export function setupDshHome(home = defaultDshHome()) {
  const resolvedHome = resolve(home)
  const userHome = resolve(process.env.USERPROFILE ?? '', '.dsh')
  if (resolvedHome.toLowerCase() === userHome.toLowerCase()) {
    throw new Error('refusing to modify the user DSH home; use a project-local DSH_HOME')
  }

  const profileDir = join(resolvedHome, 'profiles', 'web')
  rmSync(profileDir, { recursive: true, force: true })
  mkdirSync(join(profileDir, 'node_modules'), { recursive: true })

  const manifest = {
    name: 'dsh-profile-scg-test',
    private: true,
    dependencies: {
      'dsh-scg-guard': `link:${pluginDir}`,
    },
    dsh: {
      profile: {
        bundles: [
          '@deepseek-ai/dsh-base',
          '@deepseek-ai/dsh-web-app',
          'dsh-scg-guard',
        ],
      },
    },
  }

  writeFileSync(
    join(profileDir, 'package.json'),
    `${JSON.stringify(manifest, null, 2)}\n`,
  )
  writeFileSync(
    join(profileDir, 'cordis.patch.yml'),
    '# project-local SCG test profile; no user overrides\n[]\n',
  )
  writeFileSync(join(profileDir, 'cordis.yml'), '[]\n')

  const linkPath = join(profileDir, 'node_modules', 'dsh-scg-guard')
  if (!existsSync(linkPath)) {
    symlinkSync(
      pluginDir,
      linkPath,
      process.platform === 'win32' ? 'junction' : 'dir',
    )
  }

  return { home: resolvedHome, profileDir }
}

/**
 * Locate an existing DSH CLI without installing anything.
 *
 * Preference:
 *   1. DSH_BIN (a dsh/lib/bin.js path)
 *   2. the official Desktop app's bundled dsh-desktop-host CLI
 *   3. an existing npx cache (legacy web CLI)
 */
export function findDshBin() {
  if (process.env.DSH_BIN && existsSync(process.env.DSH_BIN)) {
    return {
      kind: 'node',
      command: process.execPath,
      args: [process.env.DSH_BIN],
      env: {},
      description: process.env.DSH_BIN,
    }
  }

  const desktop = findDesktopDsh()
  if (desktop) return desktop
  return findNpxDsh()
}

function findDesktopDsh() {
  const localAppData = process.env.LOCALAPPDATA
  if (!localAppData) return null

  const roots = [
    process.env.DSH_DESKTOP_HOME,
    join(localAppData, 'Programs', 'DeepSeek Harness'),
  ].filter(Boolean)

  for (const root of roots) {
    const exe = join(root, 'DeepSeek Harness.exe')
    const asar = join(root, 'resources', 'app.asar')
    if (!existsSync(exe) || !existsSync(asar)) continue

    // Electron can read this path inside app.asar; plain Node cannot stat it.
    const cli = join(
      root,
      'resources',
      'app.asar',
      'dsh',
      'node_modules',
      '@deepseek-ai',
      'dsh-desktop-host',
      'lib',
      'cli.js',
    )
    return {
      kind: 'desktop',
      command: exe,
      args: ['--expose-internals', cli],
      env: { ELECTRON_RUN_AS_NODE: '1' },
      description: `desktop: ${exe}`,
    }
  }
  return null
}

function findNpxDsh() {
  const localAppData = process.env.LOCALAPPDATA
  if (!localAppData) return null

  const npxRoot = join(localAppData, 'npm-cache', '_npx')
  if (!existsSync(npxRoot)) return null

  for (const entry of readdirSync(npxRoot)) {
    const candidate = join(
      npxRoot,
      entry,
      'node_modules',
      '@deepseek-ai',
      'dsh',
      'lib',
      'bin.js',
    )
    if (existsSync(candidate)) {
      return {
        kind: 'npx',
        command: process.execPath,
        args: [candidate],
        env: {},
        description: `npx: ${candidate}`,
      }
    }
  }
  return null
}
