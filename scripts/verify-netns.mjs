/**
 * Linux-only verification of kernel-level network isolation.
 *
 * On non-Linux hosts or hosts without unprivileged user namespaces this
 * skips with exit 0. Set SCG_REQUIRE_NETNS=1 to require it.
 */
import { execSync } from 'node:child_process'

import {
  buildNetnsCommand,
  probeNetnsSupport,
} from '../packages/scg-netns/dist/index.js'

if (process.platform !== 'linux') {
  console.log('netns skip: not Linux')
  process.exit(0)
}

const supported = await probeNetnsSupport()
if (!supported) {
  console.log('netns skip: user+network namespaces unavailable')
  process.exit(process.env.SCG_REQUIRE_NETNS === '1' ? 1 : 0)
}

const local = execSync(buildNetnsCommand('echo netns-ok'), {
  encoding: 'utf8',
  timeout: 5000,
}).trim()

let blocked = false
try {
  execSync(buildNetnsCommand('exec 3<>/dev/tcp/1.1.1.1/53'), {
    stdio: 'ignore',
    timeout: 5000,
  })
} catch {
  blocked = true
}

console.log(`netns local command: ${local}`)
console.log(`netns external TCP blocked: ${blocked}`)

process.exit(local === 'netns-ok' && blocked ? 0 : 1)
