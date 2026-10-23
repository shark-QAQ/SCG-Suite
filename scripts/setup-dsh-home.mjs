import { defaultDshHome, findDshBin, setupDshHome } from './dsh-home.mjs'

const { home, profileDir } = setupDshHome(defaultDshHome())
const dsh = findDshBin()

console.log(`DSH test home: ${home}`)
console.log(`profile:       ${profileDir}`)
console.log(
  `DSH CLI:       ${dsh?.description ?? 'not found (set DSH_BIN to run the integration check)'}`,
)
console.log('')
console.log('The profile enables dsh-scg-guard in dsh.profile.bundles.')
console.log('Run `pnpm dsh:verify` to boot DSH and confirm runtime.start in the audit log.')
