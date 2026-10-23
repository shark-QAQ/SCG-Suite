import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

/** POSIX single-quote escaping for embedding a command in a shell. */
export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

/**
 * Wrap a command in a user + network namespace.
 *
 * With only loopback inside the new network namespace, raw sockets cannot
 * reach external networks. `--user --map-root-user` lets an unprivileged
 * Linux user create the namespace when unprivileged user namespaces are
 * enabled.
 */
export function buildNetnsCommand(
  command: string,
  options: { unshare?: string; shell?: string } = {},
): string {
  const unshare = options.unshare ?? 'unshare'
  const shell = options.shell ?? 'bash'
  return `${unshare} --user --map-root-user --net -- ${shell} -c ${shellQuote(command)}`
}

/** Probe whether this host can create a user+network namespace. */
export async function probeNetnsSupport(
  options: { timeoutMs?: number } = {},
): Promise<boolean> {
  if (process.platform !== 'linux') return false
  try {
    await execFileAsync(
      'unshare',
      ['--user', '--map-root-user', '--net', '--', 'true'],
      { timeout: options.timeoutMs ?? 3000 },
    )
    return true
  } catch {
    return false
  }
}
