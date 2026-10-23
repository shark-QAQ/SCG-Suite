import dns from 'node:dns'
import http from 'node:http'
import net from 'node:net'

export interface EgressBlockedAttempt {
  host: string
  port: number
  protocol: 'http' | 'connect'
}

export interface EgressProxyOptions {
  /**
   * Allowed destinations. Exact hosts, leading-dot suffixes (".example.com"),
   * "*" for everything, or `host:port` to pin a single port (for example
   * "api.example.com:443" or "[::1]:8080"). A rule without a port allows any
   * port on that host. Defaults to loopback only.
   */
  allowlist?: readonly string[]
  /** Permit allowlisted hostnames that resolve to private/loopback IPs. */
  allowPrivate?: boolean
  /** Called for every denied destination (before the 403 is returned). */
  onBlocked?: (attempt: EgressBlockedAttempt) => void
}

export interface EgressProxyHandle {
  /** `http://127.0.0.1:<port>` to inject as HTTP(S)_PROXY. */
  url: string
  port: number
  close(): Promise<void>
}

export const LOOPBACK_ALLOWLIST = ['127.0.0.1', 'localhost', '::1'] as const

function normalizeHost(host: string): string {
  return host.replace(/^\[|\]$/g, '').toLowerCase()
}

interface HostRule {
  host: string
  port?: number
}

/** Parse `host`, `host:port`, `[ipv6]:port`, or a bare IPv6 rule. */
function parseHostRule(rawRule: string): HostRule {
  const rule = rawRule.trim()
  if (rule.startsWith('[')) {
    const end = rule.indexOf(']')
    if (end !== -1) {
      const host = rule.slice(1, end)
      const rest = rule.slice(end + 1)
      if (/^:\d{1,5}$/.test(rest)) {
        return { host: normalizeHost(host), port: Number(rest.slice(1)) }
      }
      return { host: normalizeHost(host) }
    }
  }
  if (net.isIPv6(rule)) return { host: normalizeHost(rule) }

  const match = /^(.*):(\d{1,5})$/.exec(rule)
  if (match && !net.isIPv6(match[1])) {
    return { host: normalizeHost(match[1]), port: Number(match[2]) }
  }
  return { host: normalizeHost(rule) }
}

/**
 * Check a host against the allowlist.
 *
 * When `port` is supplied, a `host:port` rule only matches that port. When it
 * is omitted (for callers that only have a hostname), port-pinned rules match
 * by host; the proxy always supplies the destination port.
 */
export function hostAllowed(
  host: string,
  allowlist: readonly string[] = LOOPBACK_ALLOWLIST,
  port?: number,
): boolean {
  const normalized = normalizeHost(host)
  return allowlist.some((rawRule) => {
    const rule = parseHostRule(rawRule)
    if (rule.port !== undefined && port !== undefined && rule.port !== port) {
      return false
    }
    if (rule.host === '*') return true
    if (rule.host === normalized) return true
    if (rule.host.startsWith('.')) {
      const suffix = rule.host.slice(1)
      return normalized === suffix || normalized.endsWith(rule.host)
    }
    return false
  })
}

/** True for loopback, link-local, private, CGNAT and otherwise unroutable IPs. */
export function isPrivateAddress(address: string): boolean {
  const normalized = normalizeHost(address)
  if (net.isIPv4(normalized)) {
    const [a, b] = normalized.split('.').map(Number)
    if (a === 0 || a === 10 || a === 127) return true
    if (a === 169 && b === 254) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 192 && b === 168) return true
    if (a === 100 && b >= 64 && b <= 127) return true
    if (a === 198 && (b === 18 || b === 19)) return true
    if (a >= 224) return true
    return false
  }
  if (net.isIPv6(normalized)) {
    if (normalized === '::' || normalized === '::1') return true
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true
    if (/^fe[89ab]/.test(normalized)) return true
    if (normalized.startsWith('::ffff:')) {
      return isPrivateAddress(normalized.slice('::ffff:'.length))
    }
    return false
  }
  // Not an IP literal; callers should resolve first.
  return true
}

/** Parse `host:port` (CONNECT authority form), including bracketed IPv6. */
export function parseConnectTarget(
  raw: string | undefined,
): { host: string; port: number } | null {
  if (!raw) return null

  let host: string
  let rawPort: string

  if (raw.startsWith('[')) {
    const end = raw.indexOf(']')
    if (end === -1) return null
    host = raw.slice(1, end)
    if (raw[end + 1] !== ':') return null
    rawPort = raw.slice(end + 2)
  } else {
    const index = raw.lastIndexOf(':')
    if (index <= 0 || index === raw.length - 1) return null
    host = raw.slice(0, index)
    rawPort = raw.slice(index + 1)
    // Unbracketed IPv6 is ambiguous and rejected.
    if (host.includes(':')) return null
  }

  if (!host || !/^\d{1,5}$/.test(rawPort)) return null
  const port = Number(rawPort)
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null

  return { host, port }
}

function parseTarget(
  rawUrl: string | undefined,
  hostHeader: string | undefined,
): { url: URL; host: string; port: number } | null {
  const raw = rawUrl ?? '/'
  try {
    const url =
      /^https?:\/\//i.test(raw)
        ? new URL(raw)
        : new URL(raw, `http://${hostHeader ?? 'localhost'}`)
    const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80))
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null
    return { url, host: normalizeHost(url.hostname), port }
  } catch {
    return null
  }
}

async function resolveDestination(
  host: string,
  port: number,
  allowlist: readonly string[],
  allowPrivate: boolean,
): Promise<{ address: string } | null> {
  if (!hostAllowed(host, allowlist, port)) return null

  const normalized = normalizeHost(host)
  const loopbackHost =
    normalized === 'localhost' ||
    normalized === '127.0.0.1' ||
    normalized === '::1'

  let addresses: dns.LookupAddress[]
  try {
    addresses = await dns.promises.lookup(normalized, { all: true })
  } catch {
    return null
  }
  if (addresses.length === 0) return null

  // An allowlisted public hostname must not resolve into a private/loopback
  // address (DNS rebinding / SSRF).
  if (
    !loopbackHost &&
    !allowPrivate &&
    addresses.some(({ address }) => isPrivateAddress(address))
  ) {
    return null
  }

  return { address: addresses[0].address }
}

/**
 * Minimal forward proxy with an allowlist.
 *
 * - Plain HTTP is forwarded.
 * - HTTPS uses CONNECT and is gated by destination host/port (no TLS
 *   interception).
 * - Only proxy-aware clients honor HTTP(S)_PROXY; raw sockets bypass it.
 */
export async function startEgressProxy(
  options: EgressProxyOptions = {},
): Promise<EgressProxyHandle> {
  const allowlist = options.allowlist ?? LOOPBACK_ALLOWLIST
  const allowPrivate = options.allowPrivate ?? false
  const blocked = (attempt: EgressBlockedAttempt) => options.onBlocked?.(attempt)

  const server = http.createServer(async (req, res) => {
    try {
      const target = parseTarget(req.url, req.headers.host)
      if (!target) {
        res.writeHead(400, { 'content-type': 'text/plain' })
        res.end('SCG egress proxy: bad request target\n')
        return
      }

      const destination = await resolveDestination(
        target.host,
        target.port,
        allowlist,
        allowPrivate,
      )
      if (!destination) {
        blocked({ host: target.host, port: target.port, protocol: 'http' })
        res.writeHead(403, { 'content-type': 'text/plain' })
        res.end('SCG egress blocked\n')
        return
      }

      const headers = { ...req.headers }
      delete headers['proxy-connection']
      delete headers['proxy-authorization']

      const upstream = http.request(
        {
          hostname: destination.address,
          port: target.port,
          path: `${target.url.pathname}${target.url.search}`,
          method: req.method,
          headers,
        },
        (upstreamResponse) => {
          res.writeHead(
            upstreamResponse.statusCode ?? 502,
            upstreamResponse.headers,
          )
          upstreamResponse.pipe(res)
        },
      )
      upstream.on('error', () => {
        if (!res.headersSent) {
          res.writeHead(502, { 'content-type': 'text/plain' })
        }
        res.end('SCG egress proxy: upstream error\n')
      })
      req.pipe(upstream)
    } catch {
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'text/plain' })
      }
      res.end('SCG egress proxy: internal error\n')
    }
  })

  server.on('connect', async (req, socket, head) => {
    try {
      const target = parseConnectTarget(req.url)
      if (!target) {
        blocked({ host: String(req.url ?? '').slice(0, 200), port: 0, protocol: 'connect' })
        socket.end('HTTP/1.1 400 Bad Request\r\n\r\n')
        return
      }

      const destination = await resolveDestination(
        target.host,
        target.port,
        allowlist,
        allowPrivate,
      )
      if (!destination) {
        blocked({
          host: target.host,
          port: target.port,
          protocol: 'connect',
        })
        socket.end('HTTP/1.1 403 Forbidden\r\n\r\n')
        return
      }

      const upstream = net.connect(target.port, destination.address, () => {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
        if (head && head.length > 0) upstream.write(head)
        upstream.pipe(socket)
        socket.pipe(upstream)
      })
      upstream.on('error', () => socket.destroy())
      socket.on('error', () => upstream.destroy())
    } catch {
      socket.destroy()
    }
  })

  server.on('clientError', (_error, socket) => {
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n')
  })

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject)
      resolve()
    })
  })

  const address = server.address()
  const port =
    address !== null && typeof address === 'object' ? address.port : 0

  return {
    port,
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections?.()
        server.close(() => resolve())
      }),
  }
}
