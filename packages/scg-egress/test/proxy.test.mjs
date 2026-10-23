import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import net from 'node:net'

import {
  hostAllowed,
  isPrivateAddress,
  parseConnectTarget,
  startEgressProxy,
} from '../dist/index.js'

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      resolve(address.port)
    })
  })
}

function requestThroughProxy(proxyPort, targetUrl) {
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: '127.0.0.1',
        port: proxyPort,
        path: targetUrl,
        method: 'GET',
        headers: { host: new URL(targetUrl).host },
      },
      (response) => {
        let body = ''
        response.setEncoding('utf8')
        response.on('data', (chunk) => {
          body += chunk
        })
        response.on('end', () =>
          resolve({ status: response.statusCode, body }),
        )
      },
    )
    request.on('error', reject)
    request.end()
  })
}

test('host allowlist supports exact, suffix and wildcard rules', () => {
  assert.equal(hostAllowed('localhost', ['localhost']), true)
  assert.equal(hostAllowed('api.example.com', ['.example.com']), true)
  assert.equal(hostAllowed('example.com', ['.example.com']), true)
  assert.equal(hostAllowed('evil.example.org', ['.example.com']), false)
  assert.equal(hostAllowed('anything.test', ['*']), true)
  assert.equal(hostAllowed('example.com', ['localhost']), false)
})

test('host allowlist can pin a port', () => {
  assert.equal(hostAllowed('example.com', ['example.com:443'], 443), true)
  assert.equal(hostAllowed('example.com', ['example.com:443'], 80), false)
  assert.equal(hostAllowed('api.example.com', ['.example.com:443'], 443), true)
  assert.equal(hostAllowed('api.example.com', ['.example.com:443'], 8443), false)
  assert.equal(hostAllowed('::1', ['[::1]:8080'], 8080), true)
  assert.equal(hostAllowed('::1', ['[::1]:8080'], 8081), false)
  assert.equal(hostAllowed('::1', ['::1'], 9000), true)
  assert.equal(hostAllowed('example.com', ['*:443'], 443), true)
  assert.equal(hostAllowed('example.com', ['*:443'], 80), false)
})

test('port-pinned allowlist blocks the wrong port end-to-end', async () => {
  const upstream = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('should-not-reach')
  })
  const upstreamPort = await listen(upstream)
  const otherPort = upstreamPort === 443 ? 80 : 443

  const proxy = await startEgressProxy({
    allowlist: [`127.0.0.1:${otherPort}`],
  })
  try {
    const result = await requestThroughProxy(
      proxy.port,
      `http://127.0.0.1:${upstreamPort}/health`,
    )
    assert.equal(result.status, 403)
  } finally {
    await proxy.close()
    await new Promise((resolve) => upstream.close(resolve))
  }
})

test('parseConnectTarget validates authority and bracketed IPv6', () => {
  assert.deepEqual(parseConnectTarget('example.com:443'), {
    host: 'example.com',
    port: 443,
  })
  assert.deepEqual(parseConnectTarget('[::1]:443'), {
    host: '::1',
    port: 443,
  })
  for (const bad of [
    '',
    'example.com',
    'example.com:abc',
    'example.com:0',
    'example.com:70000',
    '[::1]443',
    '2001:db8::1:443',
  ]) {
    assert.equal(parseConnectTarget(bad), null, bad)
  }
})

test('isPrivateAddress blocks private, loopback and link-local ranges', () => {
  for (const address of [
    '127.0.0.1',
    '10.1.2.3',
    '172.16.0.1',
    '192.168.1.1',
    '169.254.1.1',
    '100.64.0.1',
    '::1',
    'fc00::1',
    'fe80::1',
  ]) {
    assert.equal(isPrivateAddress(address), true, address)
  }
  assert.equal(isPrivateAddress('8.8.8.8'), false)
  assert.equal(isPrivateAddress('2606:4700:4700::1111'), false)
})

test('malformed CONNECT gets 400 and does not crash the proxy', async () => {
  const proxy = await startEgressProxy({ allowlist: ['127.0.0.1'] })
  try {
    const sendConnect = (authority) =>
      new Promise((resolve, reject) => {
        const socket = net.connect(proxy.port, '127.0.0.1', () => {
          socket.write(
            `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`,
          )
        })
        let data = ''
        socket.setEncoding('utf8')
        socket.on('data', (chunk) => {
          data += chunk
        })
        socket.on('end', () => resolve(data))
        socket.on('close', () => resolve(data))
        socket.on('error', reject)
        setTimeout(() => {
          socket.destroy()
          resolve(data)
        }, 1000)
      })

    assert.match(await sendConnect('evil.example:abc'), /400 Bad Request/)
    // If the bad authority had crashed the process, this second request
    // could not be served by the same proxy instance.
    assert.match(await sendConnect('evil.example:443'), /403 Forbidden/)
  } finally {
    await proxy.close()
  }
})

test('forwards allowed HTTP destinations', async () => {
  const upstream = http.createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('upstream-ok')
  })
  const upstreamPort = await listen(upstream)

  const proxy = await startEgressProxy({ allowlist: ['127.0.0.1'] })
  try {
    const result = await requestThroughProxy(
      proxy.port,
      `http://127.0.0.1:${upstreamPort}/health`,
    )
    assert.equal(result.status, 200)
    assert.equal(result.body, 'upstream-ok')
  } finally {
    await proxy.close()
    await new Promise((resolve) => upstream.close(resolve))
  }
})

test('blocks disallowed HTTP destinations and reports them', async () => {
  const attempts = []
  const proxy = await startEgressProxy({
    allowlist: ['127.0.0.1'],
    onBlocked: (attempt) => attempts.push(attempt),
  })
  try {
    const result = await requestThroughProxy(
      proxy.port,
      'http://evil.example/collect',
    )
    assert.equal(result.status, 403)
    assert.equal(result.body, 'SCG egress blocked\n')
    assert.deepEqual(attempts, [
      { host: 'evil.example', port: 80, protocol: 'http' },
    ])
  } finally {
    await proxy.close()
  }
})

test('blocks disallowed CONNECT destinations', async () => {
  const attempts = []
  const proxy = await startEgressProxy({
    allowlist: ['127.0.0.1'],
    onBlocked: (attempt) => attempts.push(attempt),
  })

  try {
    const response = await new Promise((resolve, reject) => {
      const socket = net.connect(proxy.port, '127.0.0.1', () => {
        socket.write(
          'CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n',
        )
      })
      let data = ''
      socket.setEncoding('utf8')
      socket.on('data', (chunk) => {
        data += chunk
      })
      socket.on('end', () => resolve(data))
      socket.on('close', () => resolve(data))
      socket.on('error', reject)
      setTimeout(() => {
        socket.destroy()
        resolve(data)
      }, 1000)
    })

    assert.match(response, /403 Forbidden/)
    assert.deepEqual(attempts, [
      { host: 'evil.example', port: 443, protocol: 'connect' },
    ])
  } finally {
    await proxy.close()
  }
})
