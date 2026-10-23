import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  buildNetnsCommand,
  probeNetnsSupport,
  shellQuote,
} from '../dist/index.js'

test('shellQuote escapes single quotes', () => {
  assert.equal(shellQuote('plain'), "'plain'")
  assert.equal(shellQuote("a'b"), "'a'\\''b'")
  assert.equal(shellQuote('a b; rm -rf /'), "'a b; rm -rf /'")
})

test('buildNetnsCommand wraps the command in user+network namespaces', () => {
  const wrapped = buildNetnsCommand('echo hi')
  assert.equal(
    wrapped,
    "unshare --user --map-root-user --net -- bash -c 'echo hi'",
  )
})

test('probeNetnsSupport returns a boolean and is false off Linux', async () => {
  const supported = await probeNetnsSupport()
  assert.equal(typeof supported, 'boolean')
  if (process.platform !== 'linux') {
    assert.equal(supported, false)
  }
})
