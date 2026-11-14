import { readdirSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { expect, test } from '@playwright/test'
import { committedMessage, explain, message } from '../src/shared/api'

// Every error and refusal code the Admin API can send, read from the
// gateway's source so a new code without a plain title fails here: the
// protected Admin API's own codes, the controller's refusal reasons and the
// policy compiler's reasons (sent in upper case, and in lower case by
// blocked-account and key changes).
const gateway = resolve('..', 'internal')
const source = (...dirs: string[]) =>
  dirs
    .flatMap((dir) => readdirSync(join(gateway, dir)).filter((name) => name.endsWith('.go') && !name.endsWith('_test.go')).map((name) => join(gateway, dir, name)))
    .map((file) => readFileSync(file, 'utf8'))
    .join('\n')
const found = (text: string, pattern: RegExp) => [...new Set([...text.matchAll(pattern)].map((match) => match[1]))]
const adminCodes = found(source('admin'), /(?:adminError\(w|refuse\(w, r), [^,]+, "([a-z_]+)"/g)
const controllerReasons = [
  ...new Set([
    ...found(source('controller'), /"([A-Z][A-Z_]{3,})"/g),
    ...found(source('compile', 'policy', 'controller'), /Invalid\("([A-Z_]+)"/g),
  ]),
]

const fallback = message('a_code_no_gateway_sends')

test('every code the Admin API can send has its own plain title and next step, and an unknown code still gets one', () => {
  expect(fallback.action).toContain('no description')
  // The source reading still finds the codes the gateway has long sent.
  expect(adminCodes).toEqual(expect.arrayContaining(['bad_request', 'forbidden', 'unauthenticated', 'too_many_attempts', 'stream_limit']))
  expect(controllerReasons).toEqual(expect.arrayContaining(['STALE', 'ALREADY_RESOLVED', 'DUPLICATE_ID', 'UNSUPPORTED_FEATURE']))
  const codes = [...adminCodes, ...controllerReasons, ...controllerReasons.map((code) => code.toLowerCase())]
  const missing = codes.filter((code) => {
    const words = message(code)
    return (words.title === fallback.title && words.action === fallback.action) || !words.title || !words.action
  })
  expect(missing).toEqual([])
  // A lost answer is never described as "nothing changed".
  for (const code of ['gateway_unavailable', 'STORE_ERROR', 'store_error']) expect(explain(code)).not.toMatch(/nothing (was )?changed/i)
  // A committed change whose answer reports a problem is always titled as applied.
  for (const code of ['OUTCOME_AUDIT_PENDING', 'PUBLICATION_FAILED', 'STORE_ERROR', 'unavailable']) expect(committedMessage(code).title).toMatch(/^Applied, but/)
})
