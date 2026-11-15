import type { Admin } from './http'
import { useResource } from './hooks'

// The gateway's policy size limit, read from the gateway itself, so the
// browser's size checks never disagree with the limit the gateway enforces.

export interface Limit {
  used: number
  max: number
}

// usePolicyLimit is the most bytes a policy document may have, or undefined
// until the gateway's limits are read; the gateway still refuses an oversized
// document when it is saved.
export function usePolicyLimit(admin: Admin): number | undefined {
  const limits = useResource<Record<string, Limit>>((signal) => admin.get('/admin/limits', signal), [])
  return limits.last?.body.policy_bytes?.max
}

// sizeProblem says that a document or file of this many bytes is more than
// the gateway accepts.
export function sizeProblem(what: 'document' | 'file', bytes: number, max: number | undefined): string | undefined {
  if (max === undefined || bytes <= max) return undefined
  return `The ${what} is ${bytes.toLocaleString()} bytes; the gateway accepts at most ${max.toLocaleString()}.`
}

// readPolicy reads a chosen file as text. Its size is checked first, so a
// file the gateway would refuse is never read into the page.
export async function readPolicy(file: File, max: number | undefined): Promise<{ text: string } | { problem: string }> {
  if (max === undefined) return { problem: "The gateway's size limit has not been read. Refresh the page, then choose the file again." }
  const problem = sizeProblem('file', file.size, max)
  if (problem) return { problem }
  try {
    return { text: await file.text() }
  } catch {
    return { problem: 'The file could not be read.' }
  }
}
