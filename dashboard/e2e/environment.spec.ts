// The Dashboard suite's own harness: a demonstration whose startup failed can
// still be stopped without waiting for an exit that already happened.
import { expect, test } from '@playwright/test'
import { Demo, prepared } from './env'

test('failed demo startup can still be cleaned up', async () => {
  const { bin } = prepared()
  // Deliberately omit setup: the owned demo exits before opening listeners.
  const demo = new Demo(bin, '')
  await expect(demo.start()).rejects.toThrow('demo run exited')
  const stopped = await Promise.race([
    demo.stop().then(() => true),
    new Promise<boolean>((done) => setTimeout(() => done(false), 1000)),
  ])
  expect.soft(stopped, 'dashboard teardown waited for an exit that already happened').toBe(true)
})
