// A page on another site, opened in a browser context that holds a Dashboard
// session: the cross-site requests of the security tests run from it. The
// site's listener and page are closed on every path.

import { createServer } from 'node:http'
import type { BrowserContext, Page } from '@playwright/test'

export async function fromOtherSite<T>(context: BrowserContext, run: (page: Page) => Promise<T>): Promise<T> {
  const site = createServer((_, response) => {
    response.writeHead(200, { 'Content-Type': 'text/html' })
    response.end('<!doctype html><title>Another site</title>')
  })
  await new Promise<void>((done) => site.listen(9999, '127.0.0.3', done))
  try {
    const page = await context.newPage()
    try {
      await page.goto('http://127.0.0.3:9999/')
      return await run(page)
    } finally {
      await page.close()
    }
  } finally {
    await new Promise((done) => site.close(done))
  }
}
