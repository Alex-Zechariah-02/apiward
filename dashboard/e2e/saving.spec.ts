import { expect, test } from '@playwright/test'
import { api, applyJson, baseline, designer, discard, finish, open, page, ready, stagedDraft } from './designer'
import { dialogButton } from './pages'

// The saved state of the Policy page follows the gateway: a change withdrawn
// elsewhere no longer blocks saving, and a change the gateway stored but could
// not record still counts as saved, so a second save stores no duplicate.
// Each file starts its own gateway; designer.ts holds the shared steps.

test.describe.serial('Saved draft changes', () => {
  test.beforeAll(async ({ browser }) => {
    await open(browser)
    await ready()
  })

  test.afterAll(finish)

  test('a withdrawn draft change no longer marks the draft as saved', async () => {
    const document = structuredClone(baseline)
    document.operations.find((operation) => operation.id === 'reports.summary')!.rate!.count = 4
    await applyJson(document)
    const candidate = await stagedDraft()
    await page.getByRole('link', { name: 'Access Checker', exact: true }).click()
    expect((await api('DELETE', `/admin/candidates/${candidate}`, undefined, { 'Idempotency-Key': crypto.randomUUID() })).status).toBe(200)
    await designer()
    await expect(page.getByText('Saved as a draft change', { exact: true })).toHaveCount(0)
    await expect(page.getByRole('button', { name: 'Save Changes', exact: true })).toBeEnabled()
    await discard()
  })

  test('a draft change stored without its record still counts as saved', async () => {
    const document = structuredClone(baseline)
    document.operations.find((operation) => operation.id === 'reports.summary')!.rate!.count = 5
    await applyJson(document)
    // The gateway stores the change; the answer is replaced by the one it gives when the outcome record fails.
    await page.route('**/admin/candidates', async (route) => {
      if (route.request().method() !== 'POST') return route.continue()
      const stored = (await (await route.fetch()).json()) as { receipt: { transition_id: string }; candidate: { id: number } }
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ transition_id: stored.receipt.transition_id, outcome: 'committed', reason: 'OUTCOME_AUDIT_PENDING', candidate: stored.candidate.id }),
      })
    })
    await page.getByRole('button', { name: 'Save Changes', exact: true }).click()
    await dialogButton(page, 'Save Draft Change').click()
    await expect(page.getByText('Saved as a draft change', { exact: true })).toBeVisible()
    await expect(page.getByRole('button', { name: 'Save Changes', exact: true })).toBeDisabled()
    await page.unroute('**/admin/candidates')
    await discard()
  })
})
