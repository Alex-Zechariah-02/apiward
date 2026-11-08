import { expect, test } from '@playwright/test'
import { api, applyJson, baseline, discard, finish, open, page, ready, stagedDraft } from './designer'
import { dialogButton, go, moreDetail, shot } from './pages'

// Service addresses on other hosts: a URL shows its TLS settings, the gateway
// compiles a private https address and refuses a cloud metadata address, and
// the Team page lists the gateway's TLS profiles.

const flow = () => page.getByRole('dialog', { name: 'Connect an API' })

test.describe.serial('Service addresses on other hosts', () => {
  test.beforeAll(async ({ browser }) => {
    await open(browser)
    await ready()
  })

  test.afterAll(finish)

  test('an https address asks for its TLS profile and Host header; a local address does not', async () => {
    await page.locator('.designer-bar').getByRole('button', { name: 'Connect an API', exact: true }).click()
    await flow().getByLabel('Service Address ID', { exact: true }).fill('billing-svc')
    const address = flow().getByLabel('Address', { exact: true })
    await address.fill('https://billing.internal:8443')
    await expect(flow().getByLabel('TLS Profile', { exact: true })).toHaveValue('')
    await expect(flow().getByRole('group', { name: 'Host Header' }).getByRole('button', { name: 'Use Service Host' })).toHaveAttribute('aria-pressed', 'true')
    await expect(flow().getByText('"url": "https://billing.internal:8443"')).toBeVisible()
    await shot(page, 'upstreams-connect-https')
    await address.fill('127.0.0.1:9700')
    await expect(flow().getByLabel('TLS Profile', { exact: true })).toHaveCount(0)
    await expect(flow().getByText('"dial": "127.0.0.1:9700"')).toBeVisible()
    await address.fill('orders.internal')
    await flow().getByRole('button', { name: 'Next', exact: true }).click()
    await expect(flow().getByText('Enter host:port, such as 127.0.0.1:9600, or a URL such as https://orders.internal:8443.')).toBeVisible()
    await flow().getByRole('button', { name: 'Close', exact: true }).click()
    await dialogButton(page, 'Discard Input').click()
  })

  test('the gateway keeps a private https address and refuses a cloud metadata address at its field', async () => {
    const upstreams = [...baseline.upstreams, { id: 'billing-svc', url: 'https://10.0.0.5:8443', host: 'inbound' as const }]
    await applyJson({ ...baseline, schema_version: 5, upstreams })
    const saved = await stagedDraft()
    const candidate = (await api('GET', `/admin/candidates/${saved}`)).body as { document: { schema_version: number; upstreams: unknown[] } }
    expect(candidate.document.schema_version).toBe(5)
    expect(candidate.document.upstreams).toContainEqual({ id: 'billing-svc', url: 'https://10.0.0.5:8443', host: 'inbound' })

    upstreams[upstreams.length - 1] = { id: 'billing-svc', url: 'http://169.254.169.254', host: 'inbound' }
    await applyJson({ ...baseline, schema_version: 5, upstreams })
    await page.getByRole('button', { name: 'Save Changes', exact: true }).click()
    await dialogButton(page, 'Save Draft Change').click()
    const refusal = page.getByRole('alert').filter({ hasText: 'A service address is not allowed' })
    await expect(refusal).toHaveClass(/tone-refused/)
    await expect(moreDetail(refusal, 'Error code')).toHaveText('INVALID_UPSTREAM')
    await expect(moreDetail(refusal, 'Field')).toHaveText(`upstreams[${upstreams.length - 1}].url`)
    await shot(page, 'upstreams-metadata-refused')
    await discard()
  })

  test('the Team page lists the TLS profiles, none on this gateway', async () => {
    expect((await api('GET', '/admin/tls-profiles')).body).toEqual({ items: [] })
    await go(page, 'Team')
    const profiles = page.getByRole('region', { name: 'Service TLS Profiles' })
    await expect(profiles.getByText(/^No profiles\./)).toBeVisible()
  })
})
