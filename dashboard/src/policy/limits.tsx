// Limits page: shows the gateway's built-in limits, current usage and limit behavior.

import { useResource } from '../shared/hooks'
import { Badge, TableScroll } from '../shared/ui'
import { PageHeader } from '../app/header'
import { ReplyView } from '../shared/replies'
import type { Limit } from '../shared/limits'
import { ReadStamp } from '../shared/time'
import type { ViewProps } from '../app/views'

const limitRows: { id: string; name: string; atLimit: string; bytes?: boolean }[] = [
  { id: 'policy_bytes', name: 'Policy Document', atLimit: 'A larger draft change is refused when it is saved.', bytes: true },
  { id: 'temporary_rules', name: 'Active Temporary Rules', atLimit: 'New temporary rules are refused until one ends or is revoked.' },
  { id: 'live_views', name: 'Open Live Views', atLimit: 'Another Live Traffic view cannot connect until one closes.' },
  { id: 'administrator_sessions', name: 'Administrator Sessions', atLimit: 'New sign-ins are refused until a session ends.' },
  { id: 'audit_files', name: 'Security Log Files Waiting to Archive', atLimit: 'The oldest file is deleted after a record of it is saved; with the refuse setting, the gateway stops accepting requests until files are moved away.' },
  { id: 'audit_active_bytes', name: 'Current Security Log File', atLimit: 'The file is closed, compressed and moved to the archive, and a new one started.', bytes: true },
  { id: 'audit_archive_bytes', name: 'Security Log Archive', atLimit: 'The oldest archived file is deleted after a record of it is saved.', bytes: true },
  { id: 'rate_counters', name: 'Rate Limit Counters', atLimit: 'Requests that need a new counter are refused until older ones expire.' },
  { id: 'recent_requests', name: 'Recent Requests Kept for Live Views', atLimit: 'The oldest is dropped; the security log keeps every request.' },
]

function amount(value: number, bytes?: boolean): string {
  if (!bytes) return value.toLocaleString()
  if (value >= 1 << 30) return `${(value / (1 << 30)).toFixed(1)} GiB`
  return value >= 1 << 20 ? `${(value / (1 << 20)).toFixed(1)} MiB` : `${(value / 1024).toFixed(1)} KiB`
}

export function LimitsView({ admin }: ViewProps) {
  const limits = useResource<Record<string, Limit>>((signal) => admin.get('/admin/limits', signal), [])
  return (
    <>
      <PageHeader title="Limits" lede="The gateway's built-in limits, how much of each is in use, and what happens at the limit.">
        <ReadStamp okAt={limits.last?.at ?? null} failed={limits.failed} loading={limits.loading} onRefresh={limits.refresh} />
      </PageHeader>
      <section className="section card" aria-label="Limits">
        <ReplyView reply={limits.reply}>
          {(body) => (
            <TableScroll label="Limits">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Limit</th>
                    <th scope="col">In Use</th>
                    <th scope="col">At the Limit</th>
                  </tr>
                </thead>
                <tbody>
                  {limitRows.map((row) => {
                    const limit = body[row.id]
                    if (!limit) return null
                    const share = limit.max ? limit.used / limit.max : 0
                    return (
                      <tr key={row.id}>
                        <th scope="row">{row.name}</th>
                        <td className="nowrap">
                          <span className="num">
                            {amount(limit.used, row.bytes)} of {amount(limit.max, row.bytes)}
                          </span>{' '}
                          {share >= 0.8 ? <Badge tone={share >= 1 ? 'refused' : 'unknown'}>{share >= 1 ? 'At the limit' : 'Nearly full'}</Badge> : null}
                          <meter className="limit-meter" min={0} max={limit.max} value={limit.used} low={limit.max * 0.8} high={limit.max * 0.95} optimum={0} aria-label={`${row.name} in use`} />
                        </td>
                        <td className="muted">{row.atLimit}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </TableScroll>
          )}
        </ReplyView>
      </section>
    </>
  )
}
