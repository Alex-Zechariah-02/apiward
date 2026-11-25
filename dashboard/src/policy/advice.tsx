// Advice page and Overview alerts: fixed policy warnings, unused permissions and active alerts.

import { useContext, useId, useState } from 'react'
import type { Candidate, Page } from '../shared/api'
import { Can, usePoll, useResource, ViewMemory } from '../shared/hooks'
import { searchLog } from '../shared/links'
import { Badge, Field, TableScroll } from '../shared/ui'
import { PageHeader } from '../app/header'
import { Problem, ReplyView } from '../shared/replies'
import { ReadStamp, Time } from '../shared/time'
import type { ViewProps } from '../app/views'

interface Finding {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  object: string
  message: string
}

const severityTone = { critical: 'refused', high: 'refused', medium: 'unknown', low: 'neutral', info: 'neutral' } as const
const severityWord = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Information' }

function FindingRows({ items, label }: { items: Finding[]; label: string }) {
  return (
    <TableScroll label={label}>
      <table>
        <thead>
          <tr>
            <th scope="col">Severity</th>
            <th scope="col">Finding</th>
            <th scope="col">Applies To</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={`${item.id}:${item.object}`}>
              <td className="nowrap">
                <Badge tone={severityTone[item.severity]}>{severityWord[item.severity]}</Badge>
              </td>
              <td>{item.message}</td>
              <td>
                <code>{item.object}</code> <span className="muted">({item.id})</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </TableScroll>
  )
}

interface AdviceAnswer {
  rules: string
  candidate: number | null
  warnings: Finding[]
  unused_permits: {
    requests: number
    since: string | null
    window_days: number
    withheld: string | null
    items: Finding[]
    min_minutes: number
    min_requests: number
  }
}

export function AdviceView({ admin }: ViewProps) {
  const id = useId()
  const [candidate, setCandidate] = useState('')
  const drafts = useResource<Page<Candidate>>((signal) => admin.get('/admin/candidates', signal), [])
  const advice = useResource<AdviceAnswer>((signal) => admin.get(`/admin/advice${candidate ? `?candidate=${candidate}` : ''}`, signal), [candidate])
  const open = drafts.reply?.kind === 'ok' ? drafts.reply.body.items.filter((c) => c.status === 'validated') : []
  return (
    <>
      <PageHeader title="Advice" lede="Settings worth a second look and permissions no request has used. Advice only.">
        <ReadStamp okAt={advice.last?.at ?? null} failed={advice.failed} loading={advice.loading} onRefresh={advice.refresh} />
      </PageHeader>
      <div className="section card card-pad log-form">
        <Field id={`${id}-policy`} label="Policy">
          <select id={`${id}-policy`} className="input" value={candidate} onChange={(e) => setCandidate(e.target.value)}>
            <option value="">The policy in force</option>
            {open.map((c) => (
              <option key={c.id} value={c.id}>
                Draft change {c.id}
              </option>
            ))}
          </select>
        </Field>
      </div>
      <ReplyView reply={advice.reply}>
        {(body) => (
          <>
            <section className="section card" aria-labelledby="warnings-title">
              <div className="card-head card-head-pad">
                <h2 id="warnings-title">Settings to Review</h2>
                <span className="muted">{body.warnings.length ? `${body.warnings.length} found` : 'None found'}</span>
              </div>
              <div className="card-body">
                {body.warnings.length ? <FindingRows items={body.warnings} label="Settings to Review" /> : <p className="hint card-empty">No setting matches a check.</p>}
              </div>
            </section>
            <section className="section card" aria-labelledby="unused-title">
              <div className="card-head card-head-pad">
                <h2 id="unused-title">Unused Permissions</h2>
                {body.unused_permits.since ? (
                  <span className="muted">
                    Based on {body.unused_permits.requests.toLocaleString()} admitted requests since <Time value={body.unused_permits.since} /> (last {body.unused_permits.window_days} days).
                  </span>
                ) : (
                  <span className="muted">No admitted requests recorded yet.</span>
                )}
              </div>
              <div className="card-body">
                {body.unused_permits.withheld ? (
                  <p className="hint card-empty">
                    {body.unused_permits.withheld} Shown once tracking covers {body.unused_permits.min_minutes} minutes and at least {body.unused_permits.min_requests.toLocaleString()} requests.
                  </p>
                ) : body.unused_permits.items.length ? (
                  <FindingRows items={body.unused_permits.items} label="Unused Permissions" />
                ) : (
                  <p className="hint card-empty">Every permission was used.</p>
                )}
              </div>
            </section>
            <p className="hint section">Checked with rule set {body.rules}{body.candidate ? `, against draft change ${body.candidate}` : ''}.</p>
          </>
        )}
      </ReplyView>
    </>
  )
}

// Alerts shows the gateway's active alerts above the Overview, and nothing
// when there are none. A read that fails is shown as such, never as "no
// alerts". It reads every 5 seconds: each read is recorded in the security
// log, so it is not read every second.
export function Alerts({ admin, open }: { admin: ViewProps['admin']; open: ViewProps['open'] }) {
  const alerts = useResource<{ alerts: Finding[] }>((signal) => admin.get('/admin/alerts', signal), [])
  const memory = useContext(ViewMemory)
  const can = useContext(Can)
  // Refusals open in the Security Log for an administrator who may read it, else in Live Traffic.
  const seeRefusals = () => (can('read_history') ? searchLog(memory, { decision: 'refused' }) : open('live-traffic'))
  usePoll(alerts.refresh, 5_000, false)
  if (alerts.reply && alerts.reply.kind !== 'ok') {
    return (
      <section className="section" aria-label="Alerts">
        <p className="hint">The gateway's alerts could not be read, so none are shown; that does not mean there are none.</p>
        <Problem reply={alerts.reply} />
      </section>
    )
  }
  const items = alerts.reply?.body.alerts ?? []
  if (!items.length) return null
  return (
    <section className="section notice tone-refused" aria-label="Alerts" role="status">
      <p className="notice-title">{items.length === 1 ? '1 alert' : `${items.length} alerts`}</p>
      <ul className="alert-list">
        {items.map((item) => (
          <li key={item.id}>
            <Badge tone={severityTone[item.severity]}>{severityWord[item.severity]}</Badge> {item.message}{' '}
            {item.id === 'A1' ? (
              <button type="button" className="link-button" onClick={seeRefusals}>
                See Refusals
              </button>
            ) : item.id === 'A3' ? (
              <button type="button" className="link-button" onClick={() => open('limits')}>
                See Limits
              </button>
            ) : null}
          </li>
        ))}
      </ul>
    </section>
  )
}
