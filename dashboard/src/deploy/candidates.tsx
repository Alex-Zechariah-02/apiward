import { useEffect, useState } from 'react'
import type { Candidate, Revision } from '../shared/api'
import { useGatewayState, usePaged, useRereadWhen, useResource } from '../shared/hooks'
import { ActivationHistory } from './activation'
import { TrialDecision } from './provisional'
import { Badge, ListToolbar, matches, TableScroll } from '../shared/ui'
import { ReadStamp, Time } from '../shared/time'
import { Problem, ShowMore } from '../shared/replies'
import { PageHeader } from '../app/header'
import { useFocus } from '../shared/links'
import type { ViewProps } from '../app/views'
import { CandidateStatus, statusWords } from './draft'
import { CandidateDetail } from './draft-detail'
import { StageForm } from './stage'

// The Changes page: the change on trial, saved draft changes, saving a new one, and trial history.

// Changes is the guided way a policy change goes live: drafted, checked
// by the gateway's own compiler when staged, previewed against recent
// traffic, put on trial with a rollback deadline, then confirmed or rolled
// back. A staged change (a "candidate" to the gateway) is never in force by
// itself.
export function Candidates({ admin, can, draft, candidate }: ViewProps & { draft?: string; candidate?: number }) {
  const state = useGatewayState()
  const list = usePaged<Candidate>(admin, '/admin/candidates', [])
  const policy = useResource<Revision>((signal) => admin.get('/admin/policy', signal), [])
  const [selected, setSelected] = useState<number | null>(candidate ?? null)
  const [trials, setTrials] = useState(0)
  const [query, setQuery] = useState('')
  useEffect(() => {
    if (candidate !== undefined) setSelected(candidate)
  }, [candidate])
  // A link from another page, such as the history, opens one draft change.
  const linked = useFocus('candidate')
  useEffect(() => {
    if (linked && /^\d+$/.test(linked)) setSelected(Number(linked))
  }, [linked])
  // The list, the confirmed policy and the past trials are read again
  // whenever the gateway's status changes (a trial confirmed, rolled back or
  // timed out, here or elsewhere) and whenever this page asks for a reread.
  useRereadWhen(state.version, () => {
    list.refresh()
    policy.refresh()
    setTrials((n) => n + 1)
  })
  const refresh = () => state.refresh()

  // A candidate names the confirmed revision it was prepared against; "r0"
  // when no confirmed policy is active (a new or restored installation).
  const ifMatch =
    policy.reply?.kind === 'ok'
      ? (policy.reply.etag ?? undefined)
      : policy.reply?.kind === 'refused' && policy.reply.error === 'no_confirmed_policy'
        ? '"r0"'
        : undefined
  const confirmed = policy.reply?.kind === 'ok' ? policy.reply.body : undefined
  // Without the active version's ETag nothing can be saved or put on trial, so a failed read of it is shown.
  const unread = policy.reply && policy.reply.kind !== 'ok' && ifMatch === undefined ? policy.reply : null
  const status = state.facts
  const manage = can('manage_policy')
  const shown = list.items.filter((c) =>
    matches(
      query,
      c.id,
      `change ${c.id}`,
      statusWords[c.status] ?? c.status,
      c.actor,
      c.parent ? `version ${c.parent}` : undefined,
      c.deny_all ? 'denies everything' : undefined,
    ),
  )

  return (
    <>
      <PageHeader
        title="Changes"
        lede="Review draft changes, preview their impact and activate one through a timed trial."
      >
        <ReadStamp okAt={list.last?.at ?? null} failed={list.failed || unread !== null} loading={list.loading || policy.loading} onRefresh={refresh} />
      </PageHeader>

      {unread ? (
        <section className="section" aria-label="Active version not read">
          <p className="hint">The active version could not be read, so a draft change cannot be saved or put on trial until it is. Refresh to read it again.</p>
          <Problem reply={unread} />
        </section>
      ) : null}

      <TrialDecision admin={admin} manage={manage} variant="full" />

      <section className="section card" aria-labelledby="staged-title">
        <div className="card-head card-head-pad">
          <h2 id="staged-title">Draft Changes</h2>
          {manage ? (
            <a className="card-link" href="#stage-title">
              New Draft Change
            </a>
          ) : null}
        </div>
        <div className="card-body">
          {list.reply && list.reply.kind !== 'ok' ? <Problem reply={list.reply} /> : null}
          {list.reply?.kind === 'ok' && list.items.length === 0 ? (
            <p className="hint card-empty">
              No draft changes yet.{' '}
              {manage ? (
                <>
                  Draft one on the <a href="#/policy">Policy</a> page, or start from the active version below.
                </>
              ) : null}
            </p>
          ) : null}
          {list.items.length > 0 ? (
            <ListToolbar
              label="Filter draft changes"
              query={query}
              onQuery={setQuery}
              shown={shown.length}
              total={list.items.length}
              more={list.next !== undefined}
              noun={['draft change', 'draft changes']}
            />
          ) : null}
          {list.items.length > 0 && shown.length === 0 ? <p className="hint card-empty">No loaded draft change matches the filter.</p> : null}
          {shown.length > 0 ? (
            <TableScroll label="Draft Changes">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Change</th>
                    <th scope="col">State</th>
                    <th scope="col">Based on</th>
                    <th scope="col">Saved</th>
                    <th scope="col">
                      <span className="visually-hidden">Review</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((c) => (
                    <tr key={c.id} aria-current={selected === c.id ? 'true' : undefined}>
                      <td className="num">
                        <strong>{c.id}</strong>
                        {c.deny_all ? <span className="cell-sub">denies everything</span> : null}
                      </td>
                      <td>
                        <CandidateStatus status={c.status} /> {c.active ? <Badge tone="ok">Active</Badge> : null}
                      </td>
                      <td>{c.parent ? `version ${c.parent}` : 'no active version'}</td>
                      <td>
                        <Time value={c.created_at} /> <span className="muted">by {c.actor}</span>
                      </td>
                      <td className="row-actions">
                        <button type="button" className="btn btn-small" onClick={() => setSelected(c.id)} aria-pressed={selected === c.id}>
                          Review
                          <span className="visually-hidden"> change {c.id}</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableScroll>
          ) : null}
          <div className="card-pad-x">
            <ShowMore list={list} />
          </div>
        </div>
      </section>

      {selected !== null ? (
        <CandidateDetail key={selected} id={selected} admin={admin} confirmed={confirmed} ifMatch={ifMatch} mode={status?.state} manage={manage} changed={refresh} />
      ) : null}

      {manage ? <StageForm admin={admin} ifMatch={ifMatch} draft={draft} confirmed={confirmed} changed={refresh} review={setSelected} /> : null}

      {can('read_history') ? <ActivationHistory admin={admin} reads={trials} /> : null}
    </>
  )
}
