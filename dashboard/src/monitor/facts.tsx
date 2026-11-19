import type { Reply } from '../shared/api'
import { AccountLink, XRef } from '../shared/links'
import { Badge, CopyButton } from '../shared/ui'
import { Time } from '../shared/time'
import { Problem } from '../shared/replies'
import { CheckList, decisionTone, outcomeOf, reasonOf, RequestLine, type RequestEvent } from './requests'

// The facts of one request in the request drawer: what the gateway recorded,
// each fact linked to the page where it lives.

// versionOf reads the version and temporary rules a generation was built
// from ("r6+o1.2-…"); the generation itself stays secondary text.
function versionOf(generation: string): { version: string; rules: string[] } | null {
  const match = /^r(\d+)(?:\+o([\d.]+))?-/.exec(generation)
  return match ? { version: match[1], rules: match[2]?.split('.') ?? [] } : null
}

// RequestFacts is what the gateway recorded about one request, each fact
// linked to the page where it lives.
export function RequestFacts(props: { event: RequestEvent; blocked: boolean; unread?: Reply<unknown>; block?: () => void; blockAddress?: () => void }) {
  const { event, blocked, unread, block, blockAddress } = props
  const policy = versionOf(event.generation)
  return (
    <>
      <p className="drawer-outcome">
        <Badge tone={decisionTone[event.decision]}>{outcomeOf(event)}</Badge>
        <span>{event.decision === 'allowed' ? 'Forwarded to the service' : reasonOf(event.code)}</span>
      </p>
      <dl className="facts drawer-facts">
        <div className="fact">
          <dt>Time</dt>
          <dd>
            <Time value={event.time} />
          </dd>
        </div>
        <div className="fact">
          <dt>Method and Path</dt>
          <dd>
            {event.operation ? (
              <XRef view="policy" focus={{ select: `operation:${event.operation}` }}>
                <RequestLine event={event} />
              </XRef>
            ) : (
              <RequestLine event={event} />
            )}
            <span className="cell-sub">{event.operation ? <>Endpoint <code>{event.operation}</code></> : 'No endpoint matched'}</span>
            {event.path_truncated ? <span className="cell-sub">The path was longer: the gateway recorded only its start.</span> : null}
            {event.forwarded_path ? (
              <span className="cell-sub">
                Sent to the service as <code>{event.forwarded_path}</code>
              </span>
            ) : null}
            {event.upstream ? (
              <span className="cell-sub">
                Service address <code>{event.upstream}</code>
              </span>
            ) : null}
          </dd>
        </div>
        <div className="fact">
          <dt>Response</dt>
          <dd>
            {outcomeOf(event)} <span className="muted">in {event.duration_ms.toFixed(1)} ms</span>
          </dd>
        </div>
        <div className="fact">
          <dt>Policy Version</dt>
          <dd>
            {policy ? (
              <>
                <XRef view="versions" focus={{ version: policy.version }}>
                  Version {policy.version}
                </XRef>
                {policy.rules.length ? ` with temporary rule${policy.rules.length > 1 ? 's' : ''} ${policy.rules.join(', ')}` : ''}
                <code className="cell-sub soft">{event.generation}</code>
              </>
            ) : (
              'None (no active policy)'
            )}
          </dd>
        </div>
        <div className="fact">
          <dt>Account</dt>
          <dd>
            {event.subject ? (
              <>
                <AccountLink account={event.subject}>
                  <code>{event.subject}</code>
                </AccountLink>
                {event.roles.length ? <span className="muted"> as {event.roles.join(', ')}</span> : null}
                {blocked ? <> <Badge tone="refused">Blocked</Badge></> : null}
                {unread ? <span className="cell-sub">Whether this account is blocked is not known: the blocked list could not be read.</span> : null}
                {block ? (
                  <button type="button" className="btn btn-small drawer-block" onClick={block}>
                    Block Account…
                  </button>
                ) : null}
              </>
            ) : (
              'None (no token)'
            )}
          </dd>
        </div>
        <div className="fact">
          <dt>Client Address</dt>
          <dd>
            <code>{event.client_address}</code>
            {blockAddress ? (
              <button type="button" className="btn btn-small drawer-block" onClick={blockAddress}>
                Block This Address…
              </button>
            ) : null}
          </dd>
        </div>
      </dl>
      {unread ? <Problem reply={unread} /> : null}
      <h3 className="drawer-section">Checks</h3>
      <CheckList event={event} />
      <dl className="facts drawer-facts">
        <div className="fact">
          <dt>Reason</dt>
          <dd>
            {event.code ? (
              <>
                {reasonOf(event.code)} <code className="soft">{event.code}</code>
              </>
            ) : (
              'None: every check passed'
            )}
          </dd>
        </div>
        <div className="fact">
          <dt>Ref</dt>
          <dd className="drawer-ref">
            <code>{event.request_id}</code>
            <CopyButton value={event.request_id} label="Ref" />
          </dd>
        </div>
      </dl>
      <p className="hint">Tokens, passwords and request bodies are never logged.</p>
    </>
  )
}
