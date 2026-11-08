import type { ReactNode } from 'react'
import type { Resource } from '../shared/hooks'
import { ReplyView } from '../shared/replies'
import { Time } from '../shared/time'
import { Badge, TableScroll } from '../shared/ui'
import type { ServiceProfile } from '../policy/designer/transport'

// The Team page's Service TLS Profiles: how the gateway verifies services at
// https addresses and the client certificate it presents to them. Read-only;
// profiles live in the gateway's settings and reload with the signing keys.

// soonDays is how early a client certificate's expiry is flagged: renewing
// one by hand needs that much lead time.
const soonDays = 30
const dayMs = 24 * 60 * 60 * 1000

function expiry(at: string | null, now: number): ReactNode {
  if (!at) return <span className="muted">No client certificate</span>
  const left = Date.parse(at) - now
  return (
    <>
      <Time value={at} />{' '}
      {left <= 0 ? <Badge tone="refused">Expired</Badge> : left <= soonDays * dayMs ? <Badge tone="pending">Expires Soon</Badge> : null}
    </>
  )
}

export function ServiceProfiles(props: { profiles: Resource<{ items: ServiceProfile[] }> }) {
  const now = Date.now()
  return (
    <section className="section card" aria-labelledby="profiles-title">
      <div className="card-head card-head-pad">
        <h2 id="profiles-title">Service TLS Profiles</h2>
      </div>
      <div className="card-body">
        <ReplyView reply={props.profiles.reply}>
          {(p) =>
            p.items.length === 0 ? (
              <p className="card-pad-x muted">
                No profiles. Services at https addresses are verified against public certificate authorities, and the gateway presents no client certificate.
              </p>
            ) : (
              <TableScroll label="Service TLS Profiles">
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Profile</th>
                      <th scope="col">Certificate Authority</th>
                      <th scope="col">Client Certificate Expires</th>
                    </tr>
                  </thead>
                  <tbody>
                    {p.items.map((x) => (
                      <tr key={x.id}>
                        <td>
                          <code>{x.id}</code>
                        </td>
                        <td>{x.ca_pinned ? 'Own CA (pinned)' : 'Public CAs'}</td>
                        <td className="nowrap">{expiry(x.client_certificate_expires_at, now)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableScroll>
            )
          }
        </ReplyView>
      </div>
    </section>
  )
}
