import { useResource } from '../shared/hooks'
import { ReplyView } from '../shared/replies'
import { TableScroll } from '../shared/ui'
import type { ViewProps } from '../app/views'
import type { Status } from '../shared/api'

// The Team page's Gateway Build section: which binary is running and which
// controls are compiled into it, read from the status reply.

// runsAt names each module phase as the request pipeline shows it.
const runsAt: Record<string, string> = {
  ingress: 'Before Policy',
  identity: 'Identity',
  authorise: 'Permissions',
  traffic: 'Traffic',
  validate: 'Validation',
}

// GatewayBuild is read-only: a build changes only when the operator installs
// another binary.
export function GatewayBuild({ admin }: Pick<ViewProps, 'admin'>) {
  const status = useResource<Status>((signal) => admin.get('/admin/status', signal), [])
  return (
    <section className="section card" aria-labelledby="build-title">
      <div className="card-head card-head-pad">
        <h2 id="build-title">Gateway Build</h2>
        <span className="muted">
          Shown by <code>gateway version</code> on the host
        </span>
      </div>
      <div className="card-body">
        <ReplyView reply={status.reply}>
          {(s) => (
            <>
              <div className="card-pad-x">
                <dl className="facts facts-inline">
                  <div className="fact">
                    <dt>Version</dt>
                    <dd>
                      <code>{s.build.version}</code>
                    </dd>
                  </div>
                  <div className="fact">
                    <dt>Go</dt>
                    <dd>
                      <code>{s.build.go}</code>
                    </dd>
                  </div>
                </dl>
              </div>
              <TableScroll label="Modules">
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Module</th>
                      <th scope="col">Runs At</th>
                      <th scope="col">Version</th>
                    </tr>
                  </thead>
                  <tbody>
                    {s.build.modules.map((m) => (
                      <tr key={m.id}>
                        <td>
                          <code>{m.id}</code>
                        </td>
                        <td>{runsAt[m.phase] ?? m.phase}</td>
                        <td>
                          <code className="soft">{m.version}</code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableScroll>
            </>
          )}
        </ReplyView>
      </div>
    </section>
  )
}
