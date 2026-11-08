import { createContext, useContext } from 'react'
import type { Upstream } from '../../shared/api'
import { Field } from '../../shared/ui'

// How the gateway reaches a service at an https URL: the TLS profile that
// verifies it and the Host header it receives. The Designer reads the
// gateway's profiles once and provides them to both service-address forms.

export interface ServiceProfile {
  id: string
  ca_pinned: boolean
  client_certificate: boolean
  client_certificate_expires_at: string | null
}

export const ProfilesContext = createContext<ServiceProfile[]>([])

// secure reports an https service address, the only kind with TLS settings.
export function secure(address: string): boolean {
  return address.startsWith('https://')
}

// profileLabel says what a profile proves, in a few words.
function profileLabel(profile: ServiceProfile): string {
  const parts = [profile.ca_pinned ? 'own CA' : 'public CAs', profile.client_certificate ? 'client certificate' : 'no client certificate']
  return `${profile.id} (${parts.join(', ')})`
}

export function TransportFields(props: {
  id: string
  upstream: Pick<Upstream, 'tls' | 'host'>
  editable?: boolean
  onChange: (patch: Pick<Upstream, 'tls' | 'host'>) => void
}) {
  const profiles = useContext(ProfilesContext)
  const host = props.upstream.host ?? 'upstream'
  const listed = profiles.some((profile) => profile.id === props.upstream.tls)
  const disabled = props.editable === false
  return (
    <>
      <Field
        id={`${props.id}-tls`}
        label="TLS Profile"
        hint="Which certificate authority the service’s certificate must come from, and the client certificate the gateway presents. Profiles are set in the gateway’s settings."
      >
        <select
          id={`${props.id}-tls`}
          className="input"
          value={props.upstream.tls ?? ''}
          disabled={disabled}
          onChange={(event) => props.onChange({ tls: event.target.value || undefined, host: props.upstream.host })}
        >
          <option value="">None (Public CAs)</option>
          {profiles.map((profile) => (
            <option key={profile.id} value={profile.id}>
              {profileLabel(profile)}
            </option>
          ))}
          {props.upstream.tls && !listed ? <option value={props.upstream.tls}>{props.upstream.tls} (not on this gateway)</option> : null}
        </select>
      </Field>
      <div className="field">
        <label id={`${props.id}-host`}>Host Header</label>
        <div className="segmented" role="group" aria-labelledby={`${props.id}-host`} aria-describedby={`${props.id}-host-hint`}>
          {(
            [
              ['inbound', 'Keep Client Host'],
              ['upstream', 'Use Service Host'],
            ] as const
          ).map(([value, label]) => (
            <button
              key={value}
              type="button"
              className="btn"
              aria-pressed={host === value}
              disabled={disabled}
              onClick={() => props.onChange({ tls: props.upstream.tls, host: value })}
            >
              {label}
            </button>
          ))}
        </div>
        <p className="hint" id={`${props.id}-host-hint`}>
          The host name the service receives with each request.
        </p>
      </div>
    </>
  )
}
