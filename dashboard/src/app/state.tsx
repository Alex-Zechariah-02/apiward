import { ShieldCheckered } from '@phosphor-icons/react'
import type { Status } from '../shared/api'
import { Badge } from '../shared/ui'

// Brand names the console and the gateway it administers, by the admin
// listener's address, so two gateways open side by side are never confused.
export function Brand() {
  return (
    <div className="brand">
      <span className="brand-mark" aria-hidden="true">
        <ShieldCheckered size={18} weight="fill" />
      </span>
      <span className="brand-text">
        <span className="brand-name">Fetch Gateway</span>
        <code className="brand-host" title="Admin Address">
          {window.location.host}
        </code>
      </span>
    </div>
  )
}

// What the protected admission value means. Anything else is shown as sent.
const admissionText: Record<string, string> = {
  ready: 'Protected requests are accepted under the active policy.',
  bootstrap_locked: 'New installation: every request is refused until an administrator establishes the first policy (Changes).',
  recovery_required: 'Restored from a backup: every request is refused until an administrator establishes a starting policy after the restore (Changes).',
  audit_failed: 'The security log cannot be written, so every protected request is refused.',
  generation_expired: 'The active policy passed a deadline; every request is refused until the gateway ends what expired.',
  stopping: 'The gateway is stopping and refuses every request.',
  stopped: 'The gateway has stopped and refuses every request.',
  unavailable: 'The gateway is unavailable and refuses every request.',
}

// The controller's retried state audit_reconcile_failed is a security log
// that refused a record, so it reads as the security log failing.
export const auditBlocked = (s: Status): boolean => s.audit_failed || s.state === 'audit_reconcile_failed'

// admissionWords says why protected requests are refused, naming the security
// log when it is the cause.
export function admissionWords(s: Status): string {
  if (auditBlocked(s)) return admissionText.audit_failed
  return admissionText[s.admission] ?? 'Every protected request is refused.'
}

export function AdmissionBadge({ status }: { status: Status }) {
  return status.admission === 'ready' ? <Badge tone="ok">Accepting Requests</Badge> : <Badge tone="refused">Not Accepting Requests</Badge>
}
