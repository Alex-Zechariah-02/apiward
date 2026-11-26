// Audit log health state: one typed value with checked transitions replacing
// independent health flags, where healthFailed is terminal.

package audit

type logHealth int32

const (
	healthWriting logHealth = iota
	healthFull
	healthDown
	healthNoSpace
	healthFailed
)

func allowedMove(from, to logHealth) bool {
	switch from {
	case healthWriting:
		return to == healthFull || to == healthDown || to == healthNoSpace || to == healthFailed
	case healthFull:
		return to == healthWriting || to == healthDown || to == healthNoSpace || to == healthFailed
	case healthNoSpace:
		return to == healthWriting || to == healthDown || to == healthFailed
	case healthDown:
		return to == healthWriting || to == healthFailed
	default:
		return false
	}
}

func (a *AuditLog) currentHealth() logHealth {
	return logHealth(a.health.Load())
}

func (a *AuditLog) moveHealth(from, to logHealth) bool {
	if !allowedMove(from, to) {
		return false
	}
	return a.health.CompareAndSwap(int32(from), int32(to))
}

func (a *AuditLog) failHealth() bool {
	for {
		from := a.currentHealth()
		if from == healthFailed {
			return false
		}
		if a.moveHealth(from, healthFailed) {
			return true
		}
	}
}
