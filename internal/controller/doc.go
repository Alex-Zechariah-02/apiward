// Package controller is the only authority that changes what the gateway
// enforces: it owns the database and the audit log of a deployment, compiles
// policy generations and publishes them, runs Confirmed Policy Activation and
// Temporary Policy Overrides with their deadlines and startup recovery, and
// publishes trust keys, blocked accounts and blocked addresses.
//
// Every change goes through one of its exported operations, which serialise
// under one lock, record a durable transition and audit it; publishing a
// generation, committing a transition and settling a deadline are unexported.
// Publish, which installs a whole policy without activation, exists for tests
// and the fault-injection build's test route only. The controller never
// serves the data plane and never reads the clock except through compile's
// trusted time. The gateway wiring and the Admin API call it.
package controller
