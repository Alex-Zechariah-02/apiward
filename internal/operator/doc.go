// Package operator runs the gateway's local operator commands: install,
// enrol, migrate, backup and restore. They run only on the gateway host,
// never over HTTP, while the gateway is stopped: each holds the deployment's
// exclusive lock for its whole run, and records every change it makes in
// the audit log before reporting success.
//
// It writes the database directly through store, the one place outside the
// controller that may, because no gateway can be running; it never imports
// the controller or the Admin API. The gateway's command line calls Run, and
// the configuration check calls CheckPaths.
package operator
