// Package admin is the Admin API: its routes, administrator authentication
// and sessions, the Host, Origin and CSRF checks, the sign-in throttle,
// password hashing, the status, history, monitoring and security log reads,
// and the handlers that ask the controller for changes.
//
// It changes state only through the controller's exported operations and
// reads the database only through store.Reads, so it can never write SQLite
// or publish a policy itself; a test fails if it names the store's database
// type or a function that opens one. It owns no listener: the controller
// serves its Handler on the loopback admin address. The gateway wiring builds
// it with New.
package admin
