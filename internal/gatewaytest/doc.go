// Package gatewaytest is the test harness for the gateway: it builds the
// gateway, fixture and demo programs once per test binary, runs each test's
// gateway as its own process with a disposable deployment (database, security
// log, configuration file, listeners and upstream receivers), and gives tests
// clients for the data plane and the Admin API, readers for the security log
// and the database, and the policies the tests share.
//
// It is test support only: no production package may import it, which the
// layer test enforces. Binary-driven tests in internal/integration and the
// in-process tests of internal/gateway both use it; TestMain in each calls
// Main.
package gatewaytest
