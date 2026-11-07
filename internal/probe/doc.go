// Package probe verifies a migration by differential testing. It generates
// boundary probes from an exchange file: for each operation the gateway
// will enforce, the request it forwards and the near misses around each
// control (other paths and methods, each kind of bad token, each role, an
// invalid and an oversized body, unmet host and header conditions, the rate
// limit and an unreachable upstream). Each probe names the class of the
// gateway's decision and the ledger item that predicts a difference.
//
// The reference evaluator decides a request from routes reduced to the
// shared primitives of package semantics, so the same code models every
// source gateway and the gateway itself; per format only a status-to-class
// map is kept. Judge compares an observed class with the source's and
// accepts a difference only when its ledger item is an approximation in
// that direction. It imports only exchange, semantics and policy.
package probe
