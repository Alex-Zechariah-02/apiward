// Package testissuer is the token issuer tests stand in for: it generates an
// RSA signing key in memory for each run, never writes it anywhere, and signs
// the tokens the gateway's verifier is tested against.
//
// It is test support only. No production package may import it; the layer
// test enforces that. Unit and integration tests share it so both verify the
// same genuine RS256 signatures.
package testissuer
