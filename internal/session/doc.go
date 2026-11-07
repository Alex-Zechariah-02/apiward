// Package session holds the administrator sessions of the Admin API in
// memory and makes the random tokens the Admin API and the operator commands
// hand out.
//
// Only the SHA-256 of a session token is kept; the token itself exists only
// in the administrator's cookie. Nothing is ever written to disk, so a
// restart ends every session. The table is bounded and refuses a new session
// when full. It imports no internal package. The controller ends an
// administrator's sessions inside its own lock when a credential changes; the
// Admin API creates, looks up and ends them.
package session
