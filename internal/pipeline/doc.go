// Package pipeline is the data-plane request pipeline: it decides every
// request against the one generation it captures and forwards only a request
// that passed every stage, after its audit record is durable.
//
// It owns the built-in controls (JWT verification, roles and the blocked
// accounts, the weighted sliding-window rate limiter, request body and header
// validation) and the ingress checks before them. It reads published state
// only through Authority, which has no method that publishes policy, trust or
// containment, and it never imports the controller. Any refusal or failure is
// answered here and never forwarded. Its limiter state belongs to the process:
// publication never resets it.
package pipeline
