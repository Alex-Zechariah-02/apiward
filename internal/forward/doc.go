// Package forward sends an admitted request to the one upstream it is bound
// to, through the standard library's reverse proxy, and names what a failed
// exchange means for the gateway's answer.
//
// A binding is attached only with Bind, after every control has passed; the
// proxy reads it with Bound and dials nothing else: no header, query or host
// name a client sends can choose a destination. Connections are pooled per
// endpoint and carry one request at a time; only a GET, HEAD or OPTIONS
// without a body that failed on a reused connection before any response
// byte is sent again, once, on a new connection, and no other request is
// ever resent. Of the gateway's packages it imports
// only compile, policy and filecheck (enforced by the package layer test).
// The request pipeline calls it; nothing else forwards.
package forward
