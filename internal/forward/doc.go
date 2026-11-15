// Package forward sends an admitted request to the one upstream it is bound
// to, through the standard library's reverse proxy, and names what a failed
// exchange means for the gateway's answer.
//
// A binding is attached only with Bind, after every control has passed; the
// proxy reads it with Bound and dials nothing else: no header, query or host
// name a client sends can choose a destination. Connections are pooled per
// endpoint and carry one request at a time; a request is sent once, so a
// failed one is never silently resent. The package imports only compile and
// policy. The request pipeline calls it; nothing else forwards.
package forward
