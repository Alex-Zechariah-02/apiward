// Package monitor observes the gateway without deciding anything: the bounded
// window of recent requests and its live views, request metrics, traffic
// summaries, the fixed advice checks, impact previews and the security log
// search.
//
// It holds no authority over admission, policy, durable audit or upstream
// writes; every view is built from a generation, the observations or the
// security log files it is given. It has no HTTP routing and checks no
// permission: the Admin API does both. It imports only policy, compile and
// audit. The request pipeline records into it; the Admin API and the metrics
// listener read from it.
package monitor
