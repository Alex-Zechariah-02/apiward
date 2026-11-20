// Package audit is the gateway's durable security log: one JSON record per
// request decision, administrator action and log event, appended to rotating
// files and synced to disk.
//
// An admitted request is acknowledged only after its record is on disk;
// records refused meanwhile are counted, never dropped silently, and records
// never hold credentials. Rotated files are compressed into an archive folder
// in the background; the oldest are deleted, each after a synced record of
// what it held, when the archive or the log folder is over its bound or a
// disk runs low (or, under the opt-in refuse mode, never, and a full log
// folder refuses records). A full disk first releases a reserve file; a
// failed sync replaces the active file; protected admission stops only while
// no record can be stored. It imports only fault and filecheck. The request
// pipeline, the controller and the operator commands write to it.
package audit
