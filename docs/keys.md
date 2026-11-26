# Keys and credentials

Every key, certificate and secret the gateway uses: what it protects, its algorithm, where it comes from and how to replace it.

## Inventory

| Material | Protects | Algorithm | Comes from | Replaced by |
|---|---|---|---|---|
| Token verification keys | Access tokens of protected requests | RS256; RSA 2,048 to 8,192 bits (`gateway.jwt.min_rsa_bits` raises the minimum to 3,072 or 4,096); 1 to 64 keys, chosen by `kid` | `gateway.jwt.keys[].public_key_file`: one PEM `PUBLIC KEY` each | `POST /admin/keys/reload`, live |
| Identity assertion key | `X-Gateway-Assertion` to upstreams | EdDSA (Ed25519, made by `apiward install`) or ES256 (an ECDSA P-256 key of an earlier deployment), fixed by the key's type; `kid` is the RFC 7638 thumbprint; assertions expire after 30 s | `upstream.identity_key`, or `identity.pem` beside the database; made by `apiward install`; optional `upstream.retiring_identity_key` public key | `POST /admin/keys/reload`, live |
| Data listener certificate and key | HTTPS on the data listener | TLS 1.2 or later, Go's default cipher suites; key RSA of at least 2,048 bits or ECDSA P-256, PKCS #8 | `data.tls.files.certificate_file`, `data.tls.files.key_file` | `SIGHUP` or `POST /admin/keys/reload`, live |
| Upstream TLS profiles | Upstream certificates (pinned CA) and client certificates | TLS 1.2 or later; CA file of 1 to 16 certificates; client key as for the listener | `upstream.tls_profiles[]`: `ca_file`, `client_certificate_file`, `client_key_file` | `POST /admin/keys/reload`, live |
| Administrator passwords | Admin API sign-in | argon2id, 19 MiB, 2 passes, 1 lane, 16-byte salt, 32-byte key | The database, set at enrolment or by a password change | My Account page, or `apiward enrol` |
| Session and CSRF tokens | Admin API sessions | 32 random bytes each; only a SHA-256 hash of the session token is kept | Memory, made at sign-in | Sign-out, expiry or restart |
| Enrolment secrets | First sign-in and password resets | 32 random bytes; only a SHA-256 hash is stored; one use within 24 hours | `apiward install` and `apiward enrol` print it once | A new `apiward enrol` |
| Checksums | Policy documents, backups, archived log files | SHA-256, unkeyed: they detect damage, not who made a change | Computed | Not applicable |

## File protection

- The gateway refuses a private key file (identity key, listener key, client key) that its group or other users can read; use mode `0600`.
- On Unix it also refuses a trust anchor (a CA pin file or a token verification key) that its group or other users can write, or that belongs to another user than the gateway's or root.
- A CA file of an upstream TLS profile decides which servers the gateway trusts: it must be a regular file and, on Unix, must not be writable by the group or others and must belong to the gateway's user or root.
- On Unix the database, its `-wal`, `-shm` and `-journal` files and its `.lock` file must not be readable or writable by the group or others and must belong to the gateway's user or root; the gateway and its operator commands create them with mode `0600`.
- Windows has no such modes: there these checks are skipped, so restrict the key and CA files with NTFS permissions (for example `icacls <file> /inheritance:r /grant:r "<gateway account>:R"`).
- Certificate chains are public: they are checked for format and size, not for their mode.
- The identity key, the token verification keys and the database files must be regular files, not links: the start, a keys reload and every operator command refuse a link there, naming the file. Point the setting at the file itself.
- No setting or environment variable holds a secret: settings name files, and the files hold the material.
- Keys are not encrypted at rest and no key service or hardware module is used; protect the host and its backups.

## Replacing keys

- **Token verification keys**: add the new key with a new `kid` to `gateway.jwt.keys`, reload, let the token issuer sign with it, then remove the old key and reload again.
- A reload that fails keeps the current keys in force, records a refused change with reason `KEYS_INVALID` and counts it in `gateway_key_reload_failures_total`.
- `GET /admin/keys` and the Team page show each key's size in bits.
- A token is accepted until `gateway.jwt.clock_skew` after its `exp` and from that long before its `nbf` (default `60s`, as Envoy; up to `5m`; `0s` for exact times), so a gateway clock slightly behind the issuer does not refuse new tokens.
- A key reused under the same `kid` with new material starts its use count at zero.
- Changing `gateway.jwt.issuer` or `gateway.jwt.audience` needs a restart; a reload that changes them is refused.
- **Identity assertion key**: publish the new public key to every upstream; set `upstream.retiring_identity_key` to the old public key and `upstream.identity_key` to the new private key; call `POST /admin/keys/reload` (assertions and audit checkpoints now sign with the new key while `GET /.well-known/apiward/jwks.json` publishes both); after every upstream accepts the new key, remove `upstream.retiring_identity_key` and reload again.
- **Listener certificate**: replace the files, then send `SIGHUP` (not on Windows) or call `POST /admin/keys/reload`; new file paths need a restart.
- **Upstream TLS profiles**: replace the files, then call `POST /admin/keys/reload`; a reload that would remove a profile the policy uses is refused.
- **Administrator password**: change it on the My Account page; a forgotten password is reset with `apiward enrol` while the gateway is stopped, which stops the old password at once.
- `apiward disable --config <file> --admin <name>` stops one administrator's password and sessions at once, for someone who has left; a new `apiward enrol` restores access.
- A password change, enrolment, reset or `apiward disable` ends every session of that administrator.

## Sign-in rules

- A password has 15 to 256 bytes of UTF-8 and is not on the bundled list of common passwords (any letter case).
- The list is every password of that length in the SecLists "Pwdb top 1,000,000" list (MIT licence).
- After 5 failed sign-ins, enrolments or password checks within 15 minutes, the name is locked for 15 minutes, also against the right password.
- Unknown names lock in the same way, so the answers never show which names exist.
- After 50 failures within 15 minutes, the client address is refused for 15 minutes, whichever names it tried.
- A successful sign-in, enrolment or password change clears the name's failures.
- At most 2 passwords are checked at once; one more is answered `503 busy`.
- The counters are in memory: a restart clears them.
- The sign-in record is written to the security log before the session is handed out; when it cannot be written, the sign-in is refused.
