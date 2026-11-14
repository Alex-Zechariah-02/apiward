# OpenAPI import and export

Back to the [README](../README.md).

## Import an OpenAPI description

- `apiward policy import-openapi` turns an OpenAPI 3.0 or 3.1 description (JSON, or YAML 1.2) into a new policy file for review.
- It runs offline: it reads only the files it is given, never fetches a `$ref`, and never activates anything.
- Stage the result as a draft, trial it and confirm it like any other change.

```
apiward policy import-openapi --spec <file.json|.yaml|.yml> --api <id> --upstream <id>
  --base <policy.json> [--max-body-bytes <n>] [--with-permits] --out <new file> --report <new file>
```

| Flag | Meaning |
|---|---|
| `--spec` | The description, at most 1 MiB; the extension chooses JSON or YAML |
| `--api` | The API to create, or to replace with its operations and the permits that name them |
| `--upstream` | An upstream already in `--base` that serves the API |
| `--base` | The policy to build on, for example the output of `demo policy export` |
| `--max-body-bytes` | Body limit for imported request bodies without `x-apiward-max-bytes`: 1 to 1,048,576, default 16,384 |
| `--with-permits` | Read `x-apiward-roles` into permits, adding missing roles; without it no permit is created |
| `--out`, `--report` | New files; the command never overwrites a file and writes both or neither |

Exit status: `0` every operation mapped; `2` both files written, but some operations were refused or widened (read the report); `1` nothing written (bad flags, unreadable or refused description, an output file exists, or the result does not compile).

**How it maps.**

- Each path and method becomes one operation `<api>.<operationId>`, allowed, with sign-in required unless the description says `security: []`.
- No permits are created unless `--with-permits` reads `x-apiward-roles`; grant roles afterwards.
- A path whose last segment is a parameter (`/orders/{id}`) becomes the prefix `/orders/*`, which also matches deeper paths.
- Header parameters become the header schema; query, path and cookie parameters are listed as not enforced.
- A JSON request body becomes a body rule.
- Schema `$ref`s inside the file are inlined, descriptive keywords (`description`, `example`, `x-…`) are removed, and an object without `additionalProperties` allows extra fields, as OpenAPI does.
- Every operation is checked by the gateway's own compiler, and the whole result is compiled before anything is written.

**What is refused.**

- An operation is left out, with a code in the report, when it cannot be expressed exactly: `TRACE` (`METHOD_REFUSED`); a missing or invalid `operationId` (`OPERATION_ID_INVALID`, with a suggestion) or one used twice (`OPERATION_ID_DUPLICATE`); a parameter in the middle of a path or a `*` in a path (`PATH_TEMPLATE_UNSUPPORTED`; a gateway target ending in `/*` is a prefix); two operations on the same method and target (`TARGET_COLLISION`); API keys, Basic, mutual TLS or optional sign-in (`SECURITY_SCHEME_UNSUPPORTED`); non-JSON bodies (`MEDIA_TYPE_UNSUPPORTED`); a schema keyword the gateway cannot enforce, such as `format`, `pattern` or `oneOf`, or a parameter whose `name` or `in` is not a string or whose `required` is not `true` or `false` (`SCHEMA_KEYWORD_UNSUPPORTED`; dropping it would accept more than described); a `$ref` to another file (`EXTERNAL_REF`), a missing one (`REF_INVALID`) or a circular one (`SCHEMA_CYCLE`); a schema deeper than 16 levels or larger than 4,096 values once inlined (`SCHEMA_LIMIT_EXCEEDED`); and anything else the compiler rejects (`COMPILER_REFUSED`, with its code and field).
- YAML anchors, aliases, merge keys, tags, several documents in one file, duplicate or non-string keys and `.nan`/`.inf` refuse the whole file, naming the line.

**Report.** JSON; every list is always present:

```json
{"spec_version": "3.1.0", "source_format": "yaml", "api": "orders", "operations_in_spec": 8,
 "mapped": [{"method": "GET", "path": "/orders", "operation": "orders.listOrders", "target": "/orders", "auth": "required"}],
 "widened": [{"method": "GET", "path": "/orders/{id}", "operation": "orders.getOrder", "target": "/orders/*", "auth": "required", "note": "matches /orders/<anything>, including deeper paths"}],
 "assumed": [{"operation": "orders.createOrder", "field": "body.max_bytes", "value": 16384}],
 "changed": [{"operation": "orders.updateOrder", "field": "body", "note": "The description allows no body; the gateway refuses a request without one (415 without a JSON Content-Type, else 400 malformed_json)."}],
 "refused": [{"method": "GET", "path": "/orders/{id}/items", "code": "PATH_TEMPLATE_UNSUPPORTED", "message": "A templated segment followed by more segments cannot be expressed."}],
 "needs_permissions": ["orders.listOrders", "orders.getOrder"],
 "scopes_not_mapped": ["orders:read"],
 "not_enforced": [{"operation": "orders.listOrders", "parameter": "page", "in": "query"}],
 "annotations_removed": [{"operation": "orders.createOrder", "field": "#/components/schemas/NewOrder/description"}],
 "removed_operations": ["orders.old"],
 "removed_permits": [{"role": "customer", "operation": "orders.old"}],
 "ignored": ["responses", "servers", "tags"]}
```

`mapped` and `widened` list the imported operations (`note` explains a default they rely on); `assumed` lists values the import chose; `changed` lists behaviour the gateway enforces differently from the description; `refused` entries may add `field` (a JSON Pointer into the description, or the compiler's field) and `suggestion`; `needs_permissions` lists the signed-in operations no role can call yet; `removed_operations` and `removed_permits` are what replacing `--api` took out of the base; `ignored` names description members with no effect on the policy (`servers`, `responses`, `callbacks`, `webhooks`, `links`, `tags`).

**Gateway extensions.** An operation may carry the members the export writes; each is checked, and any other `x-apiward-…` member refuses the operation (`EXTENSION_INVALID`):

| Member | Value | Effect |
|---|---|---|
| `x-apiward-target` | the prefix target the path stands for, such as `/orders/*` for `/orders/{rest}` | the operation is mapped, not widened: the description states that deeper paths match |
| `x-apiward-access` | `allow` or `deny` | the operation's access; absent means `allow` |
| `x-apiward-rate` | `{"algorithm": "sliding-window", "count", "window_seconds", "key"}` | the operation's rate rule, as in a policy |
| `x-apiward-max-bytes` | 1 to 1,048,576 | the body limit; needs a request body |
| `x-apiward-roles` | list of role identifiers | the roles permitted, read only with `--with-permits` |
| `x-apiward-when` | `{"hosts", "headers"}`, as in a policy | the operation's host and header conditions |

At the root, `x-apiward-forward`, `x-apiward-cors`, `x-apiward-response-headers` and `x-apiward-addresses` become the imported API's `forward`, `cors`, `response_headers` and `allow_addresses`, each with exactly the members of the policy's; any other member, or a value of another shape, refuses the description.

## Export a policy as OpenAPI

`apiward policy export-openapi` writes one API of a policy as an OpenAPI 3.1 description (JSON, or YAML by the `--out` extension), for review or for tools that read OpenAPI. Importing that file onto the same policy with `--with-permits` gives the same policy back.

```
apiward policy export-openapi --policy <policy.json> --api <id>
  --out <new file.json|.yaml|.yml> --report <new file> [--with-upstream]
```

- Each operation becomes the path and method of its target, with `operationId` = the operation identifier without the `<api>.` prefix.
- A prefix target `/orders/*` becomes `/orders/{rest}` with `x-apiward-target: /orders/*`.
- Sign-in required becomes the bearer scheme `apiward`; public becomes `security: []`.
- A body rule becomes a required `application/json` request body with its schema and `x-apiward-max-bytes`; a header schema becomes header parameters (its root `additionalProperties` is not written, since the gateway checks declared headers only).
- Access, rate rule and permitted roles go into `x-apiward-access`, `x-apiward-rate` and `x-apiward-roles`; the API's forward rule, browser access, response headers and address allow list go into the root members `x-apiward-forward`, `x-apiward-cors`, `x-apiward-response-headers` and `x-apiward-addresses`, and an operation's conditions into `x-apiward-when`.
- A description holds one operation per path and method, so a second operation on the same target and method (a conditioned one, after the one without conditions) is not exported and is reported `changed`.
- The upstream address is written as a server only with `--with-upstream`.

Exit status: `0` the description means exactly what the policy does; `2` both files written, but something differs (read `changed`): a prefix target, which OpenAPI reads as one segment while the gateway also matches deeper paths; an identifier without the `<api>.` prefix, which comes back with it; a target containing `{` or `}`, which is not exported; `1` nothing written. The report lists `exported` (`operation`, `method`, `path`), `changed` (`operation`, `field`, `note`) and `omitted` (what a flag would add).

## Moving to or from another gateway

- An API's routes, methods and request schemas move between gateways through standard OpenAPI.
- Many gateways can export an API as an OpenAPI description, and `apiward policy import-openapi` turns it into a candidate policy (above).
- In the other direction, `apiward policy export-openapi` writes a description that other gateways' OpenAPI importers can read; they ignore the `x-apiward-*` members.

Sign-in, trusted issuers, roles, rate limits and other gateway-specific settings have no standard form, so they are not translated between products: set them again in the target gateway, and review every imported policy before staging it. Consumers and their credentials stay in the identity provider.
