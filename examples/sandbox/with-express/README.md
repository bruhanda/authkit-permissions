# `@authkit/permissions` — Express adapter

[![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/bruhanda/authkit-permissions/tree/main/examples/sandbox/with-express)

Wires `expressPermissions(...)` between a toy auth middleware and a route
handler, then drives the server with `fetch()` to show four interesting
cases:

| Caller | Endpoint | Result | Why |
| --- | --- | --- | --- |
| `tok_alice` (member) | `GET /posts/p1` | 200 | members can read |
| `tok_alice` (member) | `PATCH /posts/p1` | 200 | alice authored p1 |
| `tok_alice` (member) | `PATCH /posts/p2` | 403 | alice did not author p2 |
| `tok_bob` (admin) | `PATCH /posts/p2` | 200 | admin inherits all post actions |
| `no_such_token` | `GET /posts/p1` | 401 | auth middleware rejects |

The adapter rethrows `PermissionError(FORBIDDEN)` so the existing Express
error handler decides the response shape — there is no built-in 403
behaviour to override.

## Run

```sh
npm install
npm start
```
