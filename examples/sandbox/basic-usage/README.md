# `@authkit/permissions` — basic usage

[![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/bruhanda/authkit-permissions/tree/main/examples/sandbox/basic-usage)

Smallest useful policy: two roles (`admin`, `member`), one resource (`document`),
three call shapes (`check`, `explain`, `enforce`). No conditions, no tenants —
just enough to feel the API.

## Run

```sh
npm install
npm start
```

Equivalent to running `npx tsx index.ts` once dependencies are installed.

## What to look at

- `definePolicy({...})` — every role, resource, action, and permission key
  is type-checked against the literals you pass in. Try changing
  `'document'` to `'pst'` in a `check()` call: TypeScript flags it before
  the program ever runs.
- `enforcer.explain(...)` — returns `{ allowed, reason, grantedBy, ... }`.
  Useful for tests and audit logs.
- `enforcer.enforce(...)` — same as `check` but throws
  `PermissionError(FORBIDDEN)` on deny. Drop into a route handler and let
  the framework's error mapper return a 403.
