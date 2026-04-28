# `@authkit/permissions` — advanced usage

[![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/bruhanda/authkit-permissions/tree/main/examples/sandbox/advanced-usage)

A realistic multi-tenant document-management policy. Every feature you'd
reach for in a real B2B SaaS is here.

## What it shows

| Feature | Where to look |
| --- | --- |
| Role inheritance (`superadmin` > `admin` > `member` > `viewer`) | `roles` block |
| Sync ABAC condition with **filter hint** for SQL | `isOwner` / `notArchived` |
| Async ABAC condition (collaborator lookup) | `isCollaborator` |
| Composite rule combinators (`allOf`, `anyOf`, `when`) | `member.document.update` |
| Explicit rule priority | `member.document.delete` |
| Cross-tenant gate (role flag **and** per-call opt-in) | the `bob` vs `root` calls |
| Structured audit hook with timing + JSON formatter | `composeAudit(withTiming(...))` |
| `accessibleBy()` → Prisma / Mongo `where` | bottom of `main()` |

## Run

```sh
npm install
npm start
```

The console output walks through each scenario, including the `FilterAst`
that comes out of `accessibleBy()` and what each ORM translator turns it
into.
