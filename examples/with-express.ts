/**
 * with-express.ts — Express adapter end-to-end.
 *
 * Wires `expressPermissions(...)` between a toy auth middleware and a
 * route handler, then exercises the four interesting cases:
 *
 *   - allowed (member reads any post)
 *   - allowed via ABAC condition (member updates a post they authored)
 *   - denied via ABAC condition (member updates someone else's post)
 *   - allowed via role inheritance (admin updates any post)
 *
 * Run from the repo root:
 *
 *   npx tsx examples/with-express.ts
 */
import express, { type NextFunction, type Request, type RequestHandler, type Response } from 'express';
import { createServer, type Server } from 'node:http';
import { once } from 'node:events';
import { setTimeout as wait } from 'node:timers/promises';

import {
  createEnforcer,
  createSubject,
  defineCondition,
  definePolicy,
  PermissionError,
  type ConditionArgs,
  type Subject,
} from '@authkit/permissions';
import { expressPermissions } from '@authkit/permissions/adapters/express';

interface PostRow {
  readonly id: string;
  readonly authorId: string;
  readonly tenantId: string;
}

declare module '@authkit/permissions' {
  interface ResourceDataMap {
    post: PostRow;
  }
}

const isAuthor = defineCondition<ConditionArgs>(
  ({ subject, resource }) =>
    (resource as PostRow | undefined)?.authorId === subject.id,
);

const policy = definePolicy({
  roles:     { admin: { extends: ['member'] }, member: {} },
  resources: { post: { actions: ['read', 'update', 'delete'] as const } },
  conditions: { isAuthor },
  permissions: {
    admin:  { post: ['*'] },
    member: {
      post: { read: true, update: { when: 'isAuthor' } },
    },
  },
});

const enforcer = createEnforcer(policy, {
  audit: (event) => {
    console.log('[audit]', event.decision, event.reason, '→', event.action, event.resource);
  },
});

type AppSubject = Subject<'admin' | 'member'>;

const sessions = new Map<string, AppSubject>([
  ['tok_alice', createSubject({ id: 'u_alice', roles: ['member'], tenantId: 't_acme' })],
  ['tok_bob',   createSubject({ id: 'u_bob',   roles: ['admin'],  tenantId: 't_acme' })],
]);

const posts = new Map<string, { id: string; authorId: string; tenantId: string; title: string }>([
  ['p1', { id: 'p1', authorId: 'u_alice', tenantId: 't_acme', title: 'Hello world' }],
  ['p2', { id: 'p2', authorId: 'u_bob',   tenantId: 't_acme', title: 'Bob writes' }],
]);

interface AuthedRequest extends Request {
  user?: AppSubject;
}

function auth(req: AuthedRequest, res: Response, next: NextFunction): void {
  const token = (req.header('authorization') ?? '').replace(/^Bearer\s+/i, '');
  const user = sessions.get(token);
  if (user === undefined) {
    res.status(401).json({ error: 'unauthenticated' });
    return;
  }
  req.user = user;
  next();
}

const app = express();

app.use(auth);

app.get(
  '/posts/:id',
  expressPermissions(enforcer, {
    getSubject: (req) => (req as unknown as AuthedRequest).user as AppSubject,
    require:    () => ({ resource: 'post', action: 'read' }),
  }) as unknown as RequestHandler,
  (req, res) => {
    const post = posts.get(req.params.id ?? '');
    if (post === undefined) res.status(404).json({ error: 'not_found' });
    else res.json(post);
  },
);

app.patch(
  '/posts/:id',
  expressPermissions(enforcer, {
    getSubject: (req) => (req as unknown as AuthedRequest).user as AppSubject,
    require: (req) => {
      const id   = ((req as unknown as Request).params.id ?? '') as string;
      const post = posts.get(id);
      return {
        resource: 'post' as const,
        action:   'update' as const,
        data:     (post ?? { id, authorId: '', tenantId: '' }) as PostRow,
      };
    },
  }) as unknown as RequestHandler,
  (_req, res) => res.json({ ok: true }),
);

// Express expects 4 params for it to be recognised as an error handler.
app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof PermissionError && err.code === 'FORBIDDEN') {
    res.status(403).json({ error: 'forbidden', detail: err.message });
    return;
  }
  console.error('[server-error]', err);
  res.status(500).json({ error: 'internal' });
});

async function call(server: Server, method: string, path: string, token: string): Promise<void> {
  const addr = server.address();
  if (typeof addr !== 'object' || addr === null) throw new Error('no address');
  const url = `http://127.0.0.1:${addr.port}${path}`;
  const res = await fetch(url, {
    method,
    headers: { authorization: `Bearer ${token}` },
  });
  console.log(`${method.padEnd(5)} ${path}  [${token}]  → ${res.status}`);
}

async function main(): Promise<void> {
  const server = createServer(app);
  server.listen(0);
  await once(server, 'listening');

  await call(server, 'GET',   '/posts/p1', 'tok_alice');         // 200
  await call(server, 'PATCH', '/posts/p1', 'tok_alice');         // 200 (alice owns p1)
  await call(server, 'PATCH', '/posts/p2', 'tok_alice');         // 403 (alice doesn't own p2)
  await call(server, 'PATCH', '/posts/p2', 'tok_bob');           // 200 (bob is admin)
  await call(server, 'GET',   '/posts/p1', 'no_such_token');     // 401

  await wait(20); // let the last response flush before closing
  server.close();
  await once(server, 'close');
}

void main();
