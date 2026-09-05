/**
 * DRIVER 2 of 2 — Fastify. Runs the shared table in test/cases.ts.
 *
 * The only thing this file knows that the Express driver does not is how Fastify mounts a
 * preHandler and how it replies. Everything being asserted comes from the table.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import Fastify from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createAuthClient, createFastifyAuth } from '../src/index';
import { AUTH_CASES, type StubMode } from './cases';

let mode: StubMode = 'ok';
let authServer: http.Server;
let base: string;

beforeAll(async () => {
  authServer = http.createServer((_req, res) => {
    const send = (c: number, b: unknown) => {
      res.writeHead(c, { 'content-type': 'application/json' });
      res.end(JSON.stringify(b));
    };
    switch (mode) {
      case '401': return send(401, { success: false });
      case '500': return send(500, { success: false });
      case '429': return send(429, { success: false });
      case 'garbage':
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end('<html>not json</html>');
      default: return send(200, { success: true, data: { userId: 'u-1' } });
    }
  });
  await new Promise<void>((r) => authServer.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(authServer.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((r) => authServer.close(() => r())));

describe('the Fastify adapter runs the shared case table', () => {
  for (const c of AUTH_CASES) {
    it(c.name, async () => {
      mode = c.mode;
      const client = createAuthClient({
        // 'unreachable' points at a closed port; every other mode at the stub.
        authServiceBaseUrl: c.mode === 'unreachable' ? 'http://127.0.0.1:1' : base,
        isMemberOf: () => false,
        timeoutMs: 300,
      });
      const auth = createFastifyAuth(client);
      const app = Fastify();
      app.get('/probe', { preHandler: [auth.requireAuth as never] }, async (req) => ({
        principal: (req as { principal?: { userId: string } }).principal?.userId ?? null,
        seen: req.headers,
      }));

      const res = await app.inject({
        method: 'GET',
        url: '/probe',
        headers: {
          ...(c.token ? { authorization: `Bearer ${c.token}` } : {}),
          ...(c.headers ?? {}),
        },
      });

      expect(res.statusCode).toBe(c.expectStatus);
      if (c.expectStatus === 200) {
        const body = res.json();
        expect(body.principal).toBe(c.expectPrincipal);
        for (const [k, v] of Object.entries(c.expectPassthrough ?? {})) {
          expect(body.seen[k]).toBe(v);
        }
        for (const [k, v] of Object.entries(c.expectOverwritten ?? {})) {
          expect(body.seen[k]).toBe(v);
        }
        for (const k of c.expectAbsent ?? []) expect(body.seen[k]).toBeUndefined();
      }
      await app.close();
    });
  }
});
