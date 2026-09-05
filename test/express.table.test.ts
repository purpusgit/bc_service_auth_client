/**
 * DRIVER 1 of 2 — Express. Runs the SAME table as test/fastify.test.ts.
 *
 * The full Express conformance battery lives in conformance.test.ts; this driver exists so the
 * shared table is genuinely shared rather than a Fastify-only artefact. If a case passes here
 * and fails there, the two adapters have diverged — which is the only thing this file is for.
 */
import express from 'express';
import request from 'supertest';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createAuthClient, type Principal } from '../src/index';
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

describe('the Express adapter runs the shared case table', () => {
  for (const c of AUTH_CASES) {
    it(c.name, async () => {
      mode = c.mode;
      const client = createAuthClient({
        authServiceBaseUrl: c.mode === 'unreachable' ? 'http://127.0.0.1:1' : base,
        isMemberOf: () => false,
        timeoutMs: 300,
      });
      const app = express();
      app.get('/probe', client.requireAuth, (req, res) => {
        res.json({
          principal: (req as express.Request & { principal?: Principal }).principal?.userId ?? null,
          seen: req.headers,
        });
      });

      const res = await request(app)
        .get('/probe')
        .set({ ...(c.token ? { Authorization: `Bearer ${c.token}` } : {}), ...(c.headers ?? {}) });

      expect(res.status).toBe(c.expectStatus);
      if (c.expectStatus === 200) {
        expect(res.body.principal).toBe(c.expectPrincipal);
        for (const [k, v] of Object.entries(c.expectPassthrough ?? {})) expect(res.body.seen[k]).toBe(v);
        for (const [k, v] of Object.entries(c.expectOverwritten ?? {})) expect(res.body.seen[k]).toBe(v);
        for (const k of c.expectAbsent ?? []) expect(res.body.seen[k]).toBeUndefined();
      }
    });
  }
});
