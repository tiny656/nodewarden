import assert from 'node:assert/strict';
import test from 'node:test';

import worker from '../src/index';
import type { Env } from '../src/types';
import { applyCors } from '../src/utils/response';

const ctx = {} as ExecutionContext;
const assetEnv = {
  ASSETS: {
    fetch: async () => new Response('<!doctype html><title>NodeWarden</title>', {
      headers: { 'Content-Type': 'text/html' },
    }),
  },
} as Env;

test('public HTTP redirects preserve method, path and query before accessing bindings', async () => {
  const env = new Proxy({} as Env, {
    get() { throw new Error('HTTP requests must not access application bindings'); },
  });
  for (const [method, path] of [
    ['GET', '/login/?next=%2Fvault'],
    ['POST', '/identity/connect/token?client=web'],
    ['OPTIONS', '/api/sync'],
  ]) {
    const response = await worker.fetch(new Request(`http://vault.example.test${path}`, {
      method,
      ...(method === 'POST' ? { body: 'grant_type=refresh_token' } : {}),
    }), env, ctx);
    assert.equal(response.status, 308);
    assert.equal(response.headers.get('Location'), `https://vault.example.test${path}`);
    assert.equal(await response.text(), '');
  }
});

test('loopback HTTP development remains usable without HSTS', async () => {
  for (const host of ['localhost', '127.0.0.1', '[::1]']) {
    const response = await worker.fetch(new Request(`http://${host}:8787/`), assetEnv, ctx);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('Strict-Transport-Security'), null);
  }
});

test('HTTPS app shell and hidden-vault responses enforce hostname-scoped HSTS', async () => {
  for (const hidden of [false, true]) {
    const response = await worker.fetch(new Request('https://vault.example.test/login'), {
      ...assetEnv,
      ...(hidden ? { HIDE_WEB_VAULT: '1' } : {}),
    }, ctx);
    assert.equal(response.status, hidden ? 404 : 200);
    assert.equal(response.headers.get('Strict-Transport-Security'), 'max-age=31536000');
    assert.equal(response.headers.get('X-Frame-Options'), 'DENY');
  }
});

test('CSP blocks inline scripts and constrains connections while permitting vault workers', () => {
  const response = applyCors(new Request('https://vault.example.test/login'), new Response(''), {} as Env);
  const policy = new Map((response.headers.get('Content-Security-Policy') || '')
    .split(';').map((part) => {
      const [directive, ...values] = part.trim().split(/\s+/);
      return [directive, values];
    }));
  assert.deepEqual(policy.get('script-src'), ["'self'"]);
  assert.deepEqual(policy.get('script-src-attr'), ["'none'"]);
  assert.deepEqual(policy.get('worker-src'), ["'self'"]);
  assert.deepEqual(policy.get('connect-src'), ["'self'", 'wss://vault.example.test', 'https://api.pwnedpasswords.com']);
  assert.deepEqual(policy.get('object-src'), ["'none'"]);
  assert.deepEqual(policy.get('base-uri'), ["'none'"]);
  assert.deepEqual(policy.get('frame-ancestors'), ["'none'"]);
});

test('API errors retain HSTS and icon responses retain their stricter sandbox', () => {
  const api = applyCors(new Request('https://vault.example.test/api/sync'), new Response('{}', {
    status: 401,
    headers: { 'Content-Type': 'application/json' },
  }), {} as Env);
  assert.equal(api.status, 401);
  assert.equal(api.headers.get('Strict-Transport-Security'), 'max-age=31536000');

  const iconPolicy = "default-src 'none'; img-src 'self' data:; sandbox";
  const icon = applyCors(new Request('https://vault.example.test/icons/example.com/icon.png'), new Response(null, {
    headers: { 'Content-Type': 'image/png', 'Content-Security-Policy': iconPolicy },
  }), {} as Env);
  assert.equal(icon.headers.get('Content-Security-Policy'), iconPolicy);
  assert.equal(icon.headers.get('Strict-Transport-Security'), 'max-age=31536000');
});
