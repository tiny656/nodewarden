import assert from 'node:assert/strict';
import test from 'node:test';
import { normalizeAuthenticationResponse, normalizeRegistrationResponse, verifyAccountPasskeyToken } from '../src/utils/account-passkeys';
import { handleRequest } from '../src/router';
import { handleToken } from '../src/handlers/identity';
import { RateLimitService } from '../src/services/ratelimit';
import { LIMITS } from '../src/config/limits';
import type { Env } from '../src/types';
import { trimCharacter, trimTrailingCharacter } from '../shared/trim-character';
import { normalizeEquivalentDomain } from '../shared/domain-normalize';

const assertion = {
  id: '+/8=', rawId: '-_8', type: 'public-key',
  response: { clientDataJson: 'AQID', authenticatorData: 'AQID', signature: 'BAUG', userHandle: null },
  extensions: {},
};

test('accepts standard and URL-safe WebAuthn encodings and official legacy property names', () => {
  const result = normalizeAuthenticationResponse(assertion);
  assert.equal(result?.id, '-_8');
  assert.equal(result?.rawId, '-_8');
  assert.equal(result?.response.clientDataJSON, 'AQID');
  assert.equal(result?.response.userHandle, undefined);
  const registration = normalizeRegistrationResponse({ ...assertion,
    response: { clientDataJSON: 'AQID', attestationObject: 'BAUG', transports: ['usb', 'internal'] } });
  assert.equal(registration?.response.attestationObject, 'BAUG');
});

test('rejects oversized, malformed and nonstring WebAuthn fields', () => {
  for (const value of ['='.repeat(200_000) + '!', 'AQ=ID', 'A', {}, 'A'.repeat(2049)]) {
    assert.equal(normalizeAuthenticationResponse({ ...assertion, rawId: value }), null);
  }
  for (const field of ['clientDataJSON', 'authenticatorData', 'signature', 'userHandle']) {
    assert.equal(normalizeAuthenticationResponse({ ...assertion,
      response: { ...assertion.response, [field]: 'A'.repeat(100_000) } }), null);
  }
  assert.equal(normalizeAuthenticationResponse({ ...assertion, id: 'BAUG' }), null);
  assert.equal(normalizeRegistrationResponse({ ...assertion,
    response: { clientDataJSON: 'AQID', attestationObject: 'A'.repeat(65537) } }), null);
});

test('oversized challenge tokens are rejected before accessing the signing secret', async () => {
  const env = new Proxy({} as Env, { get() { throw new Error('Secret must not be accessed'); } });
  assert.equal(await verifyAccountPasskeyToken(env, 'A'.repeat(8193), 'Authentication'), null);
});

test('linear trimming preserves domain and remote backup path semantics', () => {
  assert.equal(trimCharacter('///folder/file///', '/'), 'folder/file');
  assert.equal(trimTrailingCharacter('https://example.test/path///', '/'), 'https://example.test/path');
  assert.equal(trimTrailingCharacter('/'.repeat(100_000) + 'x', '/').length, 100_001);
  assert.equal(trimCharacter('/'.repeat(100_000), '/'), '');
  assert.equal(normalizeEquivalentDomain('*.Sub.Example.COM...'), 'example.com');
  assert.equal(normalizeEquivalentDomain('https://login.example.co.uk/path'), 'example.co.uk');
});

test('authentication request limits apply to all supported routes and actual streamed size', async () => {
  for (const path of ['/identity/connect/token', '/identity/accounts/prelogin', '/api/accounts/register',
    '/api/two-factor/webauthn', '/api/webauthn', '/webauthn']) {
    for (const headers of [{}, { 'Content-Length': '1' }]) {
      const request = new Request(`https://vault.example.test${path}`, {
        method: 'POST', headers, body: 'x'.repeat(LIMITS.request.maxAuthBodyBytes + 1),
      });
      const env = new Proxy({} as Env, { get() { throw new Error('Oversized authentication must not reach bindings'); } });
      assert.equal((await handleRequest(request, env)).status, 413);
    }
  }
});

test('ordinary vault requests keep their larger size limit', async () => {
  const request = new Request('https://vault.example.test/api/ciphers', {
    method: 'POST', body: 'x'.repeat(LIMITS.request.maxAuthBodyBytes + 1),
  });
  assert.equal((await handleRequest(request, { JWT_SECRET: 'test-secret-with-more-than-thirty-two-characters' } as Env)).status, 401);
});

test('login requests for different subjects and grants share one per-IP budget', async (ctx) => {
  const keys: string[] = [];
  ctx.mock.method(RateLimitService.prototype, 'consumeStrictBudget', async (key: string) => {
    keys.push(key);
    return { allowed: false, remaining: 0, retryAfterSeconds: 30 };
  });
  const db = { prepare() { throw new Error('Blocked login must not perform user lookup or cryptography'); } };
  for (const grant of ['password', 'webauthn', 'client_credentials']) {
    const response = await handleToken(new Request('https://vault.example.test/identity/connect/token', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '192.0.2.1' },
      body: JSON.stringify({ grant_type: grant, username: `${grant}@example.test` }),
    }), { DB: db } as unknown as Env);
    assert.equal(response.status, 429);
    assert.equal(response.headers.get('Retry-After'), '30');
  }
  assert.equal(new Set(keys).size, 1);
});
