import assert from 'node:assert/strict';
import test from 'node:test';
import { createCipheriv, createHmac } from 'node:crypto';
import { base64ToBytes, bytesToBase64, decryptBw, decryptBwFileData, encryptBw, encryptBwFileData } from '../webapp/src/lib/crypto';
import { decryptSingleCipher } from '../webapp/src/lib/decrypt-cipher';
import { saveSession, saveProfileSnapshot } from '../webapp/src/lib/api/auth';
import { saveOfflineUnlockRecord } from '../webapp/src/lib/offline-auth';

const enc = Uint8Array.from({ length: 32 }, (_, i) => i);
const mac = Uint8Array.from({ length: 32 }, (_, i) => 63 - i);
const plaintext = new TextEncoder().encode('A synthetic vault record with enough bytes for two blocks.');

test('decrypts Bitwarden type-2 data produced independently by Node crypto', async () => {
  const iv = Buffer.alloc(16, 7);
  const cipher = createCipheriv('aes-256-cbc', enc, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = createHmac('sha256', mac).update(iv).update(ciphertext).digest('base64');
  const value = `2.${iv.toString('base64')}|${ciphertext.toString('base64')}|${tag}`;
  assert.deepEqual(await decryptBw(value, enc, mac), plaintext);
});

test('tampering with IV, ciphertext, or MAC fails before returning plaintext', async () => {
  const encrypted = await encryptBw(plaintext, enc, mac);
  const parts = encrypted.slice(2).split('|');
  for (let index = 0; index < 3; index += 1) {
    const changed = [...parts];
    const bytes = base64ToBytes(changed[index]);
    bytes[0] ^= 3;
    changed[index] = bytesToBase64(bytes);
    await assert.rejects(() => decryptBw(`2.${changed.join('|')}`, enc, mac), /MAC mismatch/);
    for (const prefix of ['0', '1', '4', '02', '2e0']) {
      await assert.rejects(() => decryptBw(`${prefix}.${changed.join('|')}`, enc, mac), /Authenticated encryption/);
    }
  }
});

test('missing authentication keys and malformed enc strings fail closed', async () => {
  const encrypted = await encryptBw(plaintext, enc, mac);
  const parts = encrypted.slice(2).split('|');
  await assert.rejects(() => decryptBw(encrypted, enc, undefined as any), /authentication keys/);
  await assert.rejects(() => decryptBw(encrypted, enc, new Uint8Array(0)), /authentication keys/);
  await assert.rejects(() => decryptBw(encrypted, enc, new Uint8Array(32)), /MAC mismatch/);
  for (const value of [
    `2.${parts[0]}|${parts[1]}`,
    `2.${parts.join('|')}|extra`,
    `2.${bytesToBase64(new Uint8Array(15))}|${parts[1]}|${parts[2]}`,
    `2.${parts[0]}|${parts[1]}|${bytesToBase64(new Uint8Array(31))}`,
    `2.${parts[0]}|${bytesToBase64(new Uint8Array(17))}|${parts[2]}`,
  ]) await assert.rejects(() => decryptBw(value, enc, mac));
});

test('normal vault rendering does not display a downgraded or modified field', async () => {
  const encrypted = await encryptBw(plaintext, enc, mac);
  const body = encrypted.slice(2);
  const cipher = { id: 'synthetic', type: 1, name: `0.${body}`, login: { password: `1.${body}` } } as any;
  const result = await decryptSingleCipher(cipher, enc, mac);
  assert.equal(result.decName, '');
  assert.equal(result.login?.decPassword, '');
  const rawResult = await decryptSingleCipher({ ...cipher, name: 'injected plaintext', login: { password: 'injected plaintext' } }, enc, mac);
  assert.equal(rawResult.decName, '');
  assert.equal(rawResult.login?.decPassword, '');
});

test('attachment encryption round trips and rejects tampering', async () => {
  const encrypted = await encryptBwFileData(plaintext, enc, mac);
  assert.deepEqual(await decryptBwFileData(encrypted, enc, mac), plaintext);
  encrypted[1] ^= 1;
  await assert.rejects(() => decryptBwFileData(encrypted, enc, mac), /MAC mismatch/);
});

test('browser persistence contains only session metadata and encrypted offline key material', async (ctx) => {
  const original = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  const values = new Map<string, string>();
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
    removeItem: (key: string) => values.delete(key),
  } });
  ctx.after(() => {
    if (original) Object.defineProperty(globalThis, 'localStorage', original);
    else Reflect.deleteProperty(globalThis, 'localStorage');
  });
  const encryptedKey = await encryptBw(new Uint8Array(64), enc, mac);
  const profile = { id: 'example-user', email: 'user@example.test', name: 'Example', role: 'user', key: encryptedKey,
    privateKey: 'secret-private', masterPasswordHint: 'secret-hint', accountKeys: { unexpected: 'secret-nested' } } as any;
  saveSession({ email: profile.email, accessToken: 'secret-access', refreshToken: 'secret-refresh',
    symEncKey: 'secret-encryption', symMacKey: 'secret-authentication' });
  saveProfileSnapshot(profile);
  saveOfflineUnlockRecord({ email: profile.email, profile, profileKey: encryptedKey, kdfIterations: 600000 });
  assert.equal(values.size, 3);
  for (const value of values.values()) assert.ok(!value.includes('secret-'));
  const offline = JSON.parse(values.get('nodewarden.web.offline-unlock.v1')!);
  assert.equal(offline.profileKey, encryptedKey);
  assert.deepEqual(Object.keys(offline.profile).sort(), ['email', 'id', 'key', 'name', 'privateKey', 'role']);
});
