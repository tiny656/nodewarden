import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { buildDeploymentConfig, DEPLOYMENT_SETTINGS } from './prepare-deploy-config.mjs';

const template = await readFile(new URL('../wrangler.kv.toml', import.meta.url), 'utf8');
const settings = {
  CLOUDFLARE_ACCOUNT_ID: 'a'.repeat(32),
  CLOUDFLARE_ZONE_ID: 'b'.repeat(32),
  CLOUDFLARE_D1_DATABASE_ID: '00000000-0000-4000-8000-000000000001',
  CLOUDFLARE_KV_NAMESPACE_ID: 'c'.repeat(32),
  NODEWARDEN_DOMAIN: 'vault.example.test',
};

test('CI config pins existing storage and preserves Worker identity and migrations', () => {
  const config = buildDeploymentConfig(template, settings);
  assert.match(config, /^name = "nodewarden"$/m);
  assert.match(config, /binding = "DB"\ndatabase_name = "nodewarden-db"\ndatabase_id = "00000000-0000-4000-8000-000000000001"/);
  assert.match(config, new RegExp(`binding = "ATTACHMENTS_KV"\\nid = "${settings.CLOUDFLARE_KV_NAMESPACE_ID}"`));
  assert.match(config, /class_name = "NotificationsHub"/);
  assert.match(config, /class_name = "BackupTransferRunner"/);
  assert.match(config, /tag = "v1-notifications-hub"/);
  assert.match(config, /tag = "v2-backup-transfer-runner"/);
  assert.match(config, /workers_dev = false/);
  assert.match(config, /preview_urls = false/);
  assert.match(config, /keep_vars = true/);
  assert.match(config, /required = \["JWT_SECRET"\]/);
  assert.doesNotMatch(config, /\[build\]/);
  assert.doesNotMatch(config, /\[\[r2_buckets\]\]/);
  assert.equal(buildDeploymentConfig(template.replace(/\r?\n/g, '\r\n'), settings), config);
});

test('missing settings fail before Wrangler could provision new resources', () => {
  for (const name of DEPLOYMENT_SETTINGS) {
    assert.throws(() => buildDeploymentConfig(template, { ...settings, [name]: '' }), /Missing deployment setting/);
  }
});

test('rejects configuration injection without including submitted values in errors', () => {
  for (const name of DEPLOYMENT_SETTINGS) {
    const value = 'private-input"\n[vars]\nINJECTED = "yes';
    assert.throws(() => buildDeploymentConfig(template, { ...settings, [name]: value }), (error) => {
      assert.ok(!error.message.includes(value));
      assert.ok(!error.message.includes('private-input'));
      return true;
    });
  }
  for (const domain of ['https://vault.example.test', 'vault.example.test/path', 'vault.example.test:443', '*.example.test']) {
    assert.throws(() => buildDeploymentConfig(template, { ...settings, NODEWARDEN_DOMAIN: domain }), /hostname/);
  }
});

test('rejects unexpected binding or Worker template changes', () => {
  assert.throws(() => buildDeploymentConfig(template.replace('name = "nodewarden"', 'name = "another-worker"'), settings), /Worker name/);
  assert.throws(() => buildDeploymentConfig(template.replace('binding = "DB"', 'binding = "OTHER_DB"'), settings), /DB binding/);
  assert.throws(() => buildDeploymentConfig(template.replace('binding = "ATTACHMENTS_KV"', 'binding = "OTHER_KV"'), settings), /ATTACHMENTS_KV binding/);
});

test('only configuration settings, not API tokens or runtime secrets, enter the generated file', () => {
  const config = buildDeploymentConfig(template, {
    ...settings,
    CLOUDFLARE_API_TOKEN: 'token-must-stay-in-environment',
    JWT_SECRET: 'runtime-secret-must-stay-in-cloudflare',
  });
  assert.ok(!config.includes('token-must-stay-in-environment'));
  assert.ok(!config.includes('runtime-secret-must-stay-in-cloudflare'));
});
