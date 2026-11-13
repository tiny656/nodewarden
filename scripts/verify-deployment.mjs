import { setTimeout as delay } from 'node:timers/promises';
import { readDeploymentSettings } from './prepare-deploy-config.mjs';

function requireCheck(condition, message) {
  if (!condition) throw new Error(message);
}

async function checkExistingResources(settings) {
  const token = String(process.env.CLOUDFLARE_API_TOKEN || '').trim();
  requireCheck(token, 'CLOUDFLARE_API_TOKEN is required');
  const api = async (path, label) => {
    const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${settings.CLOUDFLARE_ACCOUNT_ID}${path}`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(30000),
    });
    const body = await response.json();
    const codes = (body.errors || []).map((error) => Number(error.code)).filter(Number.isFinite);
    requireCheck(response.ok && body.success,
      `${label} failed (HTTP ${response.status}; Cloudflare error codes: ${codes.join(', ') || 'none'})`);
    return body.result;
  };
  const [worker, domains] = await Promise.all([
    api('/workers/scripts/nodewarden/settings', 'Worker settings lookup'),
    api('/workers/domains', 'Custom domain lookup'),
  ]);
  const bindings = worker.bindings || [];
  requireCheck(bindings.some((binding) => binding.name === 'DB' && binding.type === 'd1' &&
    [binding.id, binding.database_id].includes(settings.CLOUDFLARE_D1_DATABASE_ID)),
  'D1 setting does not match the existing DB binding');
  requireCheck(bindings.some((binding) => binding.name === 'ATTACHMENTS_KV' && binding.type === 'kv_namespace' &&
    binding.namespace_id === settings.CLOUDFLARE_KV_NAMESPACE_ID),
  'KV setting does not match the existing ATTACHMENTS_KV binding');
  for (const [name, className] of [
    ['NOTIFICATIONS_HUB', 'NotificationsHub'],
    ['BACKUP_TRANSFER_RUNNER', 'BackupTransferRunner'],
  ]) {
    requireCheck(bindings.some((binding) => binding.name === name && binding.type === 'durable_object_namespace' &&
      binding.class_name === className), `Missing expected Durable Object binding: ${name}`);
  }
  requireCheck(bindings.some((binding) => binding.name === 'JWT_SECRET' && binding.type === 'secret_text'),
    'JWT_SECRET must already be configured as a Worker secret');
  requireCheck(domains.some((domain) => domain.hostname === settings.NODEWARDEN_DOMAIN &&
    domain.zone_id === settings.CLOUDFLARE_ZONE_ID && domain.service === 'nodewarden'),
  'Domain setting does not match the existing Worker custom domain');
  console.log('Verified existing Worker, storage bindings, custom domain, and JWT_SECRET binding.');
}

async function checkSite(settings) {
  const origin = `https://${settings.NODEWARDEN_DOMAIN}`;
  const request = (url) => fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(20000) });
  const http = await request(`http://${settings.NODEWARDEN_DOMAIN}/login?deployment-check=1`);
  requireCheck(http.status === 308 && http.headers.get('Location') === `${origin}/login?deployment-check=1`,
    'HTTP to HTTPS redirect check failed');
  await http.body?.cancel();
  const homepage = await request(`${origin}/`);
  requireCheck(homepage.status === 200, 'Homepage check failed');
  requireCheck(homepage.headers.get('Strict-Transport-Security') === 'max-age=31536000', 'HSTS check failed');
  requireCheck(/(?:^|;)\s*script-src 'self'(?:;|$)/.test(homepage.headers.get('Content-Security-Policy') || ''),
    'Script CSP check failed');
  const html = await homepage.text();
  requireCheck(html.includes('<title>NodeWarden</title>'), 'Unexpected homepage');
  const asset = html.match(/<script[^>]+src="(\/assets\/[^"?#]+\.js)"/);
  requireCheck(asset, 'Main application asset was not found');
  const assetResponse = await request(`${origin}${asset[1]}`);
  requireCheck(assetResponse.status === 200 && /javascript/.test(assetResponse.headers.get('Content-Type') || ''),
    'Application asset check failed');
  await assetResponse.body?.cancel();
  const bootstrap = await request(`${origin}/api/web-bootstrap`);
  requireCheck(bootstrap.status === 200, 'Database/bootstrap check failed');
  const bootstrapBody = await bootstrap.json();
  requireCheck(bootstrapBody.jwtUnsafeReason === null, 'Worker JWT_SECRET check failed');
  requireCheck(bootstrapBody.registrationInviteRequired === true, 'Existing account/invite registration check failed');
  const config = await request(`${origin}/api/config`);
  requireCheck(config.status === 200 && (await config.json()).environment?.vault === origin,
    'Bitwarden client configuration check failed');
  const sync = await request(`${origin}/api/sync`);
  requireCheck(sync.status === 401, 'Unauthenticated sync access check failed');
  await sync.body?.cancel();
  console.log('Verified HTTPS, HSTS, CSP, assets, database bootstrap, and API authentication.');
}

try {
  const settings = readDeploymentSettings();
  if (process.argv[2] === 'preflight') {
    await checkExistingResources(settings);
  } else if (process.argv[2] === 'smoke') {
    for (let attempt = 1; attempt <= 4; attempt += 1) {
      try {
        await checkSite(settings);
        break;
      } catch (error) {
        if (attempt === 4) throw error;
        console.log('Waiting for deployment propagation before repeating the site check.');
        await delay(5000);
      }
    }
  } else {
    throw new Error('Expected preflight or smoke');
  }
} catch (error) {
  // Do not dump Cloudflare response bodies, credentials, or resource identifiers.
  console.error(error.message);
  process.exitCode = 1;
}
