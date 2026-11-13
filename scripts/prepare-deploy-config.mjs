import { readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

export const DEPLOYMENT_SETTINGS = [
  'CLOUDFLARE_ACCOUNT_ID',
  'CLOUDFLARE_ZONE_ID',
  'CLOUDFLARE_D1_DATABASE_ID',
  'CLOUDFLARE_KV_NAMESPACE_ID',
  'NODEWARDEN_DOMAIN',
];

export function readDeploymentSettings(env = process.env) {
  const settings = {};
  for (const name of DEPLOYMENT_SETTINGS) {
    const value = String(env[name] || '').trim();
    if (!value) throw new Error(`Missing deployment setting: ${name}`);
    settings[name] = value;
  }
  for (const name of ['CLOUDFLARE_ACCOUNT_ID', 'CLOUDFLARE_ZONE_ID', 'CLOUDFLARE_KV_NAMESPACE_ID']) {
    if (!/^[a-f0-9]{32}$/.test(settings[name])) throw new Error(`Invalid deployment setting: ${name}`);
  }
  if (!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(settings.CLOUDFLARE_D1_DATABASE_ID)) {
    throw new Error('Invalid deployment setting: CLOUDFLARE_D1_DATABASE_ID');
  }
  const domain = settings.NODEWARDEN_DOMAIN;
  const labels = domain.split('.');
  if (domain.length > 253 || labels.length < 2 || labels.some((label) =>
    !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new Error('NODEWARDEN_DOMAIN must be a lowercase hostname without a scheme, port, or path');
  }
  return settings;
}

function replaceOnce(source, pattern, replacement, description) {
  const matches = [...source.matchAll(pattern)];
  if (matches.length !== 1) throw new Error(`Unexpected KV template: ${description}`);
  return source.replace(pattern, replacement);
}

export function buildDeploymentConfig(template, env = process.env) {
  const settings = readDeploymentSettings(env);
  let config = template.replace(/\r\n/g, '\n');
  if (/^\s*(?:account_id|database_id|workers_dev|preview_urls|keep_vars)\s*=|^\s*\[\[?routes?\]/m.test(config)) {
    throw new Error('Expected a generic KV template without deployment-specific settings');
  }
  config = replaceOnce(config, /^name = "nodewarden"$/gm, [
    'name = "nodewarden"',
    `account_id = "${settings.CLOUDFLARE_ACCOUNT_ID}"`,
    'workers_dev = false',
    'preview_urls = false',
    'keep_vars = true',
  ].join('\n'), 'Worker name');
  // The workflow builds before injecting deployment credentials.
  config = replaceOnce(config, /^\[build\]\ncommand = "npm run build"\n/gm, '', 'build command');
  config = replaceOnce(config,
    /^(\[\[d1_databases\]\]\nbinding = "DB"\ndatabase_name = "nodewarden-db")(?=\n\s*\n)/gm,
    `$1\ndatabase_id = "${settings.CLOUDFLARE_D1_DATABASE_ID}"`, 'DB binding');
  config = replaceOnce(config,
    /^(\[\[kv_namespaces\]\]\nbinding = "ATTACHMENTS_KV")(?=\n\s*\n)/gm,
    `$1\nid = "${settings.CLOUDFLARE_KV_NAMESPACE_ID}"`, 'ATTACHMENTS_KV binding');
  config += `\n[[routes]]\npattern = "${settings.NODEWARDEN_DOMAIN}"\ncustom_domain = true\nzone_id = "${settings.CLOUDFLARE_ZONE_ID}"\n\n[secrets]\nrequired = ["JWT_SECRET"]\n`;
  return config;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const template = await readFile(new URL('../wrangler.kv.toml', import.meta.url), 'utf8');
    const config = buildDeploymentConfig(template);
    await writeFile(new URL('../wrangler.ci.toml', import.meta.url), config, { mode: 0o600 });
    console.log('Prepared deployment configuration for the existing Worker.');
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
