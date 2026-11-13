# Fork deployment

This fork deploys the existing KV-backed `nodewarden` Worker through
`.github/workflows/deploy.yml`. Pushes to `main` and manual workflow runs on
`main` run checks and deploy. Pull requests run checks only.

## GitHub Actions configuration

Add these **repository secrets** under **Settings → Secrets and variables →
Actions**:

| Secret | Value |
| --- | --- |
| `CLOUDFLARE_API_TOKEN` | A dedicated Cloudflare deployment API token |
| `CLOUDFLARE_ACCOUNT_ID` | Account containing the existing Worker |
| `CLOUDFLARE_ZONE_ID` | Zone containing its existing custom domain |
| `CLOUDFLARE_D1_DATABASE_ID` | UUID of the database currently bound as `DB` |
| `CLOUDFLARE_KV_NAMESPACE_ID` | ID of the namespace currently bound as `ATTACHMENTS_KV` |
| `NODEWARDEN_DOMAIN` | Existing custom hostname, without `https://` or a path |

The Cloudflare **Edit Cloudflare Workers** token template is a starting point.
Limit its resources to the deployment account and domain's zone, and include
**Account → D1 → Read** for existing database lookup and **Zone → Zone → Read**
for domain lookup. The Worker deployment
requires **Workers Scripts → Edit**; binding/domain management also uses the
Workers KV and Workers Routes permissions supplied by the template.

`JWT_SECRET` is a runtime secret on Cloudflare. Normal deployments retain it;
the workflow verifies its binding exists and never generates a replacement.

The generic `wrangler.kv.toml` is versioned. The workflow validates settings,
generates the ignored `wrangler.ci.toml`, confirms its bindings match the existing
Worker, and deploys with the Wrangler version in `package-lock.json`. The build
runs before deployment credentials are injected. Generated configuration is
deleted at the end and is not uploaded as an artifact. Repository secrets are
masked by GitHub in workflow logs; keep debug logging disabled.

Checks include type checking, security/compatibility tests, and a production
build. Live verification checks HTTPS redirection, HSTS, CSP, frontend assets,
database bootstrap, existing invite-only registration, and API authentication.
Production deployment jobs run one at a time.

## Local deployment

The ignored `wrangler.my.toml` contains the local deployment configuration and
the existing resource IDs. It includes a build command and can be deployed with:

```sh
npm ci
npm run deploy:my
```

Keep the account, Worker name, D1/KV IDs, custom domain, and Durable Object
bindings consistent when transferring this file to another machine.

## Updates

`origin` points to this fork and `upstream` to the original project. Fetch and
merge reviewed upstream changes into the fork, retaining its local hardening
changes. Pushing the result to `main` triggers deployment. An upstream release
alone does not trigger a deployment.

To redeploy an earlier application revision, revert the corresponding change
and push to `main`, or use Cloudflare's deployment rollback where supported.
Code rollback does not roll back persistent database changes.
